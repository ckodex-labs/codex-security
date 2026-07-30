import { createHash } from "node:crypto";
import type {
  EvidenceRecord,
  ModelCapabilities,
  ScanModelProviderConfiguration,
} from "../kernel/contracts.js";
import type {
  ActionEnvelope,
  CapabilityLockTrustRecord,
  ContextCertificate,
} from "../kernel/governance-contracts.js";
import { createDecisionEvidence } from "./decision-trace.js";

const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const TEXT = /^[^\u0000-\u001f\u007f]{1,4096}$/u;

export interface ProductionGovernanceFacts {
  scanId: string;
  targetId: string;
  repositoryRevision: string | null;
  scanMode: string;
  pluginVersion: string;
  provider: Exclude<ScanModelProviderConfiguration, { kind: "codex" }>;
}

export interface ProductionGovernanceBinding {
  action: ActionEnvelope;
  providerDecision: EvidenceRecord;
}

export class GovernanceBindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GovernanceBindingError";
  }
}

function requireText(value: unknown, context: string): string {
  if (typeof value !== "string" || !TEXT.test(value)) {
    throw new GovernanceBindingError(`${context} must be bounded text.`);
  }
  return value;
}

function requireDigest(value: unknown, context: string): `sha256:${string}` {
  if (typeof value !== "string" || !DIGEST.test(value)) {
    throw new GovernanceBindingError(`${context} must be a sha256 digest.`);
  }
  return value as `sha256:${string}`;
}

function timestamp(value: unknown, context: string): Date {
  const text = requireText(value, context);
  const parsed = new Date(text);
  if (
    !Number.isFinite(parsed.getTime()) ||
    !/(?:[zZ]|[+-]\d\d:\d\d)$/u.test(text)
  ) {
    throw new GovernanceBindingError(
      `${context} must include an ISO 8601 zone.`,
    );
  }
  return parsed;
}

function requireObject(
  value: unknown,
  context: string,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new GovernanceBindingError(`${context} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  context: string,
): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new GovernanceBindingError(`${context} has an invalid shape.`);
  }
}

function requireLockVerification(
  value: unknown,
  now: Date,
): CapabilityLockTrustRecord["verification"] {
  const verification = requireObject(value, "capability lock verification");
  requireExactKeys(
    verification,
    ["kind", "signatureDigest", "verifiedAt", "expiresAt", "verifier"],
    "capability lock verification",
  );
  if (verification["kind"] !== "cosign") {
    throw new GovernanceBindingError(
      "capability lock must be cosign verified.",
    );
  }
  const verifiedAt = timestamp(verification["verifiedAt"], "verifiedAt");
  const expiresAt = timestamp(verification["expiresAt"], "expiresAt");
  if (
    verifiedAt.getTime() > now.getTime() ||
    expiresAt.getTime() <= verifiedAt.getTime() ||
    expiresAt.getTime() <= now.getTime()
  ) {
    throw new GovernanceBindingError(
      "capability lock verification is not currently valid.",
    );
  }
  return {
    kind: "cosign",
    signatureDigest: requireDigest(
      verification["signatureDigest"],
      "signatureDigest",
    ),
    verifiedAt: verifiedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    verifier: requireText(verification["verifier"], "verifier"),
  };
}

export function requireCapabilityLockTrust(
  value: unknown,
  now: Date = new Date(),
): CapabilityLockTrustRecord {
  const record = requireObject(value, "capability lock trust record");
  requireExactKeys(
    record,
    ["schemaVersion", "lockDigest", "bundleRef", "verification"],
    "capability lock trust record",
  );
  if (record["schemaVersion"] !== 1) {
    throw new GovernanceBindingError(
      "capability lock schemaVersion must be 1.",
    );
  }
  return {
    schemaVersion: 1,
    lockDigest: requireDigest(record["lockDigest"], "lockDigest"),
    bundleRef: requireText(record["bundleRef"], "bundleRef"),
    verification: requireLockVerification(record["verification"], now),
  };
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonical(item)).join(",")}]`;
  }
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value).sort(([left], [right]) =>
      left.localeCompare(right),
    );
    return `{${entries
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function contextCertificate(
  facts: ProductionGovernanceFacts,
  issuedAt: Date,
): ContextCertificate {
  const slice = canonical({
    pluginVersion: facts.pluginVersion,
    provider: facts.provider,
    repositoryRevision: facts.repositoryRevision,
    scanId: facts.scanId,
    scanMode: facts.scanMode,
    targetId: facts.targetId,
  });
  return {
    schemaVersion: 1,
    id: `urn:ckodex:context:scan:${facts.scanId}:provider-projection`,
    sliceHash: digest(slice),
    resolution: "standard",
    justification: "Host-owned scan and provider projection facts.",
    layers: ["identity", "objective", "task", "policy", "current_state"],
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + 5 * 60_000).toISOString(),
  };
}

function actionBudgets(
  facts: ProductionGovernanceFacts,
): ActionEnvelope["budgets"] {
  return {
    wallClockSeconds: 30,
    tokenMax: 0,
    egress: facts.provider.kind === "private" ? "allow" : "deny",
    costUsdMax: 0,
    fsWrites: 1,
    gas: {
      compute: 0,
      context: 1,
      tool: 1,
      network: 0,
      governance: 1,
      recovery: 0,
    },
  };
}

function capabilityLease(
  trust: CapabilityLockTrustRecord,
  now: Date,
): ActionEnvelope["leases"][number] {
  return {
    kind: "capability",
    ttl: "PT5M",
    heartbeatDue: new Date(now.getTime() + 4 * 60_000).toISOString(),
    revocableBy: ["codex-security-sdk"],
    scope: trust.bundleRef,
    decayFn: "step",
  };
}

function actionEnvelope(
  facts: ProductionGovernanceFacts,
  trust: CapabilityLockTrustRecord,
  now: Date,
): ActionEnvelope {
  const certificate = contextCertificate(facts, now);
  return {
    schemaVersion: 1,
    id: `urn:ckodex:action:scan:${facts.scanId}:provider-projection`,
    actor: { kind: "machine", id: "codex-security-sdk", dal: 2 },
    coactors: [],
    scope: {
      tenant: "local",
      environment: "scan",
      workspace: "codex-security",
      project: facts.targetId,
      boundaryClass: "local",
    },
    intent: {
      statement: `Admit provider projection ${facts.provider.id}.`,
      qaIds: ["CV-SAFE", "CV-EVID"],
      risk: facts.provider.kind === "private" ? "high" : "medium",
      blastRadius: "service",
    },
    budgets: actionBudgets(facts),
    leases: [capabilityLease(trust, now)],
    policy: {
      bundleRef: "urn:ckodex:policy:provider-projection:v1",
      traceRequired: true,
    },
    evidence: {
      required: ["decision_trace"],
      onFailure: "halt",
      backPropRequired: false,
    },
    data: { pii: "forbidden", secrets: "forbidden", retention: "standard" },
    context: { certificate },
    capability: trust,
  };
}

function modelCapabilities(
  facts: ProductionGovernanceFacts,
): ModelCapabilities {
  return {
    providerId: facts.provider.id,
    modelId: facts.provider.model,
    transport: facts.provider.kind === "local" ? "local_http" : "private_http",
    endpointSecurity: {
      tls: facts.provider.kind === "private",
      privateNetwork: facts.provider.kind === "private",
      loopbackOnly: facts.provider.kind === "local",
      source: "derived",
    },
    features: new Set(),
    capabilitySource: "configured",
  };
}

export function createProductionGovernanceBinding(
  facts: ProductionGovernanceFacts,
  trustValue: unknown,
  now: Date = new Date(),
): ProductionGovernanceBinding {
  const trust = requireCapabilityLockTrust(trustValue, now);
  const action = actionEnvelope(facts, trust, now);
  return {
    action,
    providerDecision: createDecisionEvidence({
      traceId: `provider-projection:${facts.scanId}`,
      actionId: action.id,
      decision: {
        verdict: "allow",
        policyId: action.policy.bundleRef,
        reasons: [
          "provider projection passed deterministic configuration validation",
        ],
      },
      timestamp: now.toISOString(),
      model: modelCapabilities(facts),
    }),
  };
}
