import type { KernelJsonValue } from "./contracts.js";
import type { SignedEvidenceEnvelope } from "./supply-chain-contracts.js";

export type BoundaryClass =
  | "local"
  | "shared"
  | "bridge_only"
  | "governance_visible"
  | "sovereign_restricted"
  | "retirement_archive";

export type ResolutionProfile =
  | "minimal"
  | "compact"
  | "standard"
  | "deep"
  | "forensic";

export type RetentionClass =
  | "ephemeral"
  | "standard"
  | "regulated"
  | "legal_hold";

export interface ContextCertificate {
  schemaVersion: 1;
  id: string;
  sliceHash: `sha256:${string}`;
  resolution: ResolutionProfile;
  justification: string;
  layers: readonly string[];
  issuedAt: string;
  expiresAt: string;
}

export interface ActionLease {
  kind:
    | "context"
    | "skill"
    | "capability"
    | "branch"
    | "dependency"
    | "snapshot";
  ttl: string;
  heartbeatDue: string;
  revocableBy: readonly string[];
  scope: string;
  decayFn: "linear" | "exp" | "step";
}

export interface CapabilityLockTrustRecord {
  schemaVersion: 1;
  lockDigest: `sha256:${string}`;
  bundleRef: string;
  verification: {
    kind: "cosign";
    signatureDigest: `sha256:${string}`;
    verifiedAt: string;
    expiresAt: string;
    verifier: string;
  };
}

export interface ActionEnvelope {
  schemaVersion: 1;
  id: string;
  actor: {
    kind: "human" | "machine" | "agent" | "service";
    id: string;
    dal: 0 | 1 | 2 | 3 | 4;
  };
  coactors: readonly {
    kind: "human" | "machine" | "agent" | "service";
    id: string;
    role: "reviewer" | "verifier" | "observer" | "peer";
    guardrailProfile: string;
  }[];
  scope: {
    tenant: string;
    environment: string;
    workspace: string;
    project: string;
    boundaryClass: BoundaryClass;
  };
  intent: {
    statement: string;
    qaIds: readonly string[];
    risk: "low" | "medium" | "high" | "critical";
    blastRadius:
      | "localized"
      | "module"
      | "service"
      | "cross_service"
      | "tenant";
  };
  budgets: {
    wallClockSeconds: number;
    tokenMax: number;
    egress: "deny" | "allow";
    costUsdMax: number;
    fsWrites: number;
    gas: {
      compute: number;
      context: number;
      tool: number;
      network: number;
      governance: number;
      recovery: number;
    };
  };
  leases: readonly ActionLease[];
  policy: {
    bundleRef: string;
    traceRequired: true;
  };
  evidence: {
    required: readonly string[];
    onFailure: "halt" | "quarantine";
    backPropRequired: boolean;
    bplDepth?: number;
  };
  data: {
    pii: "forbidden";
    secrets: "forbidden";
    retention: RetentionClass;
  };
  context: {
    certificate: ContextCertificate;
  };
  capability: CapabilityLockTrustRecord;
}

export interface BackPropagationLineage {
  schemaVersion: 1;
  promotionRef: string;
  artifactRefs: readonly string[];
  skillChain: readonly string[];
  contextSliceDigest: `sha256:${string}`;
  sourceRefs: readonly string[];
  actorDecisionRefs: readonly string[];
  policyPath: string;
  createdAt: string;
}

export type GovernanceEvidenceKind = "model_decision" | "sandbox_execution";

export interface DurableGovernanceEvidence {
  schemaVersion: 1;
  recordId: string;
  kind: GovernanceEvidenceKind;
  action: ActionEnvelope;
  receipt: KernelJsonValue;
  bpl?: BackPropagationLineage;
  signedEnvelope?: SignedEvidenceEnvelope;
}

export interface PersistedGovernanceEvidence {
  recordId: string;
  scanId: string;
  kind: GovernanceEvidenceKind;
  actionId: string;
  mediaType: string;
  digest: `sha256:${string}`;
  contextCertificateDigest: `sha256:${string}`;
  retention: RetentionClass;
  createdAt: string;
  evidence: DurableGovernanceEvidence;
}
