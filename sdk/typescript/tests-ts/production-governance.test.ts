import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import type { CapabilityLockTrustRecord } from "../src/kernel/governance-contracts.js";
import {
  createProductionGovernanceBinding,
  GovernanceBindingError,
  requireCapabilityLockTrust,
  type ProductionGovernanceFacts,
} from "../src/proof/production-governance.js";

const digest = (value: string): `sha256:${string}` =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

const NOW = new Date("2026-07-29T12:00:00.000Z");

function trust(): CapabilityLockTrustRecord {
  return {
    schemaVersion: 1,
    lockDigest: digest("compiled-lock"),
    bundleRef: "urn:ckodex:capability:provider-projection:v1",
    verification: {
      kind: "cosign",
      signatureDigest: digest("cosign-bundle"),
      verifiedAt: "2026-07-29T11:59:00.000Z",
      expiresAt: "2026-07-29T13:00:00.000Z",
      verifier: "urn:ckodex:verifier:release",
    },
  };
}

function facts(providerOrder = "normal"): ProductionGovernanceFacts {
  const provider =
    providerOrder === "normal"
      ? {
          kind: "private" as const,
          id: "ckodex-private",
          model: "private-model",
          baseUrl: "https://10.0.0.8/v1",
          credentialEnv: "PRIVATE_MODEL_TOKEN",
        }
      : ({
          credentialEnv: "PRIVATE_MODEL_TOKEN",
          baseUrl: "https://10.0.0.8/v1",
          model: "private-model",
          id: "ckodex-private",
          kind: "private",
        } as const);
  return {
    scanId: "scan-1",
    targetId: "target-1",
    repositoryRevision: "deadbeef",
    scanMode: "standard",
    pluginVersion: "0.1.1",
    provider,
  };
}

describe("production governance binding", () => {
  test("derives canonical context and binds the lease to verified lock trust", () => {
    const first = createProductionGovernanceBinding(facts(), trust(), NOW);
    const reordered = createProductionGovernanceBinding(
      facts("reordered"),
      trust(),
      NOW,
    );

    expect(first.action.context.certificate.sliceHash).toBe(
      reordered.action.context.certificate.sliceHash,
    );
    expect(first.action.leases).toHaveLength(1);
    expect(first.action.leases[0]?.scope).toBe(
      first.action.capability.bundleRef,
    );
    expect(first.providerDecision.trace.actionId).toBe(first.action.id);
    expect(first.providerDecision.trace).toMatchObject({
      providerId: "ckodex-private",
      modelId: "private-model",
      transport: "private_http",
    });
  });

  test("rejects absent, expired, future, and non-cosign trust", () => {
    expect(() => requireCapabilityLockTrust(undefined, NOW)).toThrow(
      GovernanceBindingError,
    );
    const expired = structuredClone(trust());
    expired.verification.expiresAt = "2026-07-29T12:00:00.000Z";
    expect(() => requireCapabilityLockTrust(expired, NOW)).toThrow(
      "not currently valid",
    );
    const future = structuredClone(trust());
    future.verification.verifiedAt = "2026-07-29T12:00:01.000Z";
    expect(() => requireCapabilityLockTrust(future, NOW)).toThrow(
      "not currently valid",
    );
    const inverted = structuredClone(trust());
    inverted.verification.verifiedAt = "2026-07-29T11:59:00.000Z";
    inverted.verification.expiresAt = "2026-07-29T11:58:00.000Z";
    expect(() => requireCapabilityLockTrust(inverted, NOW)).toThrow(
      "not currently valid",
    );
    const unzoned = structuredClone(trust());
    unzoned.verification.verifiedAt = "2026-07-29T11:59:00.000";
    expect(() => requireCapabilityLockTrust(unzoned, NOW)).toThrow(
      "must include an ISO 8601 zone",
    );
    const unsupported = structuredClone(trust()) as unknown as Record<
      string,
      unknown
    >;
    (unsupported["verification"] as Record<string, unknown>)["kind"] = "manual";
    expect(() => requireCapabilityLockTrust(unsupported, NOW)).toThrow(
      "must be cosign verified",
    );
  });

  test("rejects malformed digests and unrecognized trust fields", () => {
    const malformed = structuredClone(trust()) as unknown as Record<
      string,
      unknown
    >;
    malformed["lockDigest"] = "sha256:not-a-digest";
    expect(() => requireCapabilityLockTrust(malformed, NOW)).toThrow(
      "must be a sha256 digest",
    );
    const widened = { ...trust(), trusted: true };
    expect(() => requireCapabilityLockTrust(widened, NOW)).toThrow(
      "invalid shape",
    );
  });
});
