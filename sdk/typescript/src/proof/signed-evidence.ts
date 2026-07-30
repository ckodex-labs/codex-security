import type { EvidenceSignerPort } from "../kernel/ports.js";
import type {
  CapabilityLockTrustRecord,
  DurableGovernanceEvidence,
} from "../kernel/governance-contracts.js";
import type {
  PromotionEvidenceBindings,
  Sha256Digest,
  SignedEvidenceEnvelope,
  VerifiedCapabilityBundle,
} from "../kernel/supply-chain-contracts.js";
import { canonicalJson, sha256 } from "./canonical-json.js";

const DIGEST = /^sha256:[a-f0-9]{64}$/u;

function requireDigest(value: string, context: string): Sha256Digest {
  if (!DIGEST.test(value)) {
    throw new Error(`${context} must be a sha256 digest.`);
  }
  return value as Sha256Digest;
}

export function capabilityTrustFromVerified(
  capability: VerifiedCapabilityBundle,
  now: Date = new Date(),
): CapabilityLockTrustRecord {
  if (capability.lockVerification.proofMode !== "offline_key") {
    throw new Error("Only explicitly verified capability proof is admitted.");
  }
  return {
    schemaVersion: 1,
    lockDigest: capability.lockVerification.artifactDigest,
    bundleRef: capability.manifest.bundleRef,
    verification: {
      kind: "cosign",
      signatureDigest: capability.lockVerification.signatureBundleDigest,
      verifiedAt: capability.lockVerification.verifiedAt,
      expiresAt: new Date(now.getTime() + 5 * 60_000).toISOString(),
      verifier: capability.lockVerification.verifier,
    },
  };
}

export async function createSignedEvidenceEnvelope(
  bindings: PromotionEvidenceBindings,
  signer: EvidenceSignerPort,
): Promise<SignedEvidenceEnvelope> {
  for (const [key, value] of Object.entries(bindings)) {
    if (Array.isArray(value)) {
      value.forEach((item, index) => requireDigest(item, `${key}[${index}]`));
    } else {
      requireDigest(String(value), key);
    }
  }
  const canonical = canonicalJson(bindings);
  const envelope = await signer.sign(Buffer.from(canonical));
  if (
    envelope.payloadDigest !== sha256(canonical) ||
    canonicalJson(envelope.payload) !== canonical ||
    envelope.proofMode !== "offline_key"
  ) {
    throw new Error("Evidence signer returned an unbound envelope.");
  }
  return envelope;
}

export function evidenceBindings(
  evidence: DurableGovernanceEvidence,
  artifacts: Omit<
    PromotionEvidenceBindings,
    "evidenceDigest" | "bplDigest"
  >,
): PromotionEvidenceBindings {
  if (evidence.bpl === undefined) {
    throw new Error("Signed promotion evidence requires BPL.");
  }
  return {
    evidenceDigest: sha256(canonicalJson(evidence)),
    bplDigest: sha256(canonicalJson(evidence.bpl)),
    ...artifacts,
  };
}
