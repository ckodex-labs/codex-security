export type Sha256Digest = `sha256:${string}`;

export interface CapabilitySpec {
  schemaVersion: 1;
  name: string;
  version: string;
  inputs: readonly string[];
  outputs: readonly string[];
  guards: readonly string[];
  budgets: {
    wallClockSeconds: number;
    tokenMax: number;
    egress: "deny" | "allow";
    costUsdMax: number;
    fsWrites: number;
  };
  cvRefs: readonly string[];
  dalRange: readonly [number, number];
  blastRadius: "localized" | "module" | "service" | "cross_service" | "tenant";
}

export interface CapabilityLock extends CapabilitySpec {
  specDigest: Sha256Digest;
  bundleRef: string;
}

export interface DigestReference {
  id: string;
  path: string;
  digest: Sha256Digest;
}

export interface SkillBundleManifest {
  schemaVersion: 1;
  name: string;
  version: string;
  bundleRef: string;
  signatureBundlePath: string;
  lock: DigestReference & { signatureBundlePath: string };
  policyRefs: readonly DigestReference[];
  cvRefs: readonly DigestReference[];
  evidenceWiring: readonly string[];
}

export interface SignatureVerification {
  proofMode: "offline_key" | "sigstore_transparency";
  artifactDigest: Sha256Digest;
  signatureBundleDigest: Sha256Digest;
  publicKeyDigest?: Sha256Digest;
  verifiedAt: string;
  verifier: string;
}

export interface VerifiedCapabilityBundle {
  root: string;
  spec: CapabilitySpec;
  lock: CapabilityLock;
  manifest: SkillBundleManifest;
  lockVerification: SignatureVerification;
  bundleVerification: SignatureVerification;
}

export interface PromotionEvidenceBindings {
  evidenceDigest: Sha256Digest;
  bplDigest: Sha256Digest;
  manifestDigest: Sha256Digest;
  lockDigest: Sha256Digest;
  bundleDigest: Sha256Digest;
  policyDigests: readonly Sha256Digest[];
  cvDigests: readonly Sha256Digest[];
  sbomDigest: Sha256Digest;
  coverageDigest: Sha256Digest;
  provenanceDigest: Sha256Digest;
}

export interface SignedEvidenceEnvelope {
  schemaVersion: 1;
  mediaType: "application/vnd.ckodex.signed-evidence+json";
  payload: PromotionEvidenceBindings;
  payloadDigest: Sha256Digest;
  proofMode: "offline_key" | "sigstore_transparency";
  publicKeyPem?: string;
  signatureBundle: string;
  signatureBundleDigest: Sha256Digest;
  verifier: string;
  signedAt: string;
}
