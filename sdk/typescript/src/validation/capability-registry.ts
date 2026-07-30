import type {
  CapabilityLock,
  CapabilitySpec,
  DigestReference,
  Sha256Digest,
  SkillBundleManifest,
} from "../kernel/supply-chain-contracts.js";

const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;

export class CapabilityRegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CapabilityRegistryError";
  }
}

function object(value: unknown, context: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new CapabilityRegistryError(`${context} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function exact(
  value: Record<string, unknown>,
  fields: readonly string[],
  context: string,
): void {
  if (Object.keys(value).sort().join() !== [...fields].sort().join()) {
    throw new CapabilityRegistryError(`${context} has an invalid shape.`);
  }
}

function text(value: unknown, context: string): string {
  if (typeof value !== "string" || !TOKEN.test(value)) {
    throw new CapabilityRegistryError(`${context} must be bounded text.`);
  }
  return value;
}

function digest(value: unknown, context: string): Sha256Digest {
  if (typeof value !== "string" || !DIGEST.test(value)) {
    throw new CapabilityRegistryError(`${context} must be a sha256 digest.`);
  }
  return value as Sha256Digest;
}

function texts(value: unknown, context: string): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) {
    throw new CapabilityRegistryError(`${context} must be a bounded array.`);
  }
  const result = value.map((item, index) => text(item, `${context}[${index}]`));
  if (new Set(result).size !== result.length) {
    throw new CapabilityRegistryError(`${context} contains duplicates.`);
  }
  return result;
}

function positive(value: unknown, context: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new CapabilityRegistryError(`${context} must be a nonnegative integer.`);
  }
  return Number(value);
}

function specFields(value: Record<string, unknown>): CapabilitySpec {
  const budgets = object(value["budgets"], "budgets");
  exact(
    budgets,
    ["wallClockSeconds", "tokenMax", "egress", "costUsdMax", "fsWrites"],
    "budgets",
  );
  const range = value["dalRange"];
  if (!Array.isArray(range) || range.length !== 2) {
    throw new CapabilityRegistryError("dalRange must contain two integers.");
  }
  const dalRange = [positive(range[0], "dalRange[0]"), positive(range[1], "dalRange[1]")] as const;
  if (dalRange[0] > dalRange[1] || dalRange[1] > 4) {
    throw new CapabilityRegistryError("dalRange must be ordered within 0..4.");
  }
  const egress = budgets["egress"];
  const blastRadius = value["blastRadius"];
  if (egress !== "deny" && egress !== "allow") {
    throw new CapabilityRegistryError("budgets.egress is invalid.");
  }
  if (!["localized", "module", "service", "cross_service", "tenant"].includes(String(blastRadius))) {
    throw new CapabilityRegistryError("blastRadius is invalid.");
  }
  return {
    schemaVersion: 1,
    name: text(value["name"], "name"),
    version: text(value["version"], "version"),
    inputs: texts(value["inputs"], "inputs"),
    outputs: texts(value["outputs"], "outputs"),
    guards: texts(value["guards"], "guards"),
    budgets: {
      wallClockSeconds: positive(budgets["wallClockSeconds"], "wallClockSeconds"),
      tokenMax: positive(budgets["tokenMax"], "tokenMax"),
      egress,
      costUsdMax: positive(budgets["costUsdMax"], "costUsdMax"),
      fsWrites: positive(budgets["fsWrites"], "fsWrites"),
    },
    cvRefs: texts(value["cvRefs"], "cvRefs"),
    dalRange,
    blastRadius: blastRadius as CapabilitySpec["blastRadius"],
  };
}

export function validateCapabilitySpec(value: unknown): CapabilitySpec {
  const record = object(value, "CapabilitySpec");
  exact(record, [
    "schemaVersion", "name", "version", "inputs", "outputs", "guards",
    "budgets", "cvRefs", "dalRange", "blastRadius",
  ], "CapabilitySpec");
  if (record["schemaVersion"] !== 1) {
    throw new CapabilityRegistryError("CapabilitySpec schemaVersion must be 1.");
  }
  const spec = specFields(record);
  if (!spec.cvRefs.includes("CV-SAFE") || !spec.cvRefs.includes("CV-EVID")) {
    throw new CapabilityRegistryError("CapabilitySpec requires CV-SAFE and CV-EVID.");
  }
  return spec;
}

export function validateCapabilityLock(value: unknown): CapabilityLock {
  const record = object(value, "CapabilityLock");
  exact(record, [
    "schemaVersion", "name", "version", "inputs", "outputs", "guards",
    "budgets", "cvRefs", "dalRange", "blastRadius", "specDigest", "bundleRef",
  ], "CapabilityLock");
  const spec = specFields(record);
  return {
    ...spec,
    specDigest: digest(record["specDigest"], "specDigest"),
    bundleRef: text(record["bundleRef"], "bundleRef"),
  };
}

function reference(value: unknown, context: string): DigestReference {
  const record = object(value, context);
  exact(record, ["id", "path", "digest"], context);
  return {
    id: text(record["id"], `${context}.id`),
    path: text(record["path"], `${context}.path`),
    digest: digest(record["digest"], `${context}.digest`),
  };
}

export function validateSkillBundle(value: unknown): SkillBundleManifest {
  const record = object(value, "SkillBundle");
  exact(record, [
    "schemaVersion", "name", "version", "bundleRef", "signatureBundlePath", "lock",
    "policyRefs", "cvRefs", "evidenceWiring",
  ], "SkillBundle");
  const lockRecord = object(record["lock"], "SkillBundle.lock");
  exact(lockRecord, ["id", "path", "digest", "signatureBundlePath"], "SkillBundle.lock");
  const refs = (input: unknown, context: string) => {
    if (!Array.isArray(input) || input.length === 0 || input.length > 16) {
      throw new CapabilityRegistryError(`${context} must be a bounded array.`);
    }
    return input.map((item, index) => reference(item, `${context}[${index}]`));
  };
  if (record["schemaVersion"] !== 1) {
    throw new CapabilityRegistryError("SkillBundle schemaVersion must be 1.");
  }
  return {
    schemaVersion: 1,
    name: text(record["name"], "name"),
    version: text(record["version"], "version"),
    bundleRef: text(record["bundleRef"], "bundleRef"),
    signatureBundlePath: text(record["signatureBundlePath"], "signatureBundlePath"),
    lock: {
      id: text(lockRecord["id"], "SkillBundle.lock.id"),
      path: text(lockRecord["path"], "SkillBundle.lock.path"),
      digest: digest(lockRecord["digest"], "SkillBundle.lock.digest"),
      signatureBundlePath: text(lockRecord["signatureBundlePath"], "signatureBundlePath"),
    },
    policyRefs: refs(record["policyRefs"], "policyRefs"),
    cvRefs: refs(record["cvRefs"], "cvRefs"),
    evidenceWiring: texts(record["evidenceWiring"], "evidenceWiring"),
  };
}
