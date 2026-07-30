import { readFile, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type {
  CapabilityRegistryPort,
  SignatureVerifierPort,
} from "../kernel/ports.js";
import type {
  DigestReference,
  VerifiedCapabilityBundle,
} from "../kernel/supply-chain-contracts.js";
import { canonicalJson, sha256 } from "../proof/canonical-json.js";
import {
  CapabilityRegistryError,
  validateCapabilityLock,
  validateCapabilitySpec,
  validateSkillBundle,
} from "../validation/capability-registry.js";

export interface FilesystemCapabilityRegistryOptions {
  root: string;
  manifestPath?: string;
  publicKeyPath: string;
  verifier: SignatureVerifierPort;
  proofMode?: "offline_key" | "sigstore_transparency";
}

async function json(path: string): Promise<unknown> {
  const bytes = await readFile(path);
  if (bytes.byteLength > 256 * 1024) {
    throw new CapabilityRegistryError("Registry JSON exceeds 256 KiB.");
  }
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new CapabilityRegistryError(`Registry JSON is invalid: ${path}`);
  }
}

async function child(root: string, path: string): Promise<string> {
  if (isAbsolute(path) || path.includes("\0")) {
    throw new CapabilityRegistryError("Registry references must be relative.");
  }
  const candidate = await realpath(resolve(root, path));
  const rel = relative(root, candidate);
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    throw new CapabilityRegistryError("Registry reference escapes its root.");
  }
  if (!(await stat(candidate)).isFile()) {
    throw new CapabilityRegistryError("Registry reference is not a file.");
  }
  return candidate;
}

async function verifiedReference(
  root: string,
  reference: DigestReference,
): Promise<string> {
  const path = await child(root, reference.path);
  if (sha256(await readFile(path)) !== reference.digest) {
    throw new CapabilityRegistryError(`${reference.id} digest mismatch.`);
  }
  return path;
}

async function resolveReferences(
  root: string,
  manifest: VerifiedCapabilityBundle["manifest"],
): Promise<void> {
  await Promise.all([
    ...manifest.policyRefs.map((ref) => verifiedReference(root, ref)),
    ...manifest.cvRefs.map((ref) => verifiedReference(root, ref)),
  ]);
}

function assertLockMatchesSpec(
  spec: VerifiedCapabilityBundle["spec"],
  lock: VerifiedCapabilityBundle["lock"],
): void {
  const { specDigest: _specDigest, bundleRef: _bundleRef, ...compiled } = lock;
  if (
    lock.specDigest !== sha256(canonicalJson(spec)) ||
    canonicalJson(compiled) !== canonicalJson(spec)
  ) {
    throw new CapabilityRegistryError("CapabilityLock does not match its spec.");
  }
}

async function verifyBundleArtifacts(
  verifier: SignatureVerifierPort,
  input: {
    lockPath: string;
    lockSignaturePath: string;
    manifestPath: string;
    bundleSignaturePath: string;
    publicKeyPath: string;
    proofMode: "offline_key" | "sigstore_transparency";
  },
) {
  return await Promise.all([
    verifier.verify({
      artifactPath: input.lockPath,
      signatureBundlePath: input.lockSignaturePath,
      publicKeyPath: input.publicKeyPath,
      proofMode: input.proofMode,
    }),
    verifier.verify({
      artifactPath: input.manifestPath,
      signatureBundlePath: input.bundleSignaturePath,
      publicKeyPath: input.publicKeyPath,
      proofMode: input.proofMode,
    }),
  ]);
}

export class FilesystemCapabilityRegistry implements CapabilityRegistryPort {
  readonly #options: FilesystemCapabilityRegistryOptions;

  constructor(options: FilesystemCapabilityRegistryOptions) {
    this.#options = options;
  }

  async resolve(bundleRef: string): Promise<VerifiedCapabilityBundle> {
    const root = await realpath(this.#options.root);
    const manifestPath = await child(
      root,
      this.#options.manifestPath ?? "bundle.json",
    );
    const manifest = validateSkillBundle(await json(manifestPath));
    if (manifest.bundleRef !== bundleRef) {
      throw new CapabilityRegistryError("SkillBundle reference mismatch.");
    }
    const [lockPath, publicKeyPath, bundleSignaturePath] = await Promise.all([
      verifiedReference(root, manifest.lock),
      child(root, this.#options.publicKeyPath),
      child(root, manifest.signatureBundlePath),
    ]);
    const lockSignaturePath = await child(
      root,
      manifest.lock.signatureBundlePath,
    );
    const specPath = await child(root, "spec.json");
    const [spec, lock] = await Promise.all([
      json(specPath).then(validateCapabilitySpec),
      json(lockPath).then(validateCapabilityLock),
    ]);
    assertLockMatchesSpec(spec, lock);
    if (lock.bundleRef !== bundleRef) {
      throw new CapabilityRegistryError("CapabilityLock bundle reference mismatch.");
    }
    await resolveReferences(root, manifest);
    const proofMode = this.#options.proofMode ?? "offline_key";
    const [lockVerification, bundleVerification] =
      await verifyBundleArtifacts(this.#options.verifier, {
        lockPath,
        lockSignaturePath,
        manifestPath,
        bundleSignaturePath,
        publicKeyPath,
        proofMode,
      });
    return {
      root,
      spec,
      lock,
      manifest,
      lockVerification,
      bundleVerification,
    };
  }
}
