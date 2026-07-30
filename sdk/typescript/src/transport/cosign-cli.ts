import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type {
  PromotionEvidenceBindings,
  SignatureVerification,
  SignedEvidenceEnvelope,
} from "../kernel/supply-chain-contracts.js";
import type {
  EvidenceSignerPort,
  SignatureVerifierPort,
} from "../kernel/ports.js";
import { canonicalJson, sha256 } from "../proof/canonical-json.js";

const execute = promisify(execFile);
const MAX_OUTPUT_BYTES = 1024 * 1024;
const TIMEOUT_MILLIS = 30_000;

function cleanEnvironment(
  additions: Readonly<Record<string, string>> = {},
): NodeJS.ProcessEnv {
  return {
    PATH: process.env["PATH"],
    HOME: process.env["HOME"],
    TMPDIR: process.env["TMPDIR"],
    SSL_CERT_FILE: process.env["SSL_CERT_FILE"],
    ...additions,
  };
}

async function runCosign(
  executable: string,
  args: readonly string[],
  environment?: Readonly<Record<string, string>>,
): Promise<void> {
  try {
    await execute(executable, [...args], {
      env: cleanEnvironment(environment),
      maxBuffer: MAX_OUTPUT_BYTES,
      timeout: TIMEOUT_MILLIS,
      windowsHide: true,
    });
  } catch (error) {
    throw new Error("Cosign operation failed closed.", { cause: error });
  }
}

export interface CosignCliVerifierOptions {
  executable?: string;
  verifierId: string;
}

export class CosignCliVerifier implements SignatureVerifierPort {
  readonly #executable: string;
  readonly #verifierId: string;

  constructor(options: CosignCliVerifierOptions) {
    this.#executable = options.executable ?? "cosign";
    this.#verifierId = options.verifierId;
  }

  async verify(
    input: Parameters<SignatureVerifierPort["verify"]>[0],
  ): Promise<SignatureVerification> {
    const args = ["verify-blob", "--bundle", input.signatureBundlePath];
    if (input.proofMode === "offline_key") {
      if (input.publicKeyPath === undefined) {
        throw new Error("Offline Cosign verification requires a public key.");
      }
      args.push(
        "--insecure-ignore-tlog",
        "--key",
        input.publicKeyPath,
      );
    }
    args.push(input.artifactPath);
    await runCosign(this.#executable, args);
    const [artifact, signatureBundle, publicKey] = await Promise.all([
      readFile(input.artifactPath),
      readFile(input.signatureBundlePath),
      input.publicKeyPath === undefined
        ? Promise.resolve(undefined)
        : readFile(input.publicKeyPath),
    ]);
    return {
      proofMode: input.proofMode,
      artifactDigest: sha256(artifact),
      signatureBundleDigest: sha256(signatureBundle),
      ...(publicKey === undefined ? {} : { publicKeyDigest: sha256(publicKey) }),
      verifiedAt: new Date().toISOString(),
      verifier: this.#verifierId,
    };
  }
}

export interface CosignCliSignerOptions {
  keyPath: string;
  publicKeyPath: string;
  verifierId: string;
  executable?: string;
  password?: string;
}

export class CosignCliEvidenceSigner implements EvidenceSignerPort {
  readonly #options: CosignCliSignerOptions;

  constructor(options: CosignCliSignerOptions) {
    this.#options = options;
  }

  async sign(payloadBytes: Uint8Array): Promise<SignedEvidenceEnvelope> {
    const payload = JSON.parse(
      Buffer.from(payloadBytes).toString("utf8"),
    ) as PromotionEvidenceBindings;
    const root = await mkdtemp(join(tmpdir(), "ckodex-evidence-"));
    try {
      const payloadPath = join(root, "payload.json");
      const bundlePath = join(root, "payload.sigstore.json");
      await writeFile(payloadPath, canonicalJson(payload), { mode: 0o600 });
      await runCosign(
        this.#options.executable ?? "cosign",
        [
          "sign-blob", "--yes", "--use-signing-config=false",
          "--bundle", bundlePath, "--key", this.#options.keyPath, payloadPath,
        ],
        this.#options.password === undefined
          ? {}
          : { COSIGN_PASSWORD: this.#options.password },
      );
      const [signatureBundle, publicKeyPem] = await Promise.all([
        readFile(bundlePath, "utf8"),
        readFile(this.#options.publicKeyPath, "utf8"),
      ]);
      return {
        schemaVersion: 1,
        mediaType: "application/vnd.ckodex.signed-evidence+json",
        payload,
        payloadDigest: sha256(canonicalJson(payload)),
        proofMode: "offline_key",
        publicKeyPem,
        signatureBundle,
        signatureBundleDigest: sha256(signatureBundle),
        verifier: this.#options.verifierId,
        signedAt: new Date().toISOString(),
      };
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
}
