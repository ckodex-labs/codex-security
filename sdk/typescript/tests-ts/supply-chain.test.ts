import { chmod, cp, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import type {
  EvidenceSignerPort,
  SignatureVerifierPort,
} from "../src/kernel/ports.js";
import type {
  PromotionEvidenceBindings,
  SignedEvidenceEnvelope,
} from "../src/kernel/supply-chain-contracts.js";
import { canonicalJson, sha256 } from "../src/proof/canonical-json.js";
import {
  createSignedEvidenceEnvelope,
} from "../src/proof/signed-evidence.js";
import { CosignCliVerifier } from "../src/transport/cosign-cli.js";
import { FilesystemCapabilityRegistry } from "../src/transport/filesystem-capability-registry.js";

const source = new URL("../capabilities/provider-projection", import.meta.url);
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) =>
      rm(path, { recursive: true, force: true }),
    ),
  );
});

async function fixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "ckodex-registry-"));
  temporaryDirectories.push(root);
  await cp(source, root, { recursive: true });
  return root;
}

const verifier: SignatureVerifierPort = {
  async verify(input) {
    if (input.publicKeyPath === undefined) {
      throw new Error("fixture requires a public key");
    }
    const [artifact, bundle, publicKey] = await Promise.all([
      readFile(input.artifactPath),
      readFile(input.signatureBundlePath),
      readFile(input.publicKeyPath),
    ]);
    return {
      proofMode: input.proofMode,
      artifactDigest: sha256(artifact),
      signatureBundleDigest: sha256(bundle),
      publicKeyDigest: sha256(publicKey),
      verifiedAt: new Date().toISOString(),
      verifier: "test-verifier",
    };
  },
};

test("resolves digest-bound policy and CV references", async () => {
    const root = await fixture();
    const registry = new FilesystemCapabilityRegistry({
      root,
      publicKeyPath: "cosign.pub",
      verifier,
    });
    const result = await registry.resolve(
      "urn:ckodex:capability:provider-projection:v1",
    );
    expect(result.spec.cvRefs).toEqual(["CV-SAFE", "CV-EVID"]);
    expect(result.lockVerification.proofMode).toBe("offline_key");
});

test("rejects reference tampering and symlink escape", async () => {
    const root = await fixture();
    await writeFile(
      join(root, "policy/provider-projection.json"),
      '{"tampered":true}\n',
    );
    const registry = new FilesystemCapabilityRegistry({
      root,
      publicKeyPath: "cosign.pub",
      verifier,
    });
    await expect(
      registry.resolve("urn:ckodex:capability:provider-projection:v1"),
    ).rejects.toThrow("digest mismatch");

    const escaped = await fixture();
    const outsideRoot = await mkdtemp(join(tmpdir(), "ckodex-outside-"));
    temporaryDirectories.push(outsideRoot);
    const outside = join(outsideRoot, "key");
    await writeFile(outside, "outside");
    await rm(join(escaped, "cosign.pub"));
    await symlink(outside, join(escaped, "cosign.pub"));
    await expect(
      new FilesystemCapabilityRegistry({
        root: escaped,
        publicKeyPath: "cosign.pub",
        verifier,
      }).resolve("urn:ckodex:capability:provider-projection:v1"),
    ).rejects.toThrow("escapes its root");
});

test("binds every promotion artifact into the signed payload", async () => {
    const digest = sha256("artifact");
    const bindings: PromotionEvidenceBindings = {
      evidenceDigest: digest,
      bplDigest: digest,
      manifestDigest: digest,
      lockDigest: digest,
      bundleDigest: digest,
      policyDigests: [digest],
      cvDigests: [digest],
      sbomDigest: digest,
      coverageDigest: digest,
      provenanceDigest: digest,
    };
    const signer: EvidenceSignerPort = {
      async sign(payload): Promise<SignedEvidenceEnvelope> {
        const parsed = JSON.parse(
          Buffer.from(payload).toString("utf8"),
        ) as PromotionEvidenceBindings;
        return {
          schemaVersion: 1,
          mediaType: "application/vnd.ckodex.signed-evidence+json",
          payload: parsed,
          payloadDigest: sha256(canonicalJson(parsed)),
          proofMode: "offline_key",
          publicKeyPem: "-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----",
          signatureBundle: '{"fixture":true}',
          signatureBundleDigest: sha256('{"fixture":true}'),
          verifier: "test-signer",
          signedAt: new Date().toISOString(),
        };
      },
    };
    const envelope = await createSignedEvidenceEnvelope(bindings, signer);
    expect(envelope.payload).toEqual(bindings);
});

test("Cosign adapter uses bounded argv without a shell", async () => {
    const root = await fixture();
    const executable = join(root, "fake-cosign");
    const log = join(root, "args.json");
    await writeFile(
      executable,
      `#!/usr/bin/env node\nrequire("node:fs").writeFileSync(${JSON.stringify(log)},JSON.stringify(process.argv.slice(2)))\n`,
    );
    await chmod(executable, 0o700);
    await new CosignCliVerifier({
      executable,
      verifierId: "test",
    }).verify({
      artifactPath: join(root, "lock.json"),
      signatureBundlePath: join(root, "signatures/lock.sigstore.json"),
      publicKeyPath: join(root, "cosign.pub"),
      proofMode: "offline_key",
    });
    expect(JSON.parse(await readFile(log, "utf8"))).toContain(
      "--insecure-ignore-tlog",
    );
});
