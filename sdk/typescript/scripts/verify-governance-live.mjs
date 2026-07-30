import { execFileSync, spawnSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  sign as signBytes,
} from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createProductionGovernanceBinding,
  requireCapabilityLockTrust,
} from "../dist/proof/production-governance.js";
import {
  capabilityTrustFromVerified,
  createSignedEvidenceEnvelope,
} from "../dist/proof/signed-evidence.js";
import { canonicalJson } from "../dist/proof/canonical-json.js";
import { CosignCliVerifier } from "../dist/transport/cosign-cli.js";
import { FilesystemCapabilityRegistry } from "../dist/transport/filesystem-capability-registry.js";
import { createDecisionEvidence } from "../dist/proof/decision-trace.js";
import { runWorkbench } from "../dist/runtime.js";
import { WorkbenchGovernanceEvidenceAdapter } from "../dist/transport/workbench-governance-evidence.js";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pluginRoot = join(packageRoot, "_bundled_plugin");
const digest = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

function executable(candidates) {
  for (const candidate of candidates) {
    const result = spawnSync("sh", ["-c", `command -v "${candidate}"`], {
      encoding: "utf8",
    });
    if (result.status === 0) return result.stdout.trim();
  }
  throw new Error(`Required executable not found: ${candidates.join(", ")}`);
}

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  }).trim();
}

async function signedTrust() {
  const capabilityRoot = join(
    packageRoot,
    "capabilities",
    "provider-projection",
  );
  const verified = await new FilesystemCapabilityRegistry({
    root: capabilityRoot,
    publicKeyPath: "cosign.pub",
    verifier: new CosignCliVerifier({
      verifierId: "cosign-cli:governance-live",
    }),
  }).resolve("urn:ckodex:capability:provider-projection:v1");
  return { trust: capabilityTrustFromVerified(verified), verified };
}

async function expectFailure(operation, expected) {
  try {
    await operation();
  } catch (error) {
    if (String(error).includes(expected)) return;
    throw error;
  }
  throw new Error(`Expected failure containing: ${expected}`);
}

function ephemeralOfflineSigner() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  const hint = createHash("sha256").update(publicKeyDer).digest("base64");
  return {
    async sign(payloadBytes) {
      const payload = JSON.parse(Buffer.from(payloadBytes).toString("utf8"));
      const signatureBundle = JSON.stringify({
        mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
        verificationMaterial: { publicKey: { hint } },
        messageSignature: {
          messageDigest: {
            algorithm: "SHA2_256",
            digest: createHash("sha256")
              .update(payloadBytes)
              .digest("base64"),
          },
          signature: signBytes("sha256", payloadBytes, privateKey).toString(
            "base64",
          ),
        },
      });
      return {
        schemaVersion: 1,
        mediaType: "application/vnd.ckodex.signed-evidence+json",
        payload,
        payloadDigest: digest(canonicalJson(payload)),
        proofMode: "offline_key",
        publicKeyPem,
        signatureBundle,
        signatureBundleDigest: digest(signatureBundle),
        verifier: "ephemeral-offline-test-key",
        signedAt: new Date().toISOString(),
      };
    },
  };
}

async function registerScan(workbench, repository, scanDir) {
  return workbench([
    "register-cli-scan",
    "--repository",
    repository,
    "--scan-dir",
    scanDir,
    "--recipe-json",
    JSON.stringify({
      repository,
      target: { kind: "repository", paths: [] },
      mode: "standard",
      pluginVersion: "0.1.1",
      config: {},
    }),
  ]);
}

function markSealed(python, database, scanId, manifestDigest) {
  const program = [
    "import sqlite3,sys",
    "connection=sqlite3.connect(sys.argv[1])",
    "connection.execute('PRAGMA foreign_keys = ON')",
    "connection.execute(\"UPDATE scans SET status='complete', completed_at=?, seal_manifest_digest=? WHERE id=?\",(sys.argv[4],sys.argv[3],sys.argv[2]))",
    "connection.commit()",
  ].join("\n");
  run(python, [
    "-I",
    "-B",
    "-c",
    program,
    database,
    scanId,
    manifestDigest,
    new Date().toISOString(),
  ]);
}

function assertNoSensitiveText(value) {
  const serialized = JSON.stringify(value);
  const patterns = [
    /\b(?:authorization|api[_ -]?key|token|password|secret)\s*[:=]\s*\S+/iu,
    /\bbearer\s+[A-Za-z0-9._~-]{12,}/iu,
    /\bsk-[A-Za-z0-9_-]{12,}/u,
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu,
  ];
  if (patterns.some((pattern) => pattern.test(serialized))) {
    throw new Error(
      "Persisted governance evidence contains secret/PII-like text.",
    );
  }
}

async function exercise(root, trust, verified, now) {
  const python = executable([
    "python3.14",
    "python3.13",
    "python3.12",
    "python3.11",
  ]);
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  const stateDir = join(root, "state");
  await Promise.all([mkdir(repository), mkdir(scanDir)]);
  await writeFile(join(repository, "README.md"), "# Governance fixture\n");
  run("git", ["init", "--quiet"], { cwd: repository });
  const options = {
    python,
    pluginRoot,
    environment: { CODEX_SECURITY_STATE_DIR: stateDir },
  };
  const workbench = (args) => runWorkbench(options, args);
  const registration = await registerScan(workbench, repository, scanDir);
  const scanId = String(registration.scanId);
  const binding = createProductionGovernanceBinding(
    {
      scanId,
      targetId: String(registration.targetId),
      repositoryRevision: null,
      scanMode: "standard",
      pluginVersion: "0.1.1",
      provider: {
        kind: "local",
        id: "live-local",
        model: "repository-fixture",
        baseUrl: "http://127.0.0.1:11434/v1",
      },
    },
    trust,
    now,
  );
  const adapter = new WorkbenchGovernanceEvidenceAdapter({
    scanId,
    action: binding.action,
    append: workbench,
  });
  await adapter.record(binding.providerDecision);
  const providerRecordId = `model:${binding.providerDecision.trace.traceId}`;
  const stored = await workbench([
    "get-governance-evidence",
    "--scan-id",
    scanId,
    "--record-id",
    providerRecordId,
  ]);
  assertNoSensitiveText(stored);
  const promotion = await exercisePromotion(
    workbench,
    python,
    stateDir,
    scanDir,
    scanId,
    binding,
    verified,
  );
  return { scanId, stored, promotion };
}

async function exercisePromotion(
  workbench,
  python,
  stateDir,
  scanDir,
  scanId,
  binding,
  verified,
) {
  const manifest = `${JSON.stringify({ sealed: true, scanId })}\n`;
  await writeFile(join(scanDir, "scan-manifest.json"), manifest);
  const manifestDigest = digest(manifest);
  const action = structuredClone(binding.action);
  action.id = `${binding.action.id}:promotion`;
  action.actor.dal = 3;
  action.evidence = {
    required: ["decision_trace", "bpl"],
    onFailure: "halt",
    backPropRequired: true,
    bplDepth: 4,
  };
  action.data.retention = "regulated";
  const receipt = createDecisionEvidence({
    traceId: `promotion:${scanId}`,
    actionId: action.id,
    decision: {
      verdict: "allow",
      policyId: action.policy.bundleRef,
      reasons: ["promotion evidence gate passed"],
    },
    timestamp: new Date().toISOString(),
  });
  const promotionRecordId = `model:${receipt.trace.traceId}`;
  const promotionRef = `urn:ckodex:promotion:${scanId}`;
  const bpl = {
    schemaVersion: 1,
    promotionRef,
    artifactRefs: [`scan-manifest:${manifestDigest}`],
    skillChain: ["skill:security-scan"],
    contextSliceDigest: action.context.certificate.sliceHash,
    sourceRefs: ["source:repository"],
    actorDecisionRefs: [`decision:${promotionRecordId}`],
    policyPath: action.policy.bundleRef,
    createdAt: new Date().toISOString(),
  };
  const unsignedEvidence = {
    schemaVersion: 1,
    recordId: promotionRecordId,
    kind: "model_decision",
    action,
    receipt,
    bpl,
  };
  const signedEnvelope = await createSignedEvidenceEnvelope(
    {
      evidenceDigest: digest(canonicalJson(unsignedEvidence)),
      bplDigest: digest(canonicalJson(bpl)),
      manifestDigest,
      lockDigest: verified.lockVerification.artifactDigest,
      bundleDigest: verified.bundleVerification.artifactDigest,
      policyDigests: verified.manifest.policyRefs.map((ref) => ref.digest),
      cvDigests: verified.manifest.cvRefs.map((ref) => ref.digest),
      sbomDigest: digest("governance-live-sbom"),
      coverageDigest: digest("governance-live-coverage"),
      provenanceDigest: digest("governance-live-provenance"),
    },
    ephemeralOfflineSigner(),
  );
  const adapter = new WorkbenchGovernanceEvidenceAdapter({
    scanId,
    action,
    append: workbench,
    bpl,
    signedEnvelope,
  });
  await adapter.record(receipt);
  markSealed(
    python,
    join(stateDir, "workbench.sqlite3"),
    scanId,
    manifestDigest,
  );
  const promotionVerified = await workbench([
    "verify-governance-promotion",
    "--scan-id",
    scanId,
    "--record-id",
    promotionRecordId,
    "--promotion-ref",
    promotionRef,
  ]);
  await expectFailure(
    () =>
      workbench([
        "verify-governance-promotion",
        "--scan-id",
        scanId,
        "--record-id",
        promotionRecordId,
        "--promotion-ref",
        `${promotionRef}:wrong`,
      ]),
    "Promotion reference does not match",
  );
  assertNoSensitiveText(promotionVerified);
  return promotionVerified;
}

const root = await realpath(
  await mkdtemp(join(tmpdir(), "codex-governance-live-")),
);
try {
  const now = new Date();
  const { trust, verified } = await signedTrust();
  requireCapabilityLockTrust(trust, now);
  await expectFailure(
    () => requireCapabilityLockTrust(undefined, now),
    "must be an object",
  );
  const expired = structuredClone(trust);
  expired.verification.expiresAt = now.toISOString();
  await expectFailure(
    () => requireCapabilityLockTrust(expired, now),
    "not currently valid",
  );
  const result = await exercise(root, trust, verified, now);
  process.stdout.write(
    `${JSON.stringify({
      lockDigest: trust.lockDigest,
      signatureDigest: trust.verification.signatureDigest,
      providerEvidenceDigest: result.stored.governanceEvidence.digest,
      promotionEvidence: result.promotion.promotionEvidence,
      leakageInspection: "pass",
    })}\n`,
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
