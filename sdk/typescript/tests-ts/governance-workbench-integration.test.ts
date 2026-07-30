import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  chmod,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import type { ActionEnvelope } from "../src/kernel/governance-contracts.js";
import { createDecisionEvidence } from "../src/proof/decision-trace.js";
import { canonicalJson } from "../src/proof/canonical-json.js";
import { runWorkbench } from "../src/runtime.js";
import { WorkbenchGovernanceEvidenceAdapter } from "../src/transport/workbench-governance-evidence.js";
import type { SandboxEvidenceRecord } from "../src/transport/sandbox/types.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];
const digest = (value: string): `sha256:${string}` =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function pythonPath(): string {
  for (const command of [
    "python3.14",
    "python3.13",
    "python3.12",
    "python3.11",
    "python3",
  ]) {
    const path = Bun.which(command);
    if (path !== null) return path;
  }
  throw new Error("Python is required for workbench integration tests.");
}

function action(
  id: string,
  options: { promotion?: boolean } = {},
): ActionEnvelope {
  const promotion = options.promotion ?? false;
  const now = Date.now();
  const issuedAt = new Date(now - 60_000).toISOString();
  const expiresAt = new Date(now + 10 * 60_000).toISOString();
  return {
    schemaVersion: 1,
    id,
    actor: { kind: "agent", id: "ca-002", dal: promotion ? 3 : 2 },
    coactors: [],
    scope: {
      tenant: "test",
      environment: "dev",
      workspace: "codex-security",
      project: "fixture",
      boundaryClass: "local",
    },
    intent: {
      statement: "Exercise durable governance evidence.",
      qaIds: ["QA-EVID-001"],
      risk: promotion ? "critical" : "high",
      blastRadius: "service",
    },
    budgets: {
      wallClockSeconds: 300,
      tokenMax: 50_000,
      egress: "deny",
      costUsdMax: 5,
      fsWrites: 50,
      gas: {
        compute: 1,
        context: 1,
        tool: 1,
        network: 0,
        governance: 1,
        recovery: 1,
      },
    },
    leases: [
      {
        kind: "capability",
        ttl: "PT5M",
        heartbeatDue: new Date(now + 5 * 60_000).toISOString(),
        revocableBy: ["operator"],
        scope: "urn:ckodex:capability:test",
        decayFn: "step",
      },
    ],
    policy: {
      bundleRef: "urn:ckodex:policy:test:v1",
      traceRequired: true,
    },
    evidence: {
      required: ["decision_trace"],
      onFailure: "halt",
      backPropRequired: promotion,
      ...(promotion ? { bplDepth: 4 } : {}),
    },
    data: {
      pii: "forbidden",
      secrets: "forbidden",
      retention: promotion ? "regulated" : "standard",
    },
    context: {
      certificate: {
        schemaVersion: 1,
        id: `context:${id}`,
        sliceHash: digest(`context:${id}`),
        resolution: "standard",
        justification: "Bounded integration verification.",
        layers: ["identity", "objective", "task", "policy"],
        issuedAt,
        expiresAt,
      },
    },
    capability: {
      schemaVersion: 1,
      lockDigest: digest("capability-lock"),
      bundleRef: "urn:ckodex:capability:test",
      verification: {
        kind: "cosign",
        signatureDigest: digest("capability-lock-signature"),
        verifiedAt: issuedAt,
        expiresAt,
        verifier: "urn:ckodex:verifier:test",
      },
    },
  };
}

function sandboxReceipt(executionId: string): SandboxEvidenceRecord {
  const execution: SandboxEvidenceRecord["execution"] = {
    executionId,
    policyId: "sandbox-policy/v1",
    verdict: "allow",
    reasons: ["sandbox policy passed"],
    engineId: "docker-cli/v1",
    specDigest: digest("spec"),
    commandDigest: digest("command"),
    startedAt: "2026-07-29T12:00:00.000Z",
    completedAt: "2026-07-29T12:00:01.000Z",
    result: {
      exitCode: 0,
      termination: "exited",
      durationMillis: 1000,
      stdoutDigest: digest("stdout"),
      stderrDigest: digest("stderr"),
      outputDigest: digest("output"),
    },
    cleanup: "complete",
  };
  return {
    mediaType: "application/vnd.ckodex.sandbox-execution+json",
    digest: digest(JSON.stringify(execution)),
    execution,
  };
}

function initializeV24(python: string, stateDirectory: string): void {
  const database = join(stateDirectory, "workbench.sqlite3");
  const scripts = join(PLUGIN_ROOT, "scripts");
  execFileSync(
    python,
    [
      "-I",
      "-B",
      "-c",
      [
        "import sqlite3,sys",
        "sys.path.insert(0,sys.argv[1])",
        "from workbench_schema import MIGRATIONS,sql_statements",
        "connection=sqlite3.connect(sys.argv[2])",
        "connection.execute('PRAGMA foreign_keys = ON')",
        "connection.execute('CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)')",
        "for version,name,sql in MIGRATIONS:",
        "  if version > 24: break",
        "  for statement in sql_statements(sql): connection.execute(statement)",
        "  connection.execute('INSERT INTO schema_migrations VALUES (?, ?, ?)',(version,name,'2026-07-29T00:00:00Z'))",
        "connection.commit()",
      ].join("\n"),
      scripts,
      database,
    ],
    { stdio: "pipe" },
  );
}

function directSql(
  python: string,
  stateDirectory: string,
  sql: string,
): string {
  return execFileSync(
    python,
    [
      "-I",
      "-c",
      [
        "import sqlite3,sys",
        "connection=sqlite3.connect(sys.argv[1])",
        "connection.execute('PRAGMA foreign_keys = ON')",
        "row=connection.execute(sys.argv[2]).fetchone()",
        "connection.commit()",
        "print('' if row is None else row[0])",
      ].join("\n"),
      join(stateDirectory, "workbench.sqlite3"),
      sql,
    ],
    { encoding: "utf8" },
  ).trim();
}

function rejectedSql(
  python: string,
  stateDirectory: string,
  sql: string,
): string {
  return spawnSync(
    python,
    [
      "-I",
      "-c",
      "import sqlite3,sys; connection=sqlite3.connect(sys.argv[1]); connection.execute(sys.argv[2])",
      join(stateDirectory, "workbench.sqlite3"),
      sql,
    ],
    { encoding: "utf8" },
  ).stderr;
}

describe("durable workbench governance evidence", () => {
  test("migrates v24 and preserves append-only evidence across output archival", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-governance-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const stateDirectory = join(root, "state");
    const scanDir = join(root, "scan");
    const archivedScanDir = join(root, "scan.previous");
    await Promise.all([
      mkdir(repository),
      mkdir(stateDirectory),
      mkdir(scanDir, { mode: 0o700 }),
    ]);
    await writeFile(join(repository, "README.md"), "# Target\n");
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
    execFileSync("git", ["add", "README.md"], { cwd: repository });
    execFileSync(
      "git",
      [
        "-c",
        "user.name=Codex Security Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
      ],
      { cwd: repository },
    );

    const python = pythonPath();
    initializeV24(python, stateDirectory);
    const workbenchOptions = {
      python,
      pluginRoot: PLUGIN_ROOT,
      environment: { CODEX_SECURITY_STATE_DIR: stateDirectory },
    };
    const write = (args: readonly string[]) =>
      runWorkbench(workbenchOptions, args);
    const recipe = JSON.stringify({
      repository,
      target: { kind: "repository", paths: [] },
      mode: "standard",
      pluginVersion: "0.1.0",
      config: {},
    });
    const first = await write([
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      recipe,
    ]);
    const scanId = String(first["scanId"]);
    expect(
      directSql(
        python,
        stateDirectory,
        "SELECT MAX(version) FROM schema_migrations",
      ),
    ).toBe("26");

    const envelope = action("action:model-1");
    const adapter = new WorkbenchGovernanceEvidenceAdapter({
      scanId,
      action: envelope,
      append: write,
    });
    const decision = createDecisionEvidence({
      traceId: "trace-1",
      actionId: envelope.id,
      decision: {
        verdict: "allow",
        policyId: "model-policy/v1",
        reasons: ["capabilities satisfied"],
      },
      timestamp: "2026-07-29T12:00:00.000Z",
    });
    await adapter.record(decision);
    await adapter.record(decision);

    const sandboxAction = action("action:sandbox-1");
    await new WorkbenchGovernanceEvidenceAdapter({
      scanId,
      action: sandboxAction,
      append: write,
    }).emit(sandboxReceipt("execution-1"));
    expect(await readdir(scanDir)).toEqual([]);

    const stored = await write([
      "get-governance-evidence",
      "--scan-id",
      scanId,
      "--record-id",
      "model:trace-1",
    ]);
    const evidence = stored["governanceEvidence"] as Record<string, unknown>;
    expect(evidence["scanId"]).toBe(scanId);
    expect(evidence["actionId"]).toBe(envelope.id);
    expect(evidence["digest"]).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(evidence["contextCertificateDigest"]).toMatch(
      /^sha256:[a-f0-9]{64}$/,
    );
    expect(
      (
        (evidence["evidence"] as Record<string, unknown>)["action"] as Record<
          string,
          unknown
        >
      )["id"],
    ).toBe(envelope.id);

    const changed = structuredClone(decision);
    changed.trace.policyId = "different-policy/v1";
    await expect(adapter.record(changed)).rejects.toThrow("does not verify");
    changed.digest = digest(JSON.stringify(changed.trace));
    await expect(adapter.record(changed)).rejects.toThrow("immutable");
    const sensitive = structuredClone(decision);
    sensitive.trace.traceId = "secret-trace";
    sensitive.trace.reasons = ["token=abcdefghijklmnop"];
    sensitive.digest = digest(JSON.stringify(sensitive.trace));
    await expect(adapter.record(sensitive)).rejects.toThrow("secret or PII");
    const expired = structuredClone(action("action:expired-context"));
    expired.context.certificate.issuedAt = "2020-01-01T00:00:00.000Z";
    expired.context.certificate.expiresAt = "2020-01-01T00:05:00.000Z";
    await expect(
      new WorkbenchGovernanceEvidenceAdapter({
        scanId,
        action: expired,
        append: write,
      }).record(
        createDecisionEvidence({
          traceId: "expired-context",
          actionId: expired.id,
          decision: {
            verdict: "allow",
            policyId: "model-policy/v1",
            reasons: ["fixture"],
          },
          timestamp: new Date().toISOString(),
        }),
      ),
    ).rejects.toThrow("certificate has expired");
    const overdue = structuredClone(action("action:overdue-lease"));
    overdue.leases[0]!.heartbeatDue = "2020-01-01T00:00:00.000Z";
    await expect(
      new WorkbenchGovernanceEvidenceAdapter({
        scanId,
        action: overdue,
        append: write,
      }).record(
        createDecisionEvidence({
          traceId: "overdue-lease",
          actionId: overdue.id,
          decision: {
            verdict: "allow",
            policyId: "model-policy/v1",
            reasons: ["fixture"],
          },
          timestamp: new Date().toISOString(),
        }),
      ),
    ).rejects.toThrow("lease heartbeat is overdue");
    const expiredTrust = structuredClone(action("action:expired-trust"));
    expiredTrust.capability.verification.verifiedAt =
      "2019-12-31T23:59:00.000Z";
    expiredTrust.capability.verification.expiresAt = "2020-01-01T00:00:00.000Z";
    await expect(
      new WorkbenchGovernanceEvidenceAdapter({
        scanId,
        action: expiredTrust,
        append: write,
      }).record(
        createDecisionEvidence({
          traceId: "expired-trust",
          actionId: expiredTrust.id,
          decision: {
            verdict: "allow",
            policyId: "model-policy/v1",
            reasons: ["fixture"],
          },
          timestamp: new Date().toISOString(),
        }),
      ),
    ).rejects.toThrow("trust record has expired");
    const mismatched = structuredClone(action("action:mismatched-lock"));
    mismatched.leases[0]!.scope = "urn:ckodex:capability:other";
    await expect(
      new WorkbenchGovernanceEvidenceAdapter({
        scanId,
        action: mismatched,
        append: write,
      }).record(
        createDecisionEvidence({
          traceId: "mismatched-lock",
          actionId: mismatched.id,
          decision: {
            verdict: "allow",
            policyId: "model-policy/v1",
            reasons: ["fixture"],
          },
          timestamp: new Date().toISOString(),
        }),
      ),
    ).rejects.toThrow("must bind the lock bundle");
    expect(
      rejectedSql(
        python,
        stateDirectory,
        "UPDATE governance_evidence SET retention = 'ephemeral'",
      ),
    ).toContain("append-only");

    await write([
      "fail-scan",
      "--scan-id",
      scanId,
      "--message",
      "fixture complete",
    ]);
    await writeFile(join(scanDir, "partial.txt"), "preserved\n");
    await rename(scanDir, archivedScanDir);
    await mkdir(scanDir, { mode: 0o700 });
    const second = await write([
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--archived-scan-dir",
      archivedScanDir,
      "--recipe-json",
      recipe,
    ]);
    await new WorkbenchGovernanceEvidenceAdapter({
      scanId: String(second["scanId"]),
      action: envelope,
      append: write,
    }).record(decision);
    const archivedEvidence = await write([
      "get-governance-evidence",
      "--scan-id",
      scanId,
      "--record-id",
      "sandbox:execution-1",
    ]);
    expect(
      (archivedEvidence["governanceEvidence"] as Record<string, unknown>)[
        "scanId"
      ],
    ).toBe(scanId);
    expect(await readdir(scanDir)).toEqual([]);
  });

  test("fails closed on promotion evidence without bound BPL", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-governance-bpl-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const stateDirectory = join(root, "state");
    const scanDir = join(root, "scan");
    await Promise.all([mkdir(repository), mkdir(scanDir)]);
    await writeFile(join(repository, "README.md"), "# Target\n");
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
    const python = pythonPath();
    const fakeCosign = join(root, "cosign-fixture");
    await writeFile(fakeCosign, "#!/bin/sh\nexit 0\n");
    await chmod(fakeCosign, 0o700);
    const options = {
      python,
      pluginRoot: PLUGIN_ROOT,
      environment: {
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        CODEX_SECURITY_COSIGN: fakeCosign,
      },
    };
    const append = (args: readonly string[]) => runWorkbench(options, args);
    const registration = await append([
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
        pluginVersion: "0.1.0",
        config: {},
      }),
    ]);
    const manifestDigest = digest("sealed-manifest");
    const envelope = action("action:promotion-1", { promotion: true });
    const receipt = createDecisionEvidence({
      traceId: "promotion-trace",
      actionId: envelope.id,
      decision: {
        verdict: "allow",
        policyId: "promotion-policy/v1",
        reasons: ["promotion gate passed"],
      },
      timestamp: "2026-07-29T12:00:00.000Z",
    });
    await expect(
      new WorkbenchGovernanceEvidenceAdapter({
        scanId: String(registration["scanId"]),
        action: envelope,
        append,
      }).record(receipt),
    ).rejects.toThrow("requires BPL");

    const bpl = {
      schemaVersion: 1 as const,
      promotionRef: "urn:ckodex:promotion:test",
      artifactRefs: [`scan-manifest:${manifestDigest}`],
      skillChain: ["skill:security-scan"],
      contextSliceDigest: envelope.context.certificate.sliceHash,
      sourceRefs: ["source:repository"],
      actorDecisionRefs: ["decision:promotion"],
      policyPath: envelope.policy.bundleRef,
      createdAt: "2026-07-29T12:00:00.000Z",
    };
    const unsigned = {
      schemaVersion: 1 as const,
      recordId: "model:promotion-trace",
      kind: "model_decision" as const,
      action: envelope,
      receipt,
      bpl,
    };
    const payload = {
      evidenceDigest: digest(canonicalJson(unsigned)),
      bplDigest: digest(canonicalJson(bpl)),
      manifestDigest,
      lockDigest: digest("lock"),
      bundleDigest: digest("bundle"),
      policyDigests: [digest("policy")],
      cvDigests: [digest("cv-safe"), digest("cv-evid")],
      sbomDigest: digest("sbom"),
      coverageDigest: digest("coverage"),
      provenanceDigest: digest("provenance"),
    };
    await new WorkbenchGovernanceEvidenceAdapter({
      scanId: String(registration["scanId"]),
      action: envelope,
      append,
      bpl,
      signedEnvelope: {
        schemaVersion: 1,
        mediaType: "application/vnd.ckodex.signed-evidence+json",
        payload,
        payloadDigest: digest(canonicalJson(payload)),
        proofMode: "offline_key",
        publicKeyPem:
          "-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----",
        signatureBundle: "{}",
        signatureBundleDigest: digest("{}"),
        verifier: "fixture-verifier",
        signedAt: "2026-07-29T12:00:00.000Z",
      },
    }).record(receipt);
    const scanId = String(registration["scanId"]);
    const escapedScanId = scanId.replaceAll("'", "''");
    const otherManifestDigest = digest("other-sealed-manifest");
    expect(
      directSql(
        python,
        stateDirectory,
        `UPDATE scans SET status = 'complete', completed_at = '2026-07-29T12:01:00Z', seal_manifest_digest = '${otherManifestDigest}' WHERE id = '${escapedScanId}' RETURNING seal_manifest_digest`,
      ),
    ).toBe(otherManifestDigest);
    await expect(
      append([
        "verify-governance-promotion",
        "--scan-id",
        scanId,
        "--record-id",
        "model:promotion-trace",
        "--promotion-ref",
        "urn:ckodex:promotion:test",
      ]),
    ).rejects.toThrow("does not bind the recorded sealed manifest digest");
    expect(
      directSql(
        python,
        stateDirectory,
        `UPDATE scans SET seal_manifest_digest = '${manifestDigest}' WHERE id = '${escapedScanId}' RETURNING seal_manifest_digest`,
      ),
    ).toBe(manifestDigest);
    await expect(
      append([
        "verify-governance-promotion",
        "--scan-id",
        scanId,
        "--record-id",
        "model:promotion-trace",
        "--promotion-ref",
        "urn:ckodex:promotion:other",
      ]),
    ).rejects.toThrow("Promotion reference does not match");
    await expect(
      append([
        "verify-governance-promotion",
        "--scan-id",
        scanId,
        "--record-id",
        "model:promotion-trace",
        "--promotion-ref",
        "urn:ckodex:promotion:test",
      ]),
    ).resolves.toMatchObject({
      promotionEvidence: {
        scanId,
        recordId: "model:promotion-trace",
        promotionRef: "urn:ckodex:promotion:test",
        manifestDigest,
        evidenceDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
        bplDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      },
    });
  });
});
