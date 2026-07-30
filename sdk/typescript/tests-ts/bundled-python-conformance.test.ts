import { expect, test } from "bun:test";
import { resolve } from "node:path";

const packageRoot = resolve(".");
const scripts = resolve("_bundled_plugin", "scripts");
function supportedPython(): string {
  const candidate =
    Bun.which("python3.14") ??
    Bun.which("python3.13") ??
    Bun.which("python3.12") ??
    Bun.which("python3.11") ??
    Bun.which("python3.10");
  if (candidate === null) {
    throw new Error("Python 3.10 or later is required for bundled conformance");
  }
  return candidate;
}

const python = supportedPython();

async function runPython(source: string): Promise<{
  exitCode: number;
  stderr: string;
  stdout: string;
}> {
  const process = Bun.spawn([python, "-B", "-c", source], {
    cwd: packageRoot,
    env: { ...Bun.env, PYTHONPATH: scripts },
    stderr: "pipe",
    stdout: "pipe",
  });
  const [exitCode, stderr, stdout] = await Promise.all([
    process.exited,
    new Response(process.stderr).text(),
    new Response(process.stdout).text(),
  ]);
  return { exitCode, stderr, stdout };
}

test("report projection retains deterministic no-findings output", async () => {
  const result = await runPython(`
import report_projection
manifest = {"scan": {"target": {"displayName": "Demo", "kind": "repository", "targetId": "demo"}, "scope": {"includePaths": ["."], "excludePaths": []}}}
findings = {"findings": []}
coverage = {"mode": "repository", "inventoryStrategy": "tracked", "completeness": "complete", "surfaces": []}
print(report_projection.build_report_markdown(manifest, findings, coverage), end="")
`);
  expect(result).toMatchObject({ exitCode: 0, stderr: "" });
  expect(result.stdout).toContain("# Security Review: Demo");
  expect(result.stdout).toContain("### No findings");
  expect(result.stdout.endsWith("\n")).toBe(true);
});

test("report projection imports under Python isolated mode", async () => {
  const process = Bun.spawn(
    [python, "-I", "-B", resolve(scripts, "report_projection.py")],
    {
      cwd: packageRoot,
      stderr: "pipe",
      stdout: "pipe",
    },
  );
  const [exitCode, stderr, stdout] = await Promise.all([
    process.exited,
    new Response(process.stderr).text(),
    new Response(process.stdout).text(),
  ]);
  expect({ exitCode, stderr, stdout }).toEqual({
    exitCode: 0,
    stderr: "",
    stdout: "",
  });
});

test("completed-scan projection retains its byte-level contract", async () => {
  const result = await runPython(`
import hashlib, json, pathlib, report_projection
example = pathlib.Path("_bundled_plugin/examples/completed-scan")
manifest = json.loads((example / "scan-manifest.json").read_text())
findings = json.loads((example / "findings.json").read_text())
coverage = json.loads((example / "coverage.json").read_text())
report = report_projection.generate_report_markdown(manifest, findings, coverage)
print(len(report), hashlib.sha256(report).hexdigest())
`);
  expect(result).toEqual({
    exitCode: 0,
    stderr: "",
    stdout:
      "2743 b89151a8352c6f45c6e466243807f972a2076d0e59bb301def87a3c46308dbf5\n",
  });
});

test("migration facade retains signed governance migration 26", async () => {
  const result = await runPython(`
from workbench_schema import MIGRATIONS
version, name, sql = MIGRATIONS[-1]
assert version == 26
assert name == "append-only signed governance envelopes"
assert "signed_governance_envelopes_no_update" in sql
assert "signed_governance_envelopes_no_delete" in sql
print(len(MIGRATIONS))
`);
  expect(result.exitCode).toBe(0);
  expect(result.stderr).toBe("");
  expect(Number(result.stdout.trim())).toBeGreaterThanOrEqual(26);
});
