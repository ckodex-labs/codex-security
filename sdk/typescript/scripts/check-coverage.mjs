import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const MINIMUM_LINE_COVERAGE = 80;
const result = spawnSync(
  "bun",
  [
    "test",
    "--coverage",
    "--coverage-reporter=text",
    "--timeout",
    "30000",
    "./tests-ts",
  ],
  {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  },
);

process.stdout.write(result.stdout ?? "");
process.stderr.write(result.stderr ?? "");
if (result.error !== undefined) throw result.error;

const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.replace(
  /\u001B\[[0-?]*[ -/]*[@-~]/gu,
  "",
);
const summary = /^All files\s+\|\s*[\d.]+\s*\|\s*([\d.]+)/mu.exec(output);
if (summary === null) {
  process.stderr.write(
    "Bun coverage output did not contain an all-files summary\n",
  );
  process.exitCode = 1;
} else {
  const lineCoverage = Number(summary[1]);
  if (!Number.isFinite(lineCoverage)) {
    process.stderr.write(
      "Bun coverage output contained an invalid percentage\n",
    );
    process.exitCode = 1;
  } else if (lineCoverage < MINIMUM_LINE_COVERAGE) {
    process.stderr.write(
      `line coverage ${lineCoverage.toFixed(2)}% is below ${MINIMUM_LINE_COVERAGE}%\n`,
    );
    process.exitCode = 1;
  } else {
    process.stdout.write(
      `line coverage ${lineCoverage.toFixed(2)}% meets ${MINIMUM_LINE_COVERAGE}%\n`,
    );
    const evidenceDirectory = resolve(
      process.env["CKODEX_EVIDENCE_DIR"] ?? "../../artifacts/evidence",
    );
    mkdirSync(evidenceDirectory, { recursive: true, mode: 0o700 });
    writeFileSync(
      resolve(evidenceDirectory, "coverage.json"),
      `${JSON.stringify({
        schemaVersion: 1,
        tool: "bun",
        lineCoverage,
        minimumLineCoverage: MINIMUM_LINE_COVERAGE,
        verdict: "pass",
      })}\n`,
      { mode: 0o600 },
    );
  }
}
if (result.status !== 0) process.exitCode = result.status ?? 1;
