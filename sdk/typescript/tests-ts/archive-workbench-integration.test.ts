import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { runWorkbench } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function pythonPath(): string | null {
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
  return null;
}

describe("archived CLI scan registration", () => {
  test("rebinds the prior scan before reusing its output directory", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-archive-ledger-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const stateDirectory = join(root, "state");
    const scanDir = join(root, "scan");
    const archivedScanDir = join(root, "scan.previous");
    await mkdir(repository);
    await mkdir(scanDir, { mode: 0o700 });
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
    expect(python).not.toBeNull();
    const options = {
      python: python!,
      pluginRoot: PLUGIN_ROOT,
      environment: { CODEX_SECURITY_STATE_DIR: stateDirectory },
      failureMessage: "Could not save the Codex Security scan",
    };
    const recipe = JSON.stringify({
      repository,
      target: { kind: "repository", paths: [] },
      mode: "standard",
      pluginVersion: "0.1.0",
      config: {},
    });
    const first = await runWorkbench(options, [
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      recipe,
    ]);
    expect(first["scanId"]).toBeString();
    await runWorkbench(options, [
      "fail-scan",
      "--scan-id",
      String(first["scanId"]),
      "--message",
      "fixture complete",
    ]);
    await writeFile(join(scanDir, "partial.txt"), "preserved\n");
    await rename(scanDir, archivedScanDir);
    await mkdir(scanDir, { mode: 0o700 });

    const second = await runWorkbench(options, [
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
    const prior = await runWorkbench(options, [
      "get-scan",
      "--scan-id",
      String(first["scanId"]),
    ]);

    expect(second["scanDir"]).toBe(scanDir);
    expect((prior["scan"] as Record<string, unknown>)["scanDir"]).toBe(
      archivedScanDir,
    );
  });
});
