import { describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const checker = resolve("scripts/check-quality.mjs");

async function runChecker(root: string): Promise<{
  exitCode: number;
  stderr: string;
  stdout: string;
}> {
  const process = Bun.spawn(["node", checker, root], {
    cwd: resolve("."),
    env: { ...Bun.env, PYTHON: undefined },
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

describe("hard quality gate", () => {
  test("accepts bounded TypeScript and Python", async () => {
    const root = await mkdtemp(join(tmpdir(), "ckodex-quality-pass-"));
    await writeFile(
      join(root, "bounded.ts"),
      [
        'const commentLike = "// TODO is string data";',
        "export function bounded(value: boolean): number {",
        "  return value ? commentLike.length : 0;",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(root, "bounded.py"),
      "def bounded(value: bool) -> int:\n    return 1 if value else 0\n",
    );
    const result = await runChecker(root);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("quality limits: pass");
  });

  test("fails closed on malformed syntax and definite assignment", async () => {
    const root = await mkdtemp(join(tmpdir(), "ckodex-quality-parse-"));
    await writeFile(
      join(root, "malformed.ts"),
      "class Invalid {\n  value!: string;\n  broken(: void {}\n}\n",
    );
    const result = await runChecker(root);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("[parse-error]");
    expect(result.stderr).toContain("definite-assignment assertion");
  });

  test("fails closed on malformed Python and every supported stub marker", async () => {
    const root = await mkdtemp(join(tmpdir(), "ckodex-quality-markers-"));
    await writeFile(
      join(root, "markers.ts"),
      [
        "// TODO: forbidden",
        "// FIXME: forbidden",
        "// XXX: forbidden",
        "// HACK: forbidden",
        "export const value = 1;",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(root, "malformed.py"),
      [
        "# TODO: forbidden",
        "# FIXME: forbidden",
        "# XXX: forbidden",
        "# HACK: forbidden",
        "def broken(:",
        "",
      ].join("\n"),
    );
    const result = await runChecker(root);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("malformed.py:5 [parse-error]");
    for (const marker of ["TODO", "FIXME", "XXX", "HACK"]) {
      expect(result.stderr).toContain(`stub marker ${marker} is forbidden`);
    }
  });

  test("reports every TypeScript limit without executing the fixture", async () => {
    const root = await mkdtemp(join(tmpdir(), "ckodex-quality-ts-"));
    const nested = Array.from(
      { length: 16 },
      (_, index) => `${"  ".repeat(index + 1)}if (value) {`,
    );
    const closes = Array.from(
      { length: 16 },
      (_, index) => `${"  ".repeat(16 - index)}}`,
    );
    const padding = Array.from({ length: 470 }, () => "");
    await writeFile(
      join(root, "violations.ts"),
      [
        "export function oversized(value: string | undefined): string {",
        ...nested,
        ...closes,
        ...Array.from({ length: 20 }, () => "  value = value;"),
        "  // TODO: forbidden marker",
        '  if (value === "") throw new Error("not implemented");',
        "  return value!;",
        "}",
        ...padding,
      ].join("\n"),
    );
    const result = await runChecker(root);
    expect(result.exitCode).toBe(1);
    for (const rule of [
      "max-file-lines",
      "max-function-lines",
      "cognitive-complexity",
      "unwrap-analogue",
      "stub",
    ]) {
      expect(result.stderr).toContain(`[${rule}]`);
    }
  });

  test("reports Python size, complexity, and executable stubs", async () => {
    const root = await mkdtemp(join(tmpdir(), "ckodex-quality-py-"));
    const packageRoot = join(root, "package");
    await mkdir(packageRoot);
    const branches = Array.from(
      { length: 16 },
      (_, index) => `${"    ".repeat(index + 1)}if value:`,
    );
    const body = `${"    ".repeat(17)}pass`;
    const padding = Array.from({ length: 500 }, () => "    value = value");
    await writeFile(
      join(packageRoot, "violations.py"),
      [
        "def oversized(value: bool) -> None:",
        ...branches,
        body,
        "    raise NotImplementedError()",
        ...padding,
      ].join("\n"),
    );
    const result = await runChecker(packageRoot);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("[max-file-lines]");
    expect(result.stderr).toContain("[max-function-lines]");
    expect(result.stderr).toContain("[cognitive-complexity]");
    expect(result.stderr).toContain("NotImplementedError stub is forbidden");
    expect(result.stderr).toContain("stub statement 'pass' is forbidden");
  });

  test("does not treat Python marker substrings as stub comments", async () => {
    const root = await mkdtemp(join(tmpdir(), "ckodex-quality-comment-"));
    await writeFile(
      join(root, "bounded.py"),
      "# shellhack is not a marker token\ndef bounded() -> int:\n    return 1\n",
    );
    const result = await runChecker(root);
    expect(result.exitCode).toBe(0);
  });
});
