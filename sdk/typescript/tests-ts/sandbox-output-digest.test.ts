import { describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { digestOutputTree } from "../src/transport/sandbox/output-digest.js";

describe("sandbox output tree digest", () => {
  test("is stable across creation order and captures content, mode, and links", async () => {
    const first = await mkdtemp(join(tmpdir(), "ckodex-output-first-"));
    const second = await mkdtemp(join(tmpdir(), "ckodex-output-second-"));
    await mkdir(join(first, "nested"));
    await writeFile(join(first, "z.txt"), "z");
    await writeFile(join(first, "nested", "a.txt"), "a");
    await symlink("nested/a.txt", join(first, "link"));
    await writeFile(join(second, "z.txt"), "z");
    await mkdir(join(second, "nested"));
    await symlink("nested/a.txt", join(second, "link"));
    await writeFile(join(second, "nested", "a.txt"), "a");

    const expected = await digestOutputTree(first);
    expect(await digestOutputTree(second)).toBe(expected);

    await writeFile(join(second, "nested", "a.txt"), "changed");
    expect(await digestOutputTree(second)).not.toBe(expected);
    await writeFile(join(second, "nested", "a.txt"), "a");
    await chmod(join(second, "nested", "a.txt"), 0o700);
    expect(await digestOutputTree(second)).not.toBe(expected);
  });

  test("does not follow symlinks outside the output tree", async () => {
    const root = await mkdtemp(join(tmpdir(), "ckodex-output-link-"));
    const outside = join(root, "..", "ckodex-output-secret");
    await writeFile(outside, "first");
    await symlink(outside, join(root, "external"));
    const before = await digestOutputTree(root);
    await writeFile(outside, "second");
    expect(await digestOutputTree(root)).toBe(before);
  });
});
