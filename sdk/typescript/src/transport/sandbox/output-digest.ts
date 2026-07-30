import { createHash } from "node:crypto";
import { lstat, readFile, readdir, readlink } from "node:fs/promises";
import { join, relative, sep } from "node:path";

function hash(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export async function digestOutputTree(
  root: string,
): Promise<`sha256:${string}`> {
  const entries: Array<readonly (number | string)[]> = [];

  async function visit(directory: string): Promise<void> {
    const names = await readdir(directory);
    names.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
    for (const name of names) {
      const path = join(directory, name);
      const metadata = await lstat(path);
      const logicalPath = relative(root, path).split(sep).join("/");
      const mode = (metadata.mode & 0o7777).toString(8).padStart(4, "0");
      if (metadata.isDirectory()) {
        entries.push(["directory", logicalPath, mode]);
        await visit(path);
      } else if (metadata.isFile()) {
        entries.push([
          "file",
          logicalPath,
          mode,
          metadata.size,
          hash(await readFile(path)),
        ]);
      } else if (metadata.isSymbolicLink()) {
        entries.push(["symlink", logicalPath, mode, await readlink(path)]);
      } else {
        throw new Error(
          `sandbox output contains unsupported special file: ${logicalPath}`,
        );
      }
    }
  }

  await visit(root);
  return `sha256:${hash(JSON.stringify(entries))}`;
}
