import { readdir, readFile } from "node:fs/promises";
import {
  dirname,
  extname,
  join,
  normalize,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = join(packageRoot, "src");
const spaces = new Set(["kernel", "validation", "proof", "transport"]);
const allowedSpaces = {
  kernel: new Set(["kernel"]),
  validation: new Set(["kernel", "validation"]),
  proof: new Set(["kernel", "proof"]),
  transport: spaces,
};
const allowedExternal = {
  kernel: new Set(),
  validation: new Set(),
  proof: new Set(["node:crypto"]),
  transport: null,
};

async function collectTypeScript(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectTypeScript(path)));
    } else if (entry.isFile() && extname(entry.name) === ".ts") {
      files.push(path);
    }
  }
  return files;
}

function importsOf(source) {
  const imports = [];
  const pattern =
    /(?:import|export)\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?["']([^"']+)["']/g;
  for (const match of source.matchAll(pattern)) {
    if (match[1] !== undefined) imports.push(match[1]);
  }
  return imports;
}

function importedSpace(file, specifier) {
  const resolved = normalize(resolve(dirname(file), specifier));
  const path = relative(sourceRoot, resolved);
  if (path.startsWith(`..${sep}`) || path === "..") return undefined;
  return path.split(sep)[0];
}

const violations = [];
for (const space of spaces) {
  const directory = join(sourceRoot, space);
  for (const file of await collectTypeScript(directory)) {
    const source = await readFile(file, "utf8");
    for (const specifier of importsOf(source)) {
      if (specifier.startsWith(".")) {
        const targetSpace = importedSpace(file, specifier);
        if (targetSpace === undefined || !spaces.has(targetSpace)) {
          violations.push(
            `${relative(packageRoot, file)} imports ${specifier} outside the four spaces`,
          );
        } else if (!allowedSpaces[space].has(targetSpace)) {
          violations.push(
            `${relative(packageRoot, file)} imports forbidden ${targetSpace} space`,
          );
        }
        continue;
      }
      const allowlist = allowedExternal[space];
      if (allowlist !== null && !allowlist.has(specifier)) {
        violations.push(
          `${relative(packageRoot, file)} imports forbidden external module ${specifier}`,
        );
      }
    }
  }
}

if (violations.length > 0) {
  process.stderr.write(`${violations.join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("four-space dependency boundaries: pass\n");
}
