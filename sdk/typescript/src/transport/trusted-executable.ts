import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { delimiter, isAbsolute, join, relative, resolve, sep } from "node:path";

export interface TrustedExecutable {
  executable: string;
  environment: Record<string, string | undefined>;
}

interface ExecutableCandidate {
  entry: string | null;
  path: string;
  runnable: boolean;
}

export async function resolveTrustedExecutable(
  candidate: string,
  environment: Readonly<Record<string, string | undefined>>,
  protectedRoot: string,
): Promise<TrustedExecutable | null> {
  const root = await realpath(protectedRoot).catch(() =>
    resolve(protectedRoot),
  );
  const entries = await trustedPathEntries(environment, root);
  const candidates = executableCandidates(candidate, entries);
  const resolution = await inspectCandidates(candidates, root);
  if (resolution.executable === null) return null;
  return {
    executable: resolution.executable,
    environment: sanitizedEnvironment(
      environment,
      entries,
      resolution.unsafeEntries,
    ),
  };
}

async function trustedPathEntries(
  environment: Readonly<Record<string, string | undefined>>,
  root: string,
): Promise<string[]> {
  const path = Object.entries(environment).find(
    ([name]) => name.toUpperCase() === "PATH",
  )?.[1];
  const entries: string[] = [];
  for (const entry of path?.split(delimiter) ?? []) {
    if (entry.length === 0 || !isAbsolute(entry)) continue;
    const canonical = await realpath(entry).catch(() => null);
    if (canonical === null || isWithin(root, canonical)) continue;
    if (!entries.includes(canonical)) entries.push(canonical);
  }
  return entries;
}

function executableCandidates(
  candidate: string,
  entries: readonly string[],
): ExecutableCandidate[] {
  if (candidate.includes("/") || candidate.includes("\\")) {
    return [{ entry: null, path: resolve(candidate), runnable: true }];
  }
  return entries.flatMap((entry) =>
    executableExtensions(candidate).map((extension) => ({
      entry,
      path: join(entry, `${candidate}${extension.suffix}`),
      runnable: extension.runnable,
    })),
  );
}

function executableExtensions(
  candidate: string,
): ReadonlyArray<{ suffix: string; runnable: boolean }> {
  if (process.platform !== "win32") return [{ suffix: "", runnable: true }];
  if (/\.(?:exe|com)$/iu.test(candidate)) {
    return [{ suffix: "", runnable: true }];
  }
  return [
    { suffix: ".exe", runnable: true },
    { suffix: ".com", runnable: true },
    { suffix: ".bat", runnable: false },
    { suffix: ".cmd", runnable: false },
    { suffix: "", runnable: false },
  ];
}

async function inspectCandidates(
  candidates: readonly ExecutableCandidate[],
  root: string,
): Promise<{ executable: string | null; unsafeEntries: ReadonlySet<string> }> {
  const unsafeEntries = new Set<string>();
  let executable: string | null = null;
  for (const current of candidates) {
    const inspected = await inspectCandidate(current, root);
    if (inspected.unsafeEntry !== null) {
      unsafeEntries.add(inspected.unsafeEntry);
    }
    executable ??= inspected.executable;
  }
  return { executable, unsafeEntries };
}

async function inspectCandidate(
  candidate: ExecutableCandidate,
  root: string,
): Promise<{ executable: string | null; unsafeEntry: string | null }> {
  const canonical = await realpath(candidate.path).catch(() => null);
  if (canonical === null) return { executable: null, unsafeEntry: null };
  if (isWithin(root, canonical)) {
    return { executable: null, unsafeEntry: candidate.entry };
  }
  if (!candidate.runnable) return { executable: null, unsafeEntry: null };
  try {
    await access(
      canonical,
      process.platform === "win32" ? constants.F_OK : constants.X_OK,
    );
    const executable = (await stat(canonical)).isFile() ? canonical : null;
    return { executable, unsafeEntry: null };
  } catch {
    return { executable: null, unsafeEntry: null };
  }
}

function sanitizedEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
  entries: readonly string[],
  unsafeEntries: ReadonlySet<string>,
): Record<string, string | undefined> {
  const sanitizedEnvironment = { ...environment };
  for (const name of Object.keys(sanitizedEnvironment)) {
    if (name.toUpperCase() === "PATH") delete sanitizedEnvironment[name];
  }
  sanitizedEnvironment["PATH"] = entries
    .filter((entry) => !unsafeEntries.has(entry))
    .join(delimiter);
  return sanitizedEnvironment;
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}
