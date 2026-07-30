import type { SpawnOptionsWithoutStdio } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, posix, relative, sep } from "node:path";
import type { ModelProcessSpec } from "../../kernel/ports.js";
import type {
  DockerModelMount,
  DockerModelProcessRunnerOptions,
} from "./docker-process-runner.js";

const IMAGE_PATTERN =
  /^[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[0-9]+)?@sha256:[a-f0-9]{64}$/u;

export function validateOptions(
  options: DockerModelProcessRunnerOptions,
): void {
  if (!IMAGE_PATTERN.test(options.imageRef)) {
    throw new Error("model image must be digest-pinned");
  }
  if (!isAbsolute(options.executable)) {
    throw new Error("model executable must be absolute");
  }
  const limits = [
    options.runAsUser,
    options.cpuMillis,
    options.memoryBytes,
    options.processCount,
  ];
  if (limits.some((value) => !Number.isSafeInteger(value) || value <= 0)) {
    throw new Error("model sandbox limits must be positive integers");
  }
  if (
    new Set(options.allowedEnvironmentNames).size !==
    options.allowedEnvironmentNames.length
  ) {
    throw new Error("model environment allowlist contains duplicates");
  }
  for (const name of options.allowedEnvironmentNames)
    requireEnvironmentName(name);
}

export function validateSpec(
  spec: ModelProcessSpec,
  options: DockerModelProcessRunnerOptions,
): void {
  if (spec.executable !== options.executable) {
    throw new Error("model executable is not the fixed sandbox executable");
  }
  for (const [name, value] of Object.entries(spec.environment)) {
    requireEnvironmentName(name);
    if (!options.allowedEnvironmentNames.includes(name)) {
      throw new Error(`model environment ${name} is not allowed`);
    }
    if (/[\0\r\n]/u.test(value)) {
      throw new Error(`model environment ${name} is invalid`);
    }
  }
}

export async function canonicalMounts(
  mounts: readonly DockerModelMount[],
): Promise<DockerModelMount[]> {
  const result: DockerModelMount[] = [];
  for (const mount of mounts) {
    if (!validMount(mount)) {
      throw new Error("model mount must use canonical absolute paths");
    }
    const source = await realpath(mount.source);
    if (!(await lstat(source)).isDirectory()) {
      throw new Error("model mount source must be a directory");
    }
    result.push({ source, target: mount.target });
  }
  requireSeparated(
    result.map((mount) => mount.source),
    "source",
  );
  requireSeparated(
    result.map((mount) => mount.target),
    "target",
  );
  return result;
}

function validMount(mount: DockerModelMount): boolean {
  if (!isAbsolute(mount.source) || !isAbsolute(mount.target)) return false;
  if (mount.source.includes(",") || mount.target.includes(",")) return false;
  const parts = mount.target.split("/").slice(1);
  return (
    parts.length > 0 &&
    parts.every((part) => part !== "" && part !== "." && part !== "..")
  );
}

function requireSeparated(paths: readonly string[], label: string): void {
  for (const [index, path] of paths.entries()) {
    for (const other of paths.slice(index + 1)) {
      const overlaps =
        label === "target"
          ? posixOverlap(path, other)
          : platformOverlap(path, other);
      if (overlaps) {
        throw new Error(`model mount ${label} paths overlap`);
      }
    }
  }
}

function platformOverlap(left: string, right: string): boolean {
  const path = relative(left, right);
  if (path === "" || (!path.startsWith(`..${sep}`) && path !== "..")) {
    return true;
  }
  const reverse = relative(right, left);
  return (
    reverse === "" || (!reverse.startsWith(`..${sep}`) && reverse !== "..")
  );
}

function posixOverlap(left: string, right: string): boolean {
  return (
    left === right ||
    left.startsWith(`${right}${posix.sep}`) ||
    right.startsWith(`${left}${posix.sep}`)
  );
}

export function dockerArguments(
  options: DockerModelProcessRunnerOptions,
  spec: ModelProcessSpec,
  name: string,
  environmentPath: string,
  mounts: readonly DockerModelMount[],
): string[] {
  const args = [
    "run",
    "--pull=never",
    "--name",
    name,
    "--label",
    "io.ckodex.model-process=true",
    "--interactive",
    "--user",
    String(options.runAsUser),
    "--cap-drop=ALL",
    "--security-opt",
    "no-new-privileges=true",
    "--read-only",
    "--network",
    "none",
    "--pids-limit",
    String(options.processCount),
    "--memory",
    String(options.memoryBytes),
    "--cpu-period",
    "100000",
    "--cpu-quota",
    String(options.cpuMillis * 100),
    "--tmpfs",
    `/tmp:rw,nosuid,nodev,noexec,size=${Math.min(options.memoryBytes, 64 * 1024 * 1024)}`,
    "--env-file",
    environmentPath,
    "--entrypoint",
    options.executable,
  ];
  for (const mount of mounts) {
    args.push(
      "--mount",
      `type=bind,src=${mount.source},dst=${mount.target},readonly`,
    );
  }
  return [...args, options.imageRef, ...spec.arguments];
}

export function processOptions(
  options: DockerModelProcessRunnerOptions,
): SpawnOptionsWithoutStdio & { stdio: ["pipe", "pipe", "pipe"] } {
  return {
    env: {
      PATH: options.path ?? process.env["PATH"] ?? "",
      ...(options.dockerHost === undefined
        ? {}
        : { DOCKER_HOST: options.dockerHost }),
    },
    detached: process.platform !== "win32",
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  };
}

export function environmentFile(
  environment: Readonly<Record<string, string>>,
): string {
  const entries = Object.entries(environment).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  return `${entries.map(([name, value]) => `${name}=${value}`).join("\n")}\n`;
}

export function containerName(executionId: string): string {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,47}$/u.test(executionId)) {
    throw new Error("model execution id is not a canonical container identity");
  }
  return `ckodex-model-${executionId.toLowerCase()}`;
}

function requireEnvironmentName(name: string): void {
  if (!/^[A-Z_][A-Z0-9_]{0,127}$/u.test(name)) {
    throw new Error("model environment name is invalid");
  }
}
