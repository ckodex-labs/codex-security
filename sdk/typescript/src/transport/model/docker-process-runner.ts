import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Transform } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import type {
  ModelProcessSession,
  ModelProcessSpec,
  SandboxedModelProcessRunnerPort,
} from "../../kernel/ports.js";
import {
  canonicalMounts,
  containerName,
  dockerArguments,
  environmentFile,
  processOptions,
  validateOptions,
  validateSpec,
} from "./docker-process-policy.js";

export interface DockerModelMount {
  source: string;
  target: string;
}

export interface DockerModelProcessEvidence {
  mediaType: "application/vnd.ckodex.model-process+json";
  digest: `sha256:${string}`;
  execution: {
    executionId: string;
    imageRef: string;
    executable: string;
    environmentNames: readonly string[];
    startedAt: string;
    completedAt: string;
    termination:
      | "exited"
      | "canceled"
      | "timed_out"
      | "output_limited"
      | "failed";
    exitCode: number | null;
    signal: string | null;
    stdoutBytes: number;
    stderrBytes: number;
    stdoutDigest: `sha256:${string}`;
    stderrDigest: `sha256:${string}`;
    cleanup: "complete" | "failed" | "not_started";
    error?: string;
  };
}

export interface DockerModelProcessRunnerOptions {
  imageRef: string;
  executable: string;
  runAsUser: number;
  allowedEnvironmentNames: readonly string[];
  mounts?: readonly DockerModelMount[];
  cpuMillis: number;
  memoryBytes: number;
  processCount: number;
  dockerExecutable?: string;
  dockerHost?: string;
  path?: string;
  evidence: { emit(record: DockerModelProcessEvidence): Promise<void> };
  now?: () => Date;
  executionId?: () => string;
}

interface StreamCounter {
  bytes: number;
  hash: ReturnType<typeof createHash>;
}

interface ExecutionState {
  termination: DockerModelProcessEvidence["execution"]["termination"];
  cleanup: DockerModelProcessEvidence["execution"]["cleanup"];
  error?: string;
}

interface SessionControl {
  state: ExecutionState;
  terminate(reason: ExecutionState["termination"]): Promise<void>;
  completion: Promise<{ exitCode: number | null; signal: string | null }>;
}

export class DockerModelProcessRunner
  implements SandboxedModelProcessRunnerPort
{
  readonly #options: DockerModelProcessRunnerOptions;
  readonly #activeNames = new Set<string>();

  public constructor(options: DockerModelProcessRunnerOptions) {
    validateOptions(options);
    this.#options = options;
  }

  public async start(
    spec: ModelProcessSpec,
    signal: AbortSignal,
  ): Promise<ModelProcessSession> {
    const executionId = (this.#options.executionId ?? randomUUID)();
    const startedAt = (this.#options.now ?? (() => new Date()))();
    let environmentDirectory: string | undefined;
    let name: string | undefined;
    let reserved = false;
    try {
      validateSpec(spec, this.#options);
      name = containerName(executionId);
      this.#reserve(name);
      reserved = true;
      environmentDirectory = await mkdtemp(join(tmpdir(), "ckodex-model-env-"));
      const environmentPath = join(environmentDirectory, "environment");
      await writeFile(environmentPath, environmentFile(spec.environment), {
        mode: 0o600,
        flag: "wx",
      });
      const mounts = await canonicalMounts(this.#options.mounts ?? []);
      const child = spawn(
        this.#options.dockerExecutable ?? "docker",
        dockerArguments(this.#options, spec, name, environmentPath, mounts),
        processOptions(this.#options),
      );
      return await this.#session(
        child,
        spec,
        signal,
        executionId,
        name,
        environmentDirectory,
        startedAt,
      );
    } catch (error) {
      if (environmentDirectory !== undefined) {
        await rm(environmentDirectory, { recursive: true, force: true });
      }
      if (reserved && name !== undefined) this.#activeNames.delete(name);
      await this.#emitFailure(executionId, spec, startedAt);
      throw error;
    }
  }

  #reserve(name: string): void {
    if (this.#activeNames.has(name)) {
      throw new Error("model execution container identity is already active");
    }
    this.#activeNames.add(name);
  }

  async #session(
    child: ChildProcessWithoutNullStreams,
    spec: ModelProcessSpec,
    signal: AbortSignal,
    executionId: string,
    name: string,
    environmentDirectory: string,
    startedAt: Date,
  ): Promise<ModelProcessSession> {
    const childCompletion = completionOf(child);
    void childCompletion.catch(() => undefined);
    await spawned(child);
    const stdout = counter(child.stdout, spec.maxStdoutBytes);
    const stderr = counter(child.stderr, spec.maxStderrBytes);
    const control = this.#control(child, childCompletion, spec, signal, name);
    stdout.stream.once("error", () => void control.terminate("output_limited"));
    stderr.stream.once("error", () => void control.terminate("output_limited"));
    const completion = control.completion.then(async (result) => {
      await rm(environmentDirectory, { recursive: true, force: true });
      this.#activeNames.delete(name);
      await this.#emit(
        executionId,
        spec,
        startedAt,
        result,
        control.state,
        stdout,
        stderr,
      );
      return result;
    });
    return {
      stdout: stdout.stream,
      stderr: stderr.stream,
      write: async (chunk) => await writeChunk(child, chunk),
      closeInput: async () => {
        child.stdin.end();
      },
      cancel: async () => {
        await control.terminate("canceled");
        await completion;
      },
      completion,
    };
  }

  #control(
    child: ChildProcessWithoutNullStreams,
    childCompletion: Promise<{
      exitCode: number | null;
      signal: string | null;
    }>,
    spec: ModelProcessSpec,
    signal: AbortSignal,
    name: string,
  ): SessionControl {
    const state: ExecutionState = {
      termination: "exited",
      cleanup: "not_started",
    };
    let terminating: Promise<void> | undefined;
    const terminate = (
      reason: ExecutionState["termination"],
    ): Promise<void> => {
      if (terminating !== undefined) return terminating;
      state.termination = reason;
      terminating = settleCleanup(
        state,
        terminateContainer(child, childCompletion, this.#options, name),
      );
      return terminating;
    };
    const timeout = setTimeout(
      () => void terminate("timed_out"),
      spec.wallClockMillis,
    );
    const abort = (): void => void terminate("canceled");
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    const completion = childCompletion.then(async (result) => {
      clearTimeout(timeout);
      signal.removeEventListener("abort", abort);
      terminating ??= settleCleanup(
        state,
        removeContainer(this.#options, name),
      );
      await terminating;
      return result;
    });
    return { state, terminate, completion };
  }

  async #emit(
    executionId: string,
    spec: ModelProcessSpec,
    startedAt: Date,
    result: { exitCode: number | null; signal: string | null },
    state: ExecutionState,
    stdout: ReturnType<typeof counter>,
    stderr: ReturnType<typeof counter>,
  ): Promise<void> {
    const execution: DockerModelProcessEvidence["execution"] = {
      executionId,
      imageRef: this.#options.imageRef,
      executable: this.#options.executable,
      environmentNames: Object.keys(spec.environment).sort(),
      startedAt: startedAt.toISOString(),
      completedAt: (this.#options.now ?? (() => new Date()))().toISOString(),
      termination: state.termination,
      exitCode: result.exitCode,
      signal: result.signal,
      stdoutBytes: stdout.state.bytes,
      stderrBytes: stderr.state.bytes,
      stdoutDigest: digest(stdout.state.hash.digest()),
      stderrDigest: digest(stderr.state.hash.digest()),
      cleanup: state.cleanup,
      ...(state.error === undefined ? {} : { error: state.error }),
    };
    await this.#options.evidence.emit({
      mediaType: "application/vnd.ckodex.model-process+json",
      digest: digest(JSON.stringify(execution)),
      execution,
    });
  }

  async #emitFailure(
    executionId: string,
    spec: ModelProcessSpec,
    startedAt: Date,
  ): Promise<void> {
    const empty = digest("");
    const execution: DockerModelProcessEvidence["execution"] = {
      executionId,
      imageRef: this.#options.imageRef,
      executable: this.#options.executable,
      environmentNames: Object.keys(spec.environment).sort(),
      startedAt: startedAt.toISOString(),
      completedAt: (this.#options.now ?? (() => new Date()))().toISOString(),
      termination: "failed",
      exitCode: null,
      signal: null,
      stdoutBytes: 0,
      stderrBytes: 0,
      stdoutDigest: empty,
      stderrDigest: empty,
      cleanup: "not_started",
      error: "model process failed before start",
    };
    await this.#options.evidence.emit({
      mediaType: "application/vnd.ckodex.model-process+json",
      digest: digest(JSON.stringify(execution)),
      execution,
    });
  }
}

async function settleCleanup(
  state: ExecutionState,
  operation: Promise<void>,
): Promise<void> {
  try {
    await operation;
    state.cleanup = "complete";
  } catch (error) {
    state.cleanup = "failed";
    state.error = errorMessage(error);
  }
}

function counter(source: NodeJS.ReadableStream, limit: number) {
  const state: StreamCounter = { bytes: 0, hash: createHash("sha256") };
  const stream = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      state.bytes += chunk.byteLength;
      state.hash.update(chunk);
      callback(
        state.bytes > limit
          ? new Error("model process output exceeded its byte limit")
          : undefined,
        chunk,
      );
    },
  });
  source.pipe(stream);
  return { state, stream };
}

function spawned(child: ChildProcessWithoutNullStreams): Promise<void> {
  return new Promise((resolve, reject) => {
    child.once("spawn", resolve);
    child.once("error", reject);
  });
}

function completionOf(
  child: ChildProcessWithoutNullStreams,
): Promise<{ exitCode: number | null; signal: string | null }> {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (exitCode, signal) => resolve({ exitCode, signal }));
  });
}

async function writeChunk(
  child: ChildProcessWithoutNullStreams,
  chunk: Uint8Array,
): Promise<void> {
  if (child.stdin.write(chunk)) return;
  await new Promise<void>((resolve) => child.stdin.once("drain", resolve));
}

async function terminateContainer(
  child: ChildProcessWithoutNullStreams,
  completion: Promise<unknown>,
  options: DockerModelProcessRunnerOptions,
  name: string,
): Promise<void> {
  killGroup(child);
  await completion.catch(() => undefined);
  await removeContainer(options, name);
}

async function removeContainer(
  options: DockerModelProcessRunnerOptions,
  name: string,
): Promise<void> {
  let consecutiveAbsent = 0;
  for (let attempt = 0; attempt < 6; attempt += 1) {
    await invokeDocker(options, ["rm", "--force", name]);
    await delay(50 * 2 ** Math.min(attempt, 4));
    const present = (await invokeDocker(options, ["inspect", name])) === 0;
    consecutiveAbsent = present ? 0 : consecutiveAbsent + 1;
    if (consecutiveAbsent >= 2) return;
  }
  throw new Error("model container cleanup failed");
}

async function invokeDocker(
  options: DockerModelProcessRunnerOptions,
  args: readonly string[],
): Promise<number | null> {
  const child = spawn(options.dockerExecutable ?? "docker", [...args], {
    ...processOptions(options),
    stdio: ["ignore", "ignore", "ignore"],
  });
  const result = await completionOf(
    child as unknown as ChildProcessWithoutNullStreams,
  );
  return result.exitCode;
}

function killGroup(child: ChildProcessWithoutNullStreams): void {
  if (child.pid === undefined || child.killed) return;
  try {
    if (process.platform === "win32") child.kill("SIGKILL");
    else process.kill(-child.pid, "SIGKILL");
  } catch {
    child.kill("SIGKILL");
  }
}

function digest(value: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
