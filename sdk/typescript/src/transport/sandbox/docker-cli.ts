import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import type {
  EngineRunRequest,
  EngineRunResult,
  SandboxContainerEngine,
} from "./types.js";
import { SandboxExecutionError, SandboxOutputLimitError } from "./types.js";

export interface DockerCliOptions {
  executable?: string;
  path?: string;
  host?: string;
  cleanupTimeoutMillis?: number;
}

interface CaptureState {
  stdout: Buffer[];
  stderr: Buffer[];
  outputBytes: number;
  outputError?: SandboxOutputLimitError;
  spawnError?: Error;
}

function captureChunk(
  child: ReturnType<typeof spawn>,
  state: CaptureState,
  chunks: Buffer[],
  chunk: Buffer,
  maxOutputBytes: number,
): void {
  state.outputBytes += chunk.byteLength;
  if (state.outputBytes > maxOutputBytes) {
    state.outputError ??= new SandboxOutputLimitError(maxOutputBytes);
    child.kill("SIGKILL");
    return;
  }
  chunks.push(chunk);
}

function settleInvocation(
  state: CaptureState,
  code: number | null,
  resolve: (result: EngineRunResult) => void,
  reject: (error: Error) => void,
): void {
  if (state.outputError !== undefined) {
    reject(state.outputError);
    return;
  }
  if (state.spawnError !== undefined) {
    reject(
      new SandboxExecutionError("failed to invoke Docker CLI", {
        cause: state.spawnError,
      }),
    );
    return;
  }
  resolve({
    exitCode: code ?? 137,
    stdout: Buffer.concat(state.stdout),
    stderr: Buffer.concat(state.stderr),
  });
}

export class DockerCliEngine implements SandboxContainerEngine {
  readonly id = "docker-cli/v1";
  readonly destinationAllowlistEnforced = false;
  readonly #executable: string;
  readonly #path: string;
  readonly #host: string | undefined;
  readonly #cleanupTimeoutMillis: number;

  constructor(options: DockerCliOptions = {}) {
    this.#executable = options.executable ?? "docker";
    this.#path = options.path ?? process.env["PATH"] ?? "";
    this.#host = options.host;
    this.#cleanupTimeoutMillis = options.cleanupTimeoutMillis ?? 10_000;
  }

  run(request: EngineRunRequest): Promise<EngineRunResult> {
    return this.#invoke(request.args, request.signal, request.maxOutputBytes);
  }

  async remove(containerName: string): Promise<void> {
    const deadline = Date.now() + this.#cleanupTimeoutMillis;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new SandboxExecutionError("docker cleanup timed out");
      }
      const result = await this.#invoke(
        ["rm", "--force", containerName],
        AbortSignal.timeout(remaining),
        64 * 1024,
      );
      if (result.exitCode === 0) return;
      if (
        !Buffer.from(result.stderr)
          .toString("utf8")
          .includes("No such container")
      ) {
        throw new SandboxExecutionError(
          `docker cleanup exited with code ${result.exitCode}`,
        );
      }
      if (attempt < 3) await delay(25 * 2 ** attempt);
    }
  }

  #invoke(
    args: readonly string[],
    signal: AbortSignal,
    maxOutputBytes: number,
  ): Promise<EngineRunResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.#executable, [...args], {
        env: {
          PATH: this.#path,
          ...(this.#host === undefined ? {} : { DOCKER_HOST: this.#host }),
        },
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
      const state: CaptureState = {
        stdout: [],
        stderr: [],
        outputBytes: 0,
      };
      child.stdout.on("data", (chunk: Buffer) =>
        captureChunk(child, state, state.stdout, chunk, maxOutputBytes),
      );
      child.stderr.on("data", (chunk: Buffer) =>
        captureChunk(child, state, state.stderr, chunk, maxOutputBytes),
      );
      child.once("error", (error) => {
        state.spawnError = error;
      });
      const abort = (): void => {
        child.kill("SIGKILL");
      };
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
      child.once("close", (code) => {
        signal.removeEventListener("abort", abort);
        settleInvocation(state, code, resolve, reject);
      });
    });
  }
}
