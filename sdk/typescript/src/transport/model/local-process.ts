import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import type {
  ModelCapabilities,
  ModelCapability,
  ModelExecutionEvent,
  ModelExecutionRequest,
} from "../../kernel/contracts.js";
import type {
  ModelExecutionPort,
  ModelProcessSession,
  SandboxedModelProcessRunnerPort,
} from "../../kernel/ports.js";
import { requireModelEvent } from "./model-event-validation.js";
import { validateRequest } from "./responses-protocol.js";

export interface LocalProcessModelAdapterConfig {
  providerId: string;
  modelId: string;
  executable: string;
  arguments?: readonly string[];
  environment?: Readonly<Record<string, string>>;
  features: ReadonlySet<ModelCapability>;
}

export class LocalProcessModelAdapter implements ModelExecutionPort {
  readonly #config: LocalProcessModelAdapterConfig;
  readonly #runner: SandboxedModelProcessRunnerPort;
  readonly #active = new Map<string, ModelProcessSession>();
  readonly #controllers = new Map<string, AbortController>();

  public constructor(
    config: LocalProcessModelAdapterConfig,
    runner: SandboxedModelProcessRunnerPort,
  ) {
    validateConfig(config);
    this.#config = {
      ...config,
      arguments: [...(config.arguments ?? [])],
      environment: { ...(config.environment ?? {}) },
      features: new Set(config.features),
    };
    this.#runner = runner;
  }

  public async capabilities(): Promise<ModelCapabilities> {
    return {
      providerId: this.#config.providerId,
      modelId: this.#config.modelId,
      transport: "local_process",
      endpointSecurity: {
        tls: false,
        privateNetwork: true,
        loopbackOnly: true,
        source: "derived",
        endpointIdentityDigest: processIdentity(this.#config),
      },
      features: new Set(this.#config.features),
      capabilitySource: "configured",
    };
  }

  public async *execute(
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): AsyncIterable<ModelExecutionEvent> {
    validateRequest(request);
    requireCapabilities(this.#config.features, request.requiredCapabilities);
    if (this.#controllers.has(request.requestId)) {
      throw new Error(`model request ${request.requestId} is already active`);
    }
    const controller = new AbortController();
    this.#controllers.set(request.requestId, controller);
    const abort = (): void => controller.abort(abortReason(signal));
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    try {
      const session = await this.#startSession(request, controller.signal);
      this.#active.set(request.requestId, session);
      yield* consumeSession(session, request, controller.signal);
    } finally {
      signal.removeEventListener("abort", abort);
      this.#active.delete(request.requestId);
      this.#controllers.delete(request.requestId);
    }
  }

  public async cancel(requestId: string): Promise<void> {
    this.#controllers
      .get(requestId)
      ?.abort(new DOMException("operation aborted", "AbortError"));
    await this.#active.get(requestId)?.cancel();
  }

  async #startSession(
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): Promise<ModelProcessSession> {
    return await this.#runner.start(
      {
        executable: this.#config.executable,
        arguments: this.#config.arguments ?? [],
        environment: this.#config.environment ?? {},
        maxStdoutBytes: request.limits.maxResponseBytes,
        maxStderrBytes: Math.min(request.limits.maxResponseBytes, 64 * 1024),
        wallClockMillis: request.limits.wallClockMillis,
      },
      signal,
    );
  }
}

async function* consumeSession(
  session: ModelProcessSession,
  request: ModelExecutionRequest,
  signal: AbortSignal,
): AsyncIterable<ModelExecutionEvent> {
  const stderr = drainBounded(
    session.stderr,
    Math.min(request.limits.maxResponseBytes, 64 * 1024),
    "model process stderr",
  ).then(
    () => undefined,
    (error: unknown) => error,
  );
  let nextSequence = 0;
  try {
    const input = Buffer.from(
      `${JSON.stringify({ type: "execute", request })}\n`,
    );
    if (input.byteLength > request.limits.maxRequestBytes) {
      throw new Error("model process request exceeded its byte limit");
    }
    await session.write(input);
    await session.closeInput();
    for await (const event of decodeEvents(
      session.stdout,
      request.limits.maxResponseBytes,
    )) {
      nextSequence = event.sequence + 1;
      yield event;
    }
    const stderrError = await stderr;
    if (stderrError !== undefined) throw stderrError;
    const completion = await session.completion;
    if (completion.exitCode !== 0)
      throw new Error("model process exited unsuccessfully");
  } catch (error) {
    await session.cancel().catch(() => undefined);
    if (!signal.aborted) throw error;
    yield {
      kind: "canceled",
      sequence: nextSequence,
      reason: "operation aborted",
    };
  }
}

function validateConfig(config: LocalProcessModelAdapterConfig): void {
  if (config.providerId.trim() === "" || config.modelId.trim() === "") {
    throw new Error("local process model identity must not be empty");
  }
  if (!isAbsolute(config.executable)) {
    throw new Error("local process model executable must be an absolute path");
  }
  if ((config.arguments?.length ?? 0) > 64) {
    throw new Error("local process model has too many arguments");
  }
  for (const value of config.arguments ?? []) validateText(value, "argument");
  for (const [name, value] of Object.entries(config.environment ?? {})) {
    if (!/^[A-Z_][A-Z0-9_]{0,127}$/u.test(name)) {
      throw new Error("local process environment name is invalid");
    }
    validateText(value, "environment value");
  }
}

function validateText(value: string, label: string): void {
  if (Buffer.byteLength(value, "utf8") > 16 * 1024 || value.includes("\0")) {
    throw new Error(`local process ${label} is invalid`);
  }
}

function requireCapabilities(
  available: ReadonlySet<ModelCapability>,
  required: readonly ModelCapability[],
): void {
  for (const capability of required) {
    if (!available.has(capability)) {
      throw new Error(`model capability ${capability} is unavailable`);
    }
  }
}

async function* decodeEvents(
  source: AsyncIterable<Uint8Array>,
  maxBytes: number,
): AsyncIterable<ModelExecutionEvent> {
  let bytes = 0;
  let pending = "";
  for await (const chunk of source) {
    bytes += chunk.byteLength;
    if (bytes > maxBytes)
      throw new Error("model process stdout exceeded its byte limit");
    pending += Buffer.from(chunk).toString("utf8");
    const lines = pending.split("\n");
    pending = lines.pop() ?? "";
    for (const line of lines) {
      if (line !== "") yield parseModelEvent(line);
    }
  }
  if (pending.trim() !== "") yield parseModelEvent(pending);
}

function parseModelEvent(line: string): ModelExecutionEvent {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    throw new Error("model process emitted invalid NDJSON");
  }
  return requireModelEvent(value);
}

async function drainBounded(
  source: AsyncIterable<Uint8Array>,
  maxBytes: number,
  label: string,
): Promise<void> {
  let bytes = 0;
  for await (const chunk of source) {
    bytes += chunk.byteLength;
    if (bytes > maxBytes) throw new Error(`${label} exceeded its byte limit`);
  }
}

function processIdentity(
  config: LocalProcessModelAdapterConfig,
): `sha256:${string}` {
  const identity = JSON.stringify([
    config.executable,
    config.arguments ?? [],
    Object.keys(config.environment ?? {}).sort(),
  ]);
  return `sha256:${createHash("sha256").update(identity).digest("hex")}`;
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException("operation aborted", "AbortError");
}
