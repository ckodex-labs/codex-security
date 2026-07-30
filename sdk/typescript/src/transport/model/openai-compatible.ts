import type {
  ModelCapabilities,
  ModelExecutionEvent,
  ModelExecutionRequest,
} from "../../kernel/contracts.js";
import type {
  ModelExecutionPort,
  PreparedModelExecution,
} from "../../kernel/ports.js";
import {
  deriveEndpointSecurity,
  LocalFetchConnector,
  type ModelHttpConnector,
  type PreparedModelConnection,
} from "./endpoint-security.js";
import {
  resolveCredential,
  validateModelConfig,
  type OpenAIResponsesAdapterConfig,
  type ValidatedModelConfig,
} from "./model-config.js";
import {
  buildRequestBody,
  compileStructuredValidator,
  redactError,
  resolveCredentialValue,
  validateRequest,
} from "./responses-protocol.js";
import { interpretResponseStream } from "./responses-stream-interpreter.js";

export interface OpenAIResponsesAdapterDependencies {
  connector?: ModelHttpConnector;
  environment?: Readonly<Record<string, string | undefined>>;
}

const CAPABILITY_LIMITS = {
  maxRequestBytes: 1,
  maxResponseBytes: 1,
  maxToolArgumentBytes: 1,
  headerTimeoutMillis: 5_000,
  streamIdleTimeoutMillis: 5_000,
  wallClockMillis: 5_000,
} as const;
const MAX_RESPONSE_HEADER_BYTES = 64 * 1024;

export class OpenAIResponsesAdapter implements ModelExecutionPort {
  readonly #config: ValidatedModelConfig;
  readonly #connector: ModelHttpConnector;
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #active = new Map<string, AbortController>();
  readonly #prepared = new Map<
    string,
    {
      connection: PreparedModelConnection;
      endpointSecurity: ModelCapabilities["endpointSecurity"];
    }
  >();

  public constructor(
    config: OpenAIResponsesAdapterConfig,
    dependencies: OpenAIResponsesAdapterDependencies = {},
  ) {
    this.#config = validateModelConfig(config);
    this.#connector = dependencies.connector ?? new LocalFetchConnector();
    this.#environment = dependencies.environment ?? process.env;
  }

  public async capabilities(): Promise<ModelCapabilities> {
    const controller = new AbortController();
    const connection = await this.#connector.prepare(
      this.#config.endpoint,
      CAPABILITY_LIMITS,
      controller.signal,
    );
    const endpointSecurity = deriveEndpointSecurity(
      this.#config,
      connection.evidence,
    );
    return this.#capabilities(endpointSecurity);
  }

  public async prepare(
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): Promise<PreparedModelExecution> {
    validateRequest(request);
    if (
      this.#prepared.has(request.requestId) ||
      this.#active.has(request.requestId)
    ) {
      throw new Error(`model request ${request.requestId} is already active`);
    }
    const connection = await this.#connector.prepare(
      this.#config.endpoint,
      request.limits,
      signal,
    );
    const endpointSecurity = deriveEndpointSecurity(
      this.#config,
      connection.evidence,
    );
    this.#prepared.set(request.requestId, { connection, endpointSecurity });
    let consumed = false;
    return {
      capabilities: this.#capabilities(endpointSecurity),
      execute: () => {
        if (consumed) {
          throw new Error(
            `model request ${request.requestId} was already consumed`,
          );
        }
        consumed = true;
        return this.execute(request, signal);
      },
      cancel: async () => {
        this.#prepared.delete(request.requestId);
        await this.cancel(request.requestId);
      },
    };
  }

  public async *execute(
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): AsyncIterable<ModelExecutionEvent> {
    this.#validateExecution(request);
    const lifecycle = this.#startExecution(request, signal);
    const { controller, abortFromCaller, wallClock } = lifecycle;
    let sequence = 0;
    try {
      controller.signal.throwIfAborted();
      const prepared = await this.#resolveConnection(
        request,
        controller.signal,
      );
      const response = await this.#send(
        prepared.connection,
        request,
        controller,
      );
      const events = this.#events(response, request, prepared, controller);
      for await (const event of events) {
        sequence = event.sequence + 1;
        yield event;
      }
    } catch (error) {
      if (isCancellation(controller.signal.reason) || signal.aborted) {
        yield {
          kind: "canceled",
          sequence: sequence++,
          reason: "operation aborted",
        };
        return;
      }
      const failure = controller.signal.aborted
        ? controller.signal.reason
        : error;
      throw redactError(
        failure,
        resolveCredentialValue(this.#config, this.#environment),
      );
    } finally {
      clearTimeout(wallClock);
      signal.removeEventListener("abort", abortFromCaller);
      this.#active.delete(request.requestId);
    }
  }

  #startExecution(
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): {
    controller: AbortController;
    abortFromCaller: () => void;
    wallClock: ReturnType<typeof setTimeout>;
  } {
    const controller = new AbortController();
    this.#active.set(request.requestId, controller);
    const abortFromCaller = (): void =>
      controller.abort(new DOMException("operation aborted", "AbortError"));
    signal.addEventListener("abort", abortFromCaller, { once: true });
    if (signal.aborted) abortFromCaller();
    const wallClock = setTimeout(
      () => controller.abort(new Error("model request exceeded its deadline")),
      request.limits.wallClockMillis,
    );
    return { controller, abortFromCaller, wallClock };
  }

  #validateExecution(request: ModelExecutionRequest): void {
    validateRequest(request);
    for (const required of request.requiredCapabilities) {
      if (!this.#config.features.has(required)) {
        throw new Error(`model capability ${required} is unavailable`);
      }
    }
    if (this.#active.has(request.requestId)) {
      throw new Error(`model request ${request.requestId} is already active`);
    }
  }

  async #resolveConnection(
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): Promise<{
    connection: PreparedModelConnection;
    endpointSecurity: ModelCapabilities["endpointSecurity"];
  }> {
    const prepared = this.#prepared.get(request.requestId);
    this.#prepared.delete(request.requestId);
    if (prepared !== undefined) return prepared;
    const connection = await this.#connector.prepare(
      this.#config.endpoint,
      request.limits,
      signal,
    );
    return {
      connection,
      endpointSecurity: deriveEndpointSecurity(
        this.#config,
        connection.evidence,
      ),
    };
  }

  async #send(
    connection: PreparedModelConnection,
    request: ModelExecutionRequest,
    controller: AbortController,
  ): Promise<Response> {
    const encoded = encodeRequest(this.#config, request);
    controller.signal.throwIfAborted();
    const headers = requestHeaders(
      resolveCredential(this.#config, this.#environment),
    );
    const response = await sendWithHeaderTimeout(
      connection,
      encoded,
      headers,
      request.limits.headerTimeoutMillis,
      controller,
    );
    validateResponse(response, request.limits.maxResponseBytes);
    return response;
  }

  #events(
    response: Response,
    request: ModelExecutionRequest,
    prepared: {
      endpointSecurity: ModelCapabilities["endpointSecurity"];
    },
    controller: AbortController,
  ): AsyncGenerator<ModelExecutionEvent> {
    return interpretResponseStream(response, {
      request,
      endpointSecurity: prepared.endpointSecurity,
      structuredValidator: compileStructuredValidator(request),
      signal: controller.signal,
      onIdleTimeout: () =>
        controller.abort(new Error("model response stream timed out")),
    });
  }

  public async cancel(requestId: string): Promise<void> {
    this.#prepared.delete(requestId);
    this.#active
      .get(requestId)
      ?.abort(new DOMException("operation aborted", "AbortError"));
  }

  #capabilities(
    endpointSecurity: ModelCapabilities["endpointSecurity"],
  ): ModelCapabilities {
    return {
      providerId: this.#config.providerId,
      modelId: this.#config.modelId,
      transport: this.#config.transport,
      endpointSecurity,
      features: new Set(this.#config.features),
      capabilitySource: this.#config.capabilitySource,
    };
  }
}

function encodeRequest(
  config: ValidatedModelConfig,
  request: ModelExecutionRequest,
): string {
  const encoded = JSON.stringify(buildRequestBody(config, request));
  if (Buffer.byteLength(encoded, "utf8") > request.limits.maxRequestBytes) {
    throw new Error("model request exceeded its byte limit");
  }
  return encoded;
}

function requestHeaders(
  credential: string | undefined,
): Record<string, string> {
  const headers: Record<string, string> = {
    accept: "text/event-stream",
    "content-type": "application/json",
  };
  if (credential !== undefined)
    headers["authorization"] = `Bearer ${credential}`;
  enforceHeaderBytes(headers, "model request headers");
  return headers;
}

async function sendWithHeaderTimeout(
  connection: PreparedModelConnection,
  body: string,
  headers: Readonly<Record<string, string>>,
  timeoutMillis: number,
  controller: AbortController,
): Promise<Response> {
  const timeout = setTimeout(
    () => controller.abort(new Error("model response headers timed out")),
    timeoutMillis,
  );
  try {
    return await connection.send(
      { method: "POST", headers, body, redirect: "manual" },
      controller.signal,
    );
  } finally {
    clearTimeout(timeout);
  }
}

function validateResponse(response: Response, maxResponseBytes: number): void {
  enforceResponseHeaders(response.headers);
  if (response.status >= 300 && response.status < 400) {
    throw new Error("model endpoint redirects are forbidden");
  }
  if (!response.ok)
    throw new Error(`model endpoint returned HTTP ${response.status}`);
  const contentType = response.headers.get("content-type") ?? "";
  if (!/^text\/event-stream(?:;|$)/iu.test(contentType)) {
    throw new Error("model endpoint did not return an SSE stream");
  }
  if (response.body === null)
    throw new Error("model endpoint returned an empty stream");
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^\d+$/u.test(declaredLength) ||
      Number(declaredLength) > maxResponseBytes)
  ) {
    throw new Error("model response declared an invalid byte length");
  }
}

function enforceResponseHeaders(headers: Headers): void {
  let bytes = 0;
  for (const [name, value] of headers) {
    bytes += Buffer.byteLength(name, "utf8") + Buffer.byteLength(value, "utf8");
    if (bytes > MAX_RESPONSE_HEADER_BYTES) {
      throw new Error("model response headers exceeded their byte limit");
    }
  }
}

function enforceHeaderBytes(
  headers: Readonly<Record<string, string>>,
  label: string,
): void {
  let bytes = 0;
  for (const [name, value] of Object.entries(headers)) {
    bytes += Buffer.byteLength(name, "utf8") + Buffer.byteLength(value, "utf8");
    if (bytes > MAX_RESPONSE_HEADER_BYTES) {
      throw new Error(`${label} exceeded their byte limit`);
    }
  }
}

function isCancellation(reason: unknown): boolean {
  return reason instanceof DOMException && reason.name === "AbortError";
}
