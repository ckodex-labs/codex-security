import type { ValidateFunction } from "ajv";
import type {
  KernelJsonValue,
  ModelCapabilities,
  ModelExecutionEvent,
  ModelExecutionRequest,
} from "../../kernel/contracts.js";
import {
  appendToolArguments,
  captureTool,
  completeTool,
  normalizeUsage,
  parseEvent,
  parseStructuredJson,
  recordField,
  recordFieldOptional,
  requiredString,
  stringField,
  validateToolArguments,
  type ToolAccumulator,
} from "./responses-protocol.js";
import {
  parseServerSentEvents,
  type ServerSentEvent,
} from "./responses-sse.js";

const IGNORED_EVENTS = new Set([
  "response.in_progress",
  "response.content_part.added",
  "response.content_part.done",
  "response.output_text.done",
]);

export interface ResponseStreamContext {
  request: ModelExecutionRequest;
  endpointSecurity: ModelCapabilities["endpointSecurity"];
  structuredValidator: ValidateFunction | null;
  signal: AbortSignal;
  onIdleTimeout(): void;
}

export async function* interpretResponseStream(
  response: Response,
  context: ResponseStreamContext,
): AsyncGenerator<ModelExecutionEvent> {
  const body = requireResponseBody(response);
  const state = new ResponseStreamState(
    context,
    response.headers.get("x-request-id") ??
      response.headers.get("request-id") ??
      undefined,
  );
  for await (const sse of parseServerSentEvents(
    body,
    streamLimits(context.request),
    context.signal,
    context.onIdleTimeout,
  )) {
    for (const event of state.accept(sse)) yield event;
  }
  state.requireTerminal();
}

class ResponseStreamState {
  readonly #context: ResponseStreamContext;
  readonly #providerRequestId: string | undefined;
  readonly #tools = new Map<string, ToolAccumulator>();
  #responseId: string | undefined;
  #returnedModelId: string | undefined;
  #metadataEmitted = false;
  #usageEmitted = false;
  #terminal = false;
  #output = "";
  #sequence = 0;

  public constructor(
    context: ResponseStreamContext,
    providerRequestId: string | undefined,
  ) {
    this.#context = context;
    this.#providerRequestId = providerRequestId;
  }

  public accept(sse: ServerSentEvent): ModelExecutionEvent[] {
    if (sse.data === "[DONE]") return [];
    if (this.#terminal)
      throw new Error("model emitted an event after terminal completion");
    const event = parseEvent(sse.data);
    const payloadType = stringField(event, "type");
    if (
      payloadType !== undefined &&
      sse.event !== undefined &&
      payloadType !== sse.event
    ) {
      throw new Error("model SSE event type does not match its payload");
    }
    const type = payloadType ?? sse.event;
    if (type === undefined) throw new Error("model SSE event has no type");
    return this.#dispatch(type, event);
  }

  public requireTerminal(): void {
    if (!this.#terminal)
      throw new Error("model stream ended without a terminal completion");
  }

  #dispatch(
    type: string,
    event: Record<string, unknown>,
  ): ModelExecutionEvent[] {
    if (type === "response.created") return [this.#metadata(event)];
    if (type === "response.output_text.delta") return [this.#delta(event)];
    if (type === "response.output_item.added") {
      captureTool(event, this.#tools, this.#maxToolBytes());
      return [];
    }
    if (type === "response.function_call_arguments.delta") {
      appendToolArguments(event, this.#tools, this.#maxToolBytes());
      return [];
    }
    if (isToolDone(type)) return this.#completeTool(event);
    if (type === "response.completed") return this.#complete(event);
    if (isFailure(type)) throw new Error(`model stream reported ${type}`);
    if (IGNORED_EVENTS.has(type)) return [];
    throw new Error(`model stream emitted unsupported event ${type}`);
  }

  #metadata(event: Record<string, unknown>): ModelExecutionEvent {
    if (this.#metadataEmitted)
      throw new Error("model emitted response metadata more than once");
    const response = recordField(event, "response");
    this.#responseId = requiredString(response, "id");
    this.#returnedModelId = stringField(response, "model");
    this.#metadataEmitted = true;
    return this.#metadataEvent();
  }

  #metadataEvent(): ModelExecutionEvent {
    const responseId = this.#responseId;
    if (responseId === undefined)
      throw new Error("model response ID is missing");
    const fingerprint =
      this.#context.endpointSecurity.peerCertificateFingerprint;
    return {
      kind: "response_metadata",
      sequence: this.#sequence++,
      responseId,
      ...(this.#providerRequestId === undefined
        ? {}
        : { providerRequestId: this.#providerRequestId }),
      ...(this.#returnedModelId === undefined
        ? {}
        : { returnedModelId: this.#returnedModelId }),
      ...(fingerprint === undefined
        ? {}
        : { peerCertificateFingerprint: fingerprint }),
    };
  }

  #delta(event: Record<string, unknown>): ModelExecutionEvent {
    const text = requiredString(event, "delta");
    this.#output += text;
    return { kind: "output_delta", sequence: this.#sequence++, text };
  }

  #completeTool(event: Record<string, unknown>): ModelExecutionEvent[] {
    const tool = completeTool(event, this.#tools, this.#maxToolBytes());
    if (tool === null || tool.emitted) return [];
    validateToolArguments(tool, this.#context.request);
    tool.emitted = true;
    return [
      {
        kind: "tool_call",
        sequence: this.#sequence++,
        callId: tool.callId,
        name: tool.name,
        argumentsJson: tool.argumentsJson,
      },
    ];
  }

  #complete(event: Record<string, unknown>): ModelExecutionEvent[] {
    const completed = recordField(event, "response");
    this.#acceptIdentity(completed);
    const events: ModelExecutionEvent[] = [];
    if (!this.#metadataEmitted) events.push(this.#metadataEvent());
    if ([...this.#tools.values()].some((tool) => !tool.emitted)) {
      throw new Error("model completed with unfinished tool arguments");
    }
    const structured = this.#structuredOutput();
    if (structured !== undefined) events.push(structured);
    const usage = this.#usage(completed);
    if (usage !== undefined) events.push(usage);
    this.#requireUsage();
    const status = stringField(completed, "status") ?? "completed";
    if (status !== "completed")
      throw new Error(`model response ended with status ${status}`);
    this.#terminal = true;
    events.push({
      kind: "completed",
      sequence: this.#sequence++,
      finishReason: status,
      responseId: this.#requiredResponseId(),
    });
    return events;
  }

  #acceptIdentity(completed: Record<string, unknown>): void {
    const responseId = requiredString(completed, "id");
    if (this.#responseId !== undefined && this.#responseId !== responseId) {
      throw new Error("model completion response ID does not match");
    }
    this.#responseId = responseId;
    const modelId = stringField(completed, "model");
    if (
      this.#returnedModelId !== undefined &&
      modelId !== undefined &&
      this.#returnedModelId !== modelId
    ) {
      throw new Error("model completion identity does not match");
    }
    this.#returnedModelId ??= modelId;
  }

  #structuredOutput(): ModelExecutionEvent | undefined {
    const validator = this.#context.structuredValidator;
    if (validator === null) return undefined;
    const value = parseStructuredJson(this.#output);
    if (!validator(value)) {
      throw new Error("model structured output did not match its schema");
    }
    return {
      kind: "structured_output",
      sequence: this.#sequence++,
      value: value as KernelJsonValue,
    };
  }

  #usage(completed: Record<string, unknown>): ModelExecutionEvent | undefined {
    const value = recordFieldOptional(completed, "usage");
    if (value === undefined) return undefined;
    if (this.#usageEmitted)
      throw new Error("model emitted usage more than once");
    this.#usageEmitted = true;
    return {
      kind: "usage",
      sequence: this.#sequence++,
      ...normalizeUsage(value),
    };
  }

  #requireUsage(): void {
    if (
      this.#context.request.requiredCapabilities.includes("usage_accounting") &&
      !this.#usageEmitted
    ) {
      throw new Error("model completion did not include required usage");
    }
  }

  #requiredResponseId(): string {
    if (this.#responseId === undefined)
      throw new Error("model response ID is missing");
    return this.#responseId;
  }

  #maxToolBytes(): number {
    return this.#context.request.limits.maxToolArgumentBytes;
  }
}

function requireResponseBody(response: Response): ReadableStream<Uint8Array> {
  if (response.body === null)
    throw new Error("model endpoint returned an empty stream");
  return response.body;
}

function streamLimits(request: ModelExecutionRequest): {
  maxResponseBytes: number;
  maxEventBytes: number;
  streamIdleTimeoutMillis: number;
} {
  return {
    maxResponseBytes: request.limits.maxResponseBytes,
    maxEventBytes: Math.min(
      request.limits.maxResponseBytes,
      Math.max(request.limits.maxToolArgumentBytes, 64 * 1024),
    ),
    streamIdleTimeoutMillis: request.limits.streamIdleTimeoutMillis,
  };
}

function isToolDone(type: string): boolean {
  return (
    type === "response.function_call_arguments.done" ||
    type === "response.output_item.done"
  );
}

function isFailure(type: string): boolean {
  return (
    type === "response.failed" ||
    type === "response.incomplete" ||
    type === "error"
  );
}
