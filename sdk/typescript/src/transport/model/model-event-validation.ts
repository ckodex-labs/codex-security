import type {
  KernelJsonValue,
  ModelExecutionEvent,
} from "../../kernel/contracts.js";

const MAX_EVENT_STRING_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 32;
const MAX_JSON_NODES = 100_000;

export function requireModelEvent(value: unknown): ModelExecutionEvent {
  const event = requireRecord(value, "model event");
  const kind = requireString(event, "kind");
  const sequence = requireInteger(event, "sequence");
  if (sequence < 0) throw new Error("model event sequence is invalid");
  if (kind === "output_delta") return outputDelta(event, sequence);
  if (kind === "tool_call") return toolCall(event, sequence);
  if (kind === "structured_output") return structuredOutput(event, sequence);
  if (kind === "response_metadata") return responseMetadata(event, sequence);
  if (kind === "usage") return usage(event, sequence);
  if (kind === "completed") return completed(event, sequence);
  if (kind === "canceled") return canceled(event, sequence);
  throw new Error("model event kind is invalid");
}

function outputDelta(
  event: Record<string, unknown>,
  sequence: number,
): ModelExecutionEvent {
  requireKeys(event, ["kind", "sequence", "text"]);
  return { kind: "output_delta", sequence, text: requireString(event, "text") };
}

function toolCall(
  event: Record<string, unknown>,
  sequence: number,
): ModelExecutionEvent {
  requireKeys(event, ["kind", "sequence", "callId", "name", "argumentsJson"]);
  return {
    kind: "tool_call",
    sequence,
    callId: requireString(event, "callId"),
    name: requireString(event, "name"),
    argumentsJson: requireString(event, "argumentsJson"),
  };
}

function structuredOutput(
  event: Record<string, unknown>,
  sequence: number,
): ModelExecutionEvent {
  requireKeys(event, ["kind", "sequence", "value"]);
  validateJson(event["value"]);
  return {
    kind: "structured_output",
    sequence,
    value: event["value"] as KernelJsonValue,
  };
}

function responseMetadata(
  event: Record<string, unknown>,
  sequence: number,
): ModelExecutionEvent {
  requireKeys(event, [
    "kind",
    "sequence",
    "responseId",
    "providerRequestId",
    "returnedModelId",
    "peerCertificateFingerprint",
  ]);
  const fingerprint = optionalString(event, "peerCertificateFingerprint");
  if (
    fingerprint !== undefined &&
    !/^sha256:[0-9a-f]{64}$/u.test(fingerprint)
  ) {
    throw new Error("model event certificate fingerprint is invalid");
  }
  return {
    kind: "response_metadata",
    sequence,
    responseId: requireString(event, "responseId"),
    ...optionalFields(event, fingerprint),
  };
}

function optionalFields(
  event: Record<string, unknown>,
  fingerprint: string | undefined,
): Partial<Extract<ModelExecutionEvent, { kind: "response_metadata" }>> {
  const providerRequestId = optionalString(event, "providerRequestId");
  const returnedModelId = optionalString(event, "returnedModelId");
  return {
    ...(providerRequestId === undefined ? {} : { providerRequestId }),
    ...(returnedModelId === undefined ? {} : { returnedModelId }),
    ...(fingerprint === undefined
      ? {}
      : { peerCertificateFingerprint: fingerprint as `sha256:${string}` }),
  };
}

function usage(
  event: Record<string, unknown>,
  sequence: number,
): ModelExecutionEvent {
  requireKeys(event, [
    "kind",
    "sequence",
    "inputTokens",
    "outputTokens",
    "cachedInputTokens",
    "totalTokens",
  ]);
  const cachedInputTokens = optionalInteger(event, "cachedInputTokens");
  return {
    kind: "usage",
    sequence,
    inputTokens: requireNonNegative(event, "inputTokens"),
    outputTokens: requireNonNegative(event, "outputTokens"),
    totalTokens: requireNonNegative(event, "totalTokens"),
    ...(cachedInputTokens === undefined ? {} : { cachedInputTokens }),
  };
}

function completed(
  event: Record<string, unknown>,
  sequence: number,
): ModelExecutionEvent {
  requireKeys(event, ["kind", "sequence", "finishReason", "responseId"]);
  return {
    kind: "completed",
    sequence,
    finishReason: requireString(event, "finishReason"),
    responseId: requireString(event, "responseId"),
  };
}

function canceled(
  event: Record<string, unknown>,
  sequence: number,
): ModelExecutionEvent {
  requireKeys(event, ["kind", "sequence", "reason"]);
  return { kind: "canceled", sequence, reason: requireString(event, "reason") };
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: Record<string, unknown>, field: string): string {
  const result = value[field];
  if (
    typeof result !== "string" ||
    Buffer.byteLength(result, "utf8") > MAX_EVENT_STRING_BYTES
  ) {
    throw new Error(`model event ${field} is invalid`);
  }
  return result;
}

function optionalString(
  value: Record<string, unknown>,
  field: string,
): string | undefined {
  return value[field] === undefined ? undefined : requireString(value, field);
}

function requireInteger(value: Record<string, unknown>, field: string): number {
  const result = value[field];
  if (!Number.isSafeInteger(result)) {
    throw new Error(`model event ${field} is invalid`);
  }
  return result as number;
}

function requireNonNegative(
  value: Record<string, unknown>,
  field: string,
): number {
  const result = requireInteger(value, field);
  if (result < 0) throw new Error(`model event ${field} is invalid`);
  return result;
}

function optionalInteger(
  value: Record<string, unknown>,
  field: string,
): number | undefined {
  return value[field] === undefined
    ? undefined
    : requireNonNegative(value, field);
}

function requireKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): void {
  const names = new Set(allowed);
  if (Object.keys(value).some((name) => !names.has(name))) {
    throw new Error("model event contains an unsupported field");
  }
}

function validateJson(value: unknown): void {
  const pending: { value: unknown; depth: number }[] = [{ value, depth: 0 }];
  let nodes = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) break;
    nodes += 1;
    if (nodes > MAX_JSON_NODES || current.depth > MAX_JSON_DEPTH) {
      throw new Error("model structured output exceeded its shape limit");
    }
    addJsonChildren(current.value, current.depth, pending);
  }
}

function addJsonChildren(
  value: unknown,
  depth: number,
  pending: { value: unknown; depth: number }[],
): void {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_EVENT_STRING_BYTES)
      throw new Error("model structured output string is too large");
    return;
  }
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (Array.isArray(value)) {
    for (const item of value) pending.push({ value: item, depth: depth + 1 });
    return;
  }
  const record = requireRecord(value, "model structured output value");
  for (const item of Object.values(record)) {
    pending.push({ value: item, depth: depth + 1 });
  }
}
