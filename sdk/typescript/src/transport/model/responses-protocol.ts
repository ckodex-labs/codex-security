import Ajv, { type ValidateFunction } from "ajv";
import type {
  ModelExecutionRequest,
  ModelToolChoice,
} from "../../kernel/contracts.js";
import type { ValidatedModelConfig } from "./model-config.js";

export interface ToolAccumulator {
  callId: string;
  name: string;
  argumentsJson: string;
  emitted: boolean;
}

const MAX_EXECUTION_BYTES = 64 * 1024 * 1024;
const MAX_EXECUTION_MILLIS = 24 * 60 * 60 * 1_000;

export function buildRequestBody(
  config: ValidatedModelConfig,
  request: ModelExecutionRequest,
): Record<string, unknown> {
  return {
    model: config.modelId,
    stream: true,
    instructions: request.systemPrompt,
    input:
      request.continuation === undefined
        ? request.input
        : request.continuation.outputs.map((output) => ({
            type: "function_call_output",
            call_id: output.callId,
            output: output.output,
          })),
    ...(request.continuation === undefined
      ? {}
      : { previous_response_id: request.continuation.previousResponseId }),
    ...(request.tools === undefined
      ? {}
      : {
          tools: request.tools.map((tool) => ({
            type: "function",
            name: tool.name,
            description: tool.description,
            parameters: tool.inputSchema,
            strict: true,
          })),
        }),
    ...(request.toolChoice === undefined
      ? {}
      : { tool_choice: mapToolChoice(request.toolChoice) }),
    ...(request.outputFormat === undefined
      ? {}
      : {
          text: {
            format: {
              type: "json_schema",
              name: request.outputFormat.name,
              schema: request.outputFormat.schema,
              strict: true,
            },
          },
        }),
  };
}

export function validateRequest(request: ModelExecutionRequest): void {
  if (request.requestId.trim() === "") throw new Error("request ID is empty");
  validateLimits(request);
  validateContinuation(request);
  validateTools(request);
  validateRequiredFeatures(request);
}

function validateLimits(request: ModelExecutionRequest): void {
  for (const [name, value] of Object.entries(request.limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new Error(`model execution limit ${name} must be positive`);
    }
    const maximum = name.endsWith("Millis")
      ? MAX_EXECUTION_MILLIS
      : MAX_EXECUTION_BYTES;
    if (value > maximum) {
      throw new Error(`model execution limit ${name} is too large`);
    }
  }
}

function validateContinuation(request: ModelExecutionRequest): void {
  const continuation = request.continuation;
  if (continuation === undefined) return;
  validateBoundedIdentifier(
    continuation.previousResponseId,
    "previous response ID",
  );
  if (continuation.outputs.length === 0) {
    throw new Error("model continuation requires tool outputs");
  }
  const callIds = new Set<string>();
  for (const output of continuation.outputs) {
    validateBoundedIdentifier(output.callId, "model tool call ID");
    if (callIds.has(output.callId)) {
      throw new Error("model continuation tool call IDs must be unique");
    }
    callIds.add(output.callId);
    if (
      Buffer.byteLength(output.output, "utf8") >
      request.limits.maxToolArgumentBytes
    ) {
      throw new Error("model tool output exceeded its byte limit");
    }
  }
}

function validateTools(request: ModelExecutionRequest): void {
  if (
    request.tools !== undefined &&
    new Set(request.tools.map((tool) => tool.name)).size !==
      request.tools.length
  ) {
    throw new Error("model tool names must be unique");
  }
  for (const tool of request.tools ?? []) {
    validateProtocolName(tool.name, "model tool");
  }
  if (request.outputFormat !== undefined) {
    validateProtocolName(request.outputFormat.name, "structured output");
  }
  if (typeof request.toolChoice === "object") {
    const selectedName = request.toolChoice.name;
    if (!request.tools?.some((tool) => tool.name === selectedName)) {
      throw new Error("selected model tool is not defined");
    }
  }
}

function validateRequiredFeatures(request: ModelExecutionRequest): void {
  if (
    request.requiredCapabilities.includes("structured_output") &&
    request.outputFormat === undefined
  ) {
    throw new Error("structured output capability requires an output schema");
  }
  if (
    request.requiredCapabilities.includes("tool_calling") &&
    (request.tools === undefined || request.tools.length === 0)
  ) {
    throw new Error("tool calling capability requires tool definitions");
  }
}

export function compileStructuredValidator(
  request: ModelExecutionRequest,
): ValidateFunction | null {
  if (request.outputFormat === undefined) return null;
  try {
    return new Ajv({ allErrors: true, strict: true }).compile(
      request.outputFormat.schema,
    );
  } catch {
    throw new Error("structured output schema is invalid");
  }
}

export function captureTool(
  event: Record<string, unknown>,
  tools: Map<string, ToolAccumulator>,
  maxBytes: number,
): void {
  const item = recordFieldOptional(event, "item");
  if (item?.["type"] !== "function_call") return;
  const itemId = requiredString(item, "id");
  if (tools.has(itemId)) {
    throw new Error("model emitted a duplicate tool item");
  }
  const callId = requiredString(item, "call_id");
  if ([...tools.values()].some((tool) => tool.callId === callId)) {
    throw new Error("model emitted a duplicate tool call ID");
  }
  const argumentsJson = stringField(item, "arguments") ?? "";
  enforceToolBytes(argumentsJson, maxBytes);
  tools.set(itemId, {
    callId,
    name: requiredString(item, "name"),
    argumentsJson,
    emitted: false,
  });
}

export function appendToolArguments(
  event: Record<string, unknown>,
  tools: Map<string, ToolAccumulator>,
  maxBytes: number,
): void {
  const itemId = requiredString(event, "item_id");
  const tool = tools.get(itemId);
  if (tool === undefined) throw new Error("model tool delta has no item");
  if (tool.emitted) {
    throw new Error("model changed tool arguments after completion");
  }
  tool.argumentsJson += requiredString(event, "delta");
  enforceToolBytes(tool.argumentsJson, maxBytes);
}

export function completeTool(
  event: Record<string, unknown>,
  tools: Map<string, ToolAccumulator>,
  maxBytes: number,
): ToolAccumulator | null {
  const item = recordFieldOptional(event, "item");
  const itemId =
    stringField(event, "item_id") ??
    (item?.["type"] === "function_call" ? stringField(item, "id") : undefined);
  if (itemId === undefined) return null;
  let tool = tools.get(itemId);
  if (tool === undefined && item?.["type"] === "function_call") {
    captureTool({ item }, tools, maxBytes);
    tool = tools.get(itemId);
  }
  if (tool === undefined) throw new Error("completed model tool has no item");
  const completedArguments =
    stringField(event, "arguments") ??
    (item === undefined ? undefined : stringField(item, "arguments"));
  if (
    tool.emitted &&
    completedArguments !== undefined &&
    completedArguments !== tool.argumentsJson
  ) {
    throw new Error("model changed tool arguments after completion");
  }
  if (completedArguments !== undefined) tool.argumentsJson = completedArguments;
  enforceToolBytes(tool.argumentsJson, maxBytes);
  return tool;
}

export function normalizeUsage(usage: Record<string, unknown>): {
  inputTokens: number;
  outputTokens: number;
  cachedInputTokens?: number;
  totalTokens: number;
} {
  const inputTokens = tokenCount(usage, "input_tokens");
  const outputTokens = tokenCount(usage, "output_tokens");
  const totalTokens = tokenCount(usage, "total_tokens");
  if (totalTokens !== inputTokens + outputTokens) {
    throw new Error("model usage total is inconsistent");
  }
  const details = recordFieldOptional(usage, "input_tokens_details");
  const cached =
    details === undefined
      ? undefined
      : optionalTokenCount(details, "cached_tokens");
  if (cached !== undefined && cached > inputTokens) {
    throw new Error("model cached usage exceeds input usage");
  }
  return {
    inputTokens,
    outputTokens,
    ...(cached === undefined ? {} : { cachedInputTokens: cached }),
    totalTokens,
  };
}

export function parseEvent(data: string): Record<string, unknown> {
  const value = parseJson(data, "model SSE data");
  if (!isRecord(value)) throw new Error("model SSE data is not an object");
  return value;
}

export function recordField(
  record: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const value = record[key];
  if (!isRecord(value)) throw new Error(`model event field ${key} is invalid`);
  return value;
}

export function recordFieldOptional(
  record: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined {
  const value = record[key];
  if (value === undefined || value === null) return undefined;
  if (!isRecord(value)) throw new Error(`model event field ${key} is invalid`);
  return value;
}

export function stringField(
  record: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = record[key];
  return typeof value === "string" && value !== "" ? value : undefined;
}

export function requiredString(
  record: Record<string, unknown>,
  key: string,
): string {
  const value = stringField(record, key);
  if (value === undefined)
    throw new Error(`model event field ${key} is invalid`);
  return value;
}

export function resolveCredentialValue(
  config: ValidatedModelConfig,
  environment: Readonly<Record<string, string | undefined>>,
): string | undefined {
  const name = config.credential?.environmentVariable;
  return name === undefined ? undefined : environment[name]?.trim();
}

export function redactError(
  error: unknown,
  credential: string | undefined,
): Error {
  const original = error instanceof Error ? error.message : String(error);
  const message =
    credential === undefined || credential === ""
      ? original
      : original.replaceAll(credential, "[REDACTED]");
  return new Error(message);
}

function mapToolChoice(choice: ModelToolChoice): unknown {
  return typeof choice === "string"
    ? choice
    : { type: "function", name: choice.name };
}

function parseJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${label} is invalid JSON`);
  }
}

export function parseStructuredJson(value: string): unknown {
  return parseJson(value, "model structured output");
}

export function validateToolArguments(
  tool: ToolAccumulator,
  request: ModelExecutionRequest,
): void {
  const parsed = parseJson(tool.argumentsJson, "model tool arguments");
  if (!isRecord(parsed))
    throw new Error("model tool arguments is not an object");
  const definition = request.tools?.find((item) => item.name === tool.name);
  if (definition === undefined) {
    throw new Error("model called an undefined tool");
  }
  let validator: ValidateFunction;
  try {
    validator = new Ajv({ allErrors: true, strict: true }).compile(
      definition.inputSchema,
    );
  } catch {
    throw new Error(`model tool schema ${tool.name} is invalid`);
  }
  if (!validator(parsed)) {
    throw new Error(
      `model tool arguments for ${tool.name} did not match schema`,
    );
  }
}

function tokenCount(record: Record<string, unknown>, key: string): number {
  const value = optionalTokenCount(record, key);
  if (value === undefined)
    throw new Error(`model usage field ${key} is invalid`);
  return value;
}

function optionalTokenCount(
  record: Record<string, unknown>,
  key: string,
): number | undefined {
  const value = record[key];
  return Number.isSafeInteger(value) && (value as number) >= 0
    ? (value as number)
    : undefined;
}

function enforceToolBytes(value: string, maxBytes: number): void {
  if (Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new Error("model tool arguments exceeded their byte limit");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateProtocolName(value: string, label: string): void {
  if (!/^[A-Za-z0-9_-]{1,64}$/u.test(value)) {
    throw new Error(`${label} name is invalid`);
  }
}

function validateBoundedIdentifier(value: string, label: string): void {
  if (
    value.trim() === "" ||
    value !== value.trim() ||
    Buffer.byteLength(value, "utf8") > 256 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error(`${label} is invalid`);
  }
}
