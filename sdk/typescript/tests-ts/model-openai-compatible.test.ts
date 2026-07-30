import { describe, expect, test } from "bun:test";
import type {
  ModelExecutionEvent,
  ModelExecutionRequest,
} from "../src/kernel/contracts.js";
import type {
  ConnectionEvidence,
  ModelHttpConnector,
  PreparedModelConnection,
} from "../src/transport/model/endpoint-security.js";
import { OpenAIResponsesAdapter } from "../src/transport/model/openai-compatible.js";

const limits = {
  maxRequestBytes: 64 * 1024,
  maxResponseBytes: 64 * 1024,
  maxToolArgumentBytes: 4 * 1024,
  headerTimeoutMillis: 1_000,
  streamIdleTimeoutMillis: 1_000,
  wallClockMillis: 2_000,
} as const;

function request(
  overrides: Partial<ModelExecutionRequest> = {},
): ModelExecutionRequest {
  return {
    requestId: "request-1",
    systemPrompt: "Follow the schema.",
    input: "Inspect this.",
    requiredCapabilities: [
      "streaming",
      "structured_output",
      "tool_calling",
      "cancellation",
      "usage_accounting",
    ],
    tools: [
      {
        name: "inspect",
        description: "Inspect an item.",
        inputSchema: {
          type: "object",
          properties: { path: { type: "string" } },
          required: ["path"],
          additionalProperties: false,
        },
      },
    ],
    toolChoice: { name: "inspect" },
    outputFormat: {
      name: "result",
      schema: {
        type: "object",
        properties: { ok: { type: "boolean" } },
        required: ["ok"],
        additionalProperties: false,
      },
      strict: true,
    },
    limits,
    ...overrides,
  };
}

function adapter(
  connector: ModelHttpConnector,
  environment: Record<string, string | undefined> = {},
) {
  return new OpenAIResponsesAdapter(
    {
      providerId: "private-provider",
      modelId: "model-a",
      baseUrl: "https://models.internal/v1",
      transport: "private_http",
      credential: { environmentVariable: "MODEL_TOKEN" },
      features: new Set([
        "streaming",
        "structured_output",
        "tool_calling",
        "cancellation",
        "usage_accounting",
      ]),
      capabilitySource: "configured",
    },
    { connector, environment },
  );
}

function privateEvidence(): ConnectionEvidence {
  return {
    resolvedAddress: "10.20.30.40",
    addressPinned: true,
    tlsAuthenticated: true,
    peerCertificateFingerprint: `sha256:${"a".repeat(64)}`,
  };
}

function sseResponse(events: unknown[], headers: Record<string, string> = {}) {
  const contents = events
    .map((event) => `data: ${JSON.stringify(event)}\n\n`)
    .join("");
  return new Response(contents, {
    status: 200,
    headers: { "content-type": "text/event-stream", ...headers },
  });
}

async function collect(
  iterable: AsyncIterable<ModelExecutionEvent>,
): Promise<ModelExecutionEvent[]> {
  const events = [];
  for await (const event of iterable) events.push(event);
  return events;
}

describe("OpenAI Responses-compatible model adapter", () => {
  test("streams tools and schema-validated output with stable identity and usage", async () => {
    let requestInit: RequestInit | undefined;
    const connector: ModelHttpConnector = {
      async prepare(): Promise<PreparedModelConnection> {
        return {
          evidence: privateEvidence(),
          async send(init) {
            requestInit = init;
            return sseResponse(
              [
                {
                  type: "response.created",
                  response: { id: "resp-1", model: "returned-model" },
                },
                {
                  type: "response.output_item.added",
                  item: {
                    type: "function_call",
                    id: "item-1",
                    call_id: "call-1",
                    name: "inspect",
                    arguments: "",
                  },
                },
                {
                  type: "response.function_call_arguments.done",
                  item_id: "item-1",
                  arguments: '{"path":"src"}',
                },
                {
                  type: "response.output_text.delta",
                  delta: '{"ok":true}',
                },
                {
                  type: "response.completed",
                  response: {
                    id: "resp-1",
                    model: "returned-model",
                    status: "completed",
                    usage: {
                      input_tokens: 7,
                      output_tokens: 3,
                      total_tokens: 10,
                      input_tokens_details: { cached_tokens: 2 },
                    },
                  },
                },
              ],
              { "x-request-id": "provider-request-1" },
            );
          },
        };
      },
    };
    const events = await collect(
      adapter(connector, { MODEL_TOKEN: "secret-value" }).execute(
        request(),
        new AbortController().signal,
      ),
    );

    expect(events.map((event) => event.kind)).toEqual([
      "response_metadata",
      "tool_call",
      "output_delta",
      "structured_output",
      "usage",
      "completed",
    ]);
    expect(events.map((event) => event.sequence)).toEqual([0, 1, 2, 3, 4, 5]);
    expect(events[0]).toMatchObject({
      responseId: "resp-1",
      providerRequestId: "provider-request-1",
      returnedModelId: "returned-model",
    });
    expect(events[1]).toMatchObject({
      callId: "call-1",
      name: "inspect",
      argumentsJson: '{"path":"src"}',
    });
    expect(events[4]).toMatchObject({
      inputTokens: 7,
      outputTokens: 3,
      cachedInputTokens: 2,
      totalTokens: 10,
    });
    expect(new Headers(requestInit?.headers).get("authorization")).toBe(
      "Bearer secret-value",
    );
    const body = JSON.parse(String(requestInit?.body));
    expect(body).toMatchObject({
      model: "model-a",
      stream: true,
      tool_choice: { type: "function", name: "inspect" },
      text: { format: { type: "json_schema", strict: true } },
    });
  });

  test("rejects duplicate active IDs and cancellation is idempotent", async () => {
    const connector: ModelHttpConnector = {
      async prepare(): Promise<PreparedModelConnection> {
        return {
          evidence: privateEvidence(),
          async send(_init, signal) {
            await new Promise<void>((_resolve, reject) => {
              signal.addEventListener("abort", () => reject(signal.reason), {
                once: true,
              });
            });
            throw new Error("unreachable");
          },
        };
      },
    };
    const client = adapter(connector, { MODEL_TOKEN: "token" });
    const first = client.execute(request(), new AbortController().signal);
    const pending = first[Symbol.asyncIterator]().next();
    await Promise.resolve();
    await expect(
      collect(client.execute(request(), new AbortController().signal)),
    ).rejects.toThrow("already active");
    await client.cancel("request-1");
    await client.cancel("request-1");
    expect(await pending).toEqual({
      done: false,
      value: { kind: "canceled", sequence: 0, reason: "operation aborted" },
    });
  });

  test("redacts credentials and never follows redirects", async () => {
    const failing: ModelHttpConnector = {
      async prepare(): Promise<PreparedModelConnection> {
        return {
          evidence: privateEvidence(),
          async send() {
            throw new Error("upstream rejected secret-value");
          },
        };
      },
    };
    await expect(
      collect(
        adapter(failing, { MODEL_TOKEN: "secret-value" }).execute(
          request(),
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("upstream rejected [REDACTED]");

    const redirecting: ModelHttpConnector = {
      async prepare(): Promise<PreparedModelConnection> {
        return {
          evidence: privateEvidence(),
          async send() {
            return new Response(null, {
              status: 307,
              headers: { location: "https://attacker.example" },
            });
          },
        };
      },
    };
    await expect(
      collect(
        adapter(redirecting, { MODEL_TOKEN: "secret-value" }).execute(
          request(),
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("redirects are forbidden");
  });

  test("fails closed when required usage or structured conformance is absent", async () => {
    const connector: ModelHttpConnector = {
      async prepare(): Promise<PreparedModelConnection> {
        return {
          evidence: privateEvidence(),
          async send() {
            return sseResponse([
              {
                type: "response.created",
                response: { id: "resp-2", model: "model-a" },
              },
              {
                type: "response.output_text.delta",
                delta: '{"ok":"not-a-boolean"}',
              },
              {
                type: "response.completed",
                response: {
                  id: "resp-2",
                  status: "completed",
                },
              },
            ]);
          },
        };
      },
    };
    await expect(
      collect(
        adapter(connector, { MODEL_TOKEN: "token" }).execute(
          request(),
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("did not match its schema");
  });

  test("does not complete a usage-accounted request without terminal usage", async () => {
    const connector: ModelHttpConnector = {
      async prepare(): Promise<PreparedModelConnection> {
        return {
          evidence: privateEvidence(),
          async send() {
            return sseResponse([
              {
                type: "response.created",
                response: { id: "resp-3", model: "model-a" },
              },
              {
                type: "response.output_text.delta",
                delta: '{"ok":true}',
              },
              {
                type: "response.completed",
                response: { id: "resp-3", status: "completed" },
              },
            ]);
          },
        };
      },
    };
    await expect(
      collect(
        adapter(connector, { MODEL_TOKEN: "token" }).execute(
          request(),
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("did not include required usage");
  });

  test("binds terminal response and model identities to response.created", async () => {
    const connector: ModelHttpConnector = {
      async prepare(): Promise<PreparedModelConnection> {
        return {
          evidence: privateEvidence(),
          async send() {
            return sseResponse([
              {
                type: "response.created",
                response: { id: "resp-created", model: "model-a" },
              },
              {
                type: "response.completed",
                response: {
                  id: "resp-substituted",
                  model: "model-b",
                  status: "completed",
                  usage: {
                    input_tokens: 1,
                    output_tokens: 1,
                    total_tokens: 2,
                  },
                },
              },
            ]);
          },
        };
      },
    };
    await expect(
      collect(
        adapter(connector, { MODEL_TOKEN: "token" }).execute(
          request({
            outputFormat: undefined,
            requiredCapabilities: ["usage_accounting"],
          }),
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("response ID does not match");
  });

  test("rejects duplicate terminal events and tool arguments outside the declared schema", async () => {
    const duplicateTerminal: ModelHttpConnector = {
      async prepare(): Promise<PreparedModelConnection> {
        return {
          evidence: privateEvidence(),
          async send() {
            const completed = {
              type: "response.completed",
              response: {
                id: "resp-4",
                status: "completed",
                usage: {
                  input_tokens: 1,
                  output_tokens: 1,
                  total_tokens: 2,
                },
              },
            };
            return sseResponse([completed, completed]);
          },
        };
      },
    };
    await expect(
      collect(
        adapter(duplicateTerminal, { MODEL_TOKEN: "token" }).execute(
          request({
            outputFormat: undefined,
            tools: undefined,
            toolChoice: undefined,
            requiredCapabilities: ["usage_accounting"],
          }),
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("after terminal completion");

    const invalidTool: ModelHttpConnector = {
      async prepare(): Promise<PreparedModelConnection> {
        return {
          evidence: privateEvidence(),
          async send() {
            return sseResponse([
              {
                type: "response.output_item.done",
                item: {
                  type: "function_call",
                  id: "item-invalid",
                  call_id: "call-invalid",
                  name: "inspect",
                  arguments: '{"path":42}',
                },
              },
            ]);
          },
        };
      },
    };
    await expect(
      collect(
        adapter(invalidTool, { MODEL_TOKEN: "token" }).execute(
          request(),
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("did not match schema");
  });
});
