import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type {
  ModelExecutionEvent,
  ModelExecutionRequest,
} from "../src/kernel/contracts.js";
import type { ModelHttpConnector } from "../src/transport/model/endpoint-security.js";
import { OpenAIResponsesAdapter } from "../src/transport/model/openai-compatible.js";
import { ClosingLoopbackConnector } from "./model-live-connector.test.js";

interface CapturedRequest {
  input: string;
  headers: IncomingMessage["headers"];
  body: Record<string, unknown>;
}

const limits = {
  maxRequestBytes: 64 * 1024,
  maxResponseBytes: 64 * 1024,
  maxToolArgumentBytes: 4 * 1024,
  headerTimeoutMillis: 2_000,
  streamIdleTimeoutMillis: 2_000,
  wallClockMillis: 5_000,
} as const;

let server: Server;
let baseUrl: string;
const captured: CapturedRequest[] = [];

beforeAll(async () => {
  server = createServer((request, response) => {
    void handleRequest(request, response);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("live model server did not expose an address");
  }
  baseUrl = `http://127.0.0.1:${address.port}/v1`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function adapter(connector?: ModelHttpConnector) {
  return new OpenAIResponsesAdapter(
    {
      providerId: "live-loopback",
      modelId: "model-live",
      baseUrl,
      transport: "local_http",
      credential: { environmentVariable: "LIVE_MODEL_TOKEN" },
      features: new Set([
        "streaming",
        "structured_output",
        "tool_calling",
        "cancellation",
        "usage_accounting",
      ]),
      capabilitySource: "configured",
    },
    {
      environment: { LIVE_MODEL_TOKEN: "live-secret" },
      ...(connector === undefined ? {} : { connector }),
    },
  );
}

function modelRequest(
  input: string,
  overrides: Partial<ModelExecutionRequest> = {},
): ModelExecutionRequest {
  return {
    requestId: `live-${input}`,
    systemPrompt: "Return the strict result.",
    input,
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
        description: "Inspect a path.",
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
      name: "live_result",
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

async function collect(
  events: AsyncIterable<ModelExecutionEvent>,
): Promise<ModelExecutionEvent[]> {
  const values = [];
  for await (const event of events) values.push(event);
  return values;
}

describe("live loopback model adapter", () => {
  test("streams the complete Responses contract over a real socket", async () => {
    const client = adapter();
    const capabilities = await client.capabilities();
    expect(capabilities.endpointSecurity).toMatchObject({
      source: "derived",
      loopbackOnly: true,
      privateNetwork: true,
      tls: false,
    });

    const events = await collect(
      client.execute(modelRequest("success"), new AbortController().signal),
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
      responseId: "resp-live",
      providerRequestId: "socket-request-live",
      returnedModelId: "model-live-returned",
    });
    expect(events[1]).toMatchObject({
      callId: "call-live",
      name: "inspect",
      argumentsJson: '{"path":"src"}',
    });
    expect(events[3]).toMatchObject({ value: { ok: true } });
    expect(events[4]).toMatchObject({
      inputTokens: 11,
      outputTokens: 4,
      cachedInputTokens: 3,
      totalTokens: 15,
    });

    const request = captured.find((item) => item.input === "success");
    expect(request?.headers.authorization).toBe("Bearer live-secret");
    expect(request?.headers.accept).toBe("text/event-stream");
    expect(request?.body).toMatchObject({
      model: "model-live",
      stream: true,
      input: "success",
      tool_choice: { type: "function", name: "inspect" },
      text: { format: { type: "json_schema", strict: true } },
    });
  });

  test("aborts the real response socket and releases the request ID", async () => {
    const connector = new ClosingLoopbackConnector();
    const client = adapter(connector);
    const request = modelRequest("hang", { requestId: "live-reusable" });
    const iterator = client
      .execute(request, new AbortController().signal)
      [Symbol.asyncIterator]();
    expect(await iterator.next()).toMatchObject({
      done: false,
      value: { kind: "response_metadata", responseId: "resp-hang" },
    });
    await client.cancel("live-reusable");
    expect(await iterator.next()).toEqual({
      done: false,
      value: { kind: "canceled", sequence: 1, reason: "operation aborted" },
    });
    expect(await iterator.next()).toEqual({ done: true, value: undefined });
    await withTimeout(
      connector.closed,
      2_000,
      "canceled client socket did not close",
    );

    const replay = client
      .execute(
        modelRequest("hang", { requestId: "live-reusable" }),
        new AbortController().signal,
      )
      [Symbol.asyncIterator]();
    expect(await replay.next()).toMatchObject({
      value: { kind: "response_metadata", responseId: "resp-hang" },
    });
    await client.cancel("live-reusable");
    expect(await replay.next()).toMatchObject({
      value: { kind: "canceled", sequence: 1 },
    });
  });

  test("continues a tool call over the real loopback Responses protocol", async () => {
    const events = await collect(
      adapter().execute(
        modelRequest("continuation-placeholder", {
          requestId: "live-continuation",
          continuation: {
            previousResponseId: "resp-live",
            outputs: [{ callId: "call-live", output: '{"result":"safe"}' }],
          },
          tools: undefined,
          toolChoice: undefined,
          outputFormat: undefined,
          requiredCapabilities: ["streaming", "usage_accounting"],
        }),
        new AbortController().signal,
      ),
    );
    expect(events.map((event) => event.kind)).toEqual([
      "response_metadata",
      "usage",
      "completed",
    ]);
    const request = captured.find((item) => item.input === "continuation");
    expect(request?.body).toMatchObject({
      previous_response_id: "resp-live",
      input: [
        {
          type: "function_call_output",
          call_id: "call-live",
          output: '{"result":"safe"}',
        },
      ],
    });
  });

  test("rejects redirects and bounded HTTP failures without leaking secrets", async () => {
    const client = adapter();
    await expect(
      collect(
        client.execute(
          modelRequest("redirect", {
            outputFormat: undefined,
            tools: undefined,
            toolChoice: undefined,
            requiredCapabilities: ["streaming"],
          }),
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("redirects are forbidden");
    expect(captured.filter((item) => item.input === "redirect")).toHaveLength(
      1,
    );

    let failure: Error | undefined;
    try {
      await collect(
        client.execute(
          modelRequest("error", {
            outputFormat: undefined,
            tools: undefined,
            toolChoice: undefined,
            requiredCapabilities: ["streaming"],
          }),
          new AbortController().signal,
        ),
      );
    } catch (error) {
      failure = error as Error;
    }
    expect(failure?.message).toBe("model endpoint returned HTTP 500");
    expect(failure?.message).not.toContain("live-secret");

    await expect(
      collect(
        client.execute(
          modelRequest("oversized", {
            outputFormat: undefined,
            tools: undefined,
            toolChoice: undefined,
            requiredCapabilities: ["streaming"],
            limits: { ...limits, maxResponseBytes: 128 },
          }),
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("declared an invalid byte length");
  });
});

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<
    string,
    unknown
  >;
  const input =
    typeof body["input"] === "string"
      ? body["input"]
      : body["previous_response_id"] === "resp-live"
        ? "continuation"
        : "";
  captured.push({ input, headers: request.headers, body });

  if (input === "redirect") {
    response.writeHead(307, { location: "http://127.0.0.1:1/stolen" });
    response.end();
    return;
  }
  if (input === "error") {
    response.writeHead(500, { "content-type": "text/plain" });
    response.end(`live-secret ${"x".repeat(256 * 1024)}`);
    return;
  }
  if (input === "oversized") {
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "content-length": "9999",
    });
    response.end("data: {}\n\n");
    return;
  }
  if (input === "hang") {
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "x-request-id": "socket-request-hang",
      connection: "close",
      "content-length": "4096",
    });
    response.flushHeaders();
    response.write(
      sse({
        type: "response.created",
        response: { id: "resp-hang", model: "model-live-returned" },
      }),
    );
    return;
  }
  if (input === "continuation") {
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.write(
      sse({
        type: "response.created",
        response: { id: "resp-continued", model: "model-live-returned" },
      }),
    );
    response.end(
      sse({
        type: "response.completed",
        response: {
          id: "resp-continued",
          model: "model-live-returned",
          status: "completed",
          usage: { input_tokens: 2, output_tokens: 1, total_tokens: 3 },
        },
      }),
    );
    return;
  }

  response.writeHead(200, {
    "content-type": "text/event-stream",
    "x-request-id": "socket-request-live",
  });
  response.flushHeaders();
  const stream = [
    sse({
      type: "response.created",
      response: { id: "resp-live", model: "model-live-returned" },
    }),
    sse({
      type: "response.output_item.added",
      item: {
        type: "function_call",
        id: "item-live",
        call_id: "call-live",
        name: "inspect",
        arguments: "",
      },
    }),
    sse({
      type: "response.function_call_arguments.done",
      item_id: "item-live",
      arguments: '{"path":"src"}',
    }),
    sse({ type: "response.output_text.delta", delta: '{"ok":true}' }),
    sse({
      type: "response.completed",
      response: {
        id: "resp-live",
        model: "model-live-returned",
        status: "completed",
        usage: {
          input_tokens: 11,
          output_tokens: 4,
          total_tokens: 15,
          input_tokens_details: { cached_tokens: 3 },
        },
      },
    }),
    "data: [DONE]\n\n",
  ].join("");
  for (const chunk of splitAcrossProtocolBoundaries(stream)) {
    response.write(chunk);
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  response.end();
}

function sse(value: unknown): string {
  return `data: ${JSON.stringify(value)}\r\n\r\n`;
}

function splitAcrossProtocolBoundaries(value: string): string[] {
  const chunks: string[] = [];
  const sizes = [1, 7, 2, 19, 3, 5, 11];
  let offset = 0;
  let index = 0;
  while (offset < value.length) {
    const next = Math.min(value.length, offset + (sizes[index] ?? 1));
    chunks.push(value.slice(offset, next));
    offset = next;
    index = (index + 1) % sizes.length;
  }
  return chunks;
}

async function withTimeout(
  promise: Promise<void>,
  milliseconds: number,
  message: string,
): Promise<void> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error(message)), milliseconds);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}
