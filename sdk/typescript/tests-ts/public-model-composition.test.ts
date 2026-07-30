import { createServer, type Server, type ServerResponse } from "node:http";
import { describe, expect, test } from "bun:test";
import {
  executeComposedModel,
  OpenAIResponsesAdapter,
  type DecisionTrace,
  type EvidenceRecord,
  type ModelExecutionComposition,
  type ModelExecutionEvent,
  type ModelExecutionRequest,
} from "../src/index.js";

const request: ModelExecutionRequest = {
  requestId: "public-request-1",
  systemPrompt: "Inspect the bounded target.",
  input: "Return the result.",
  requiredCapabilities: ["streaming", "usage_accounting"],
  limits: {
    maxRequestBytes: 1024,
    maxResponseBytes: 4096,
    maxToolArgumentBytes: 1024,
    headerTimeoutMillis: 1000,
    streamIdleTimeoutMillis: 1000,
    wallClockMillis: 5000,
  },
};

async function closeServer(server: Server): Promise<void> {
  server.closeAllConnections();
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}

async function collect(
  events: AsyncIterable<ModelExecutionEvent>,
): Promise<ModelExecutionEvent[]> {
  const collected: ModelExecutionEvent[] = [];
  for await (const event of events) collected.push(event);
  return collected;
}

function writeSse(response: ServerResponse, value: unknown): void {
  response.write(`data: ${JSON.stringify(value)}\n\n`);
}

async function startResponsesServer(order: string[]): Promise<{
  server: Server;
  baseUrl: string;
}> {
  const server = createServer((_incoming, response) => {
    order.push("request");
    response.writeHead(200, { "content-type": "text/event-stream" });
    writeSse(response, {
      type: "response.created",
      response: { id: "response-public", model: "public-model" },
    });
    writeSse(response, {
      type: "response.output_text.delta",
      delta: "public",
    });
    writeSse(response, {
      type: "response.completed",
      response: {
        id: "response-public",
        model: "public-model",
        status: "completed",
        usage: { input_tokens: 2, output_tokens: 1, total_tokens: 3 },
      },
    });
    response.end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address !== null && typeof address !== "string") {
    return { server, baseUrl: `http://127.0.0.1:${address.port}/v1` };
  }
  await closeServer(server);
  throw new Error("loopback server did not expose a TCP address");
}

function publicComposition(
  baseUrl: string,
  order: string[],
  evidence: EvidenceRecord[],
  traces: DecisionTrace[],
): ModelExecutionComposition {
  const adapter = new OpenAIResponsesAdapter({
    providerId: "public-loopback",
    modelId: "public-model",
    baseUrl,
    transport: "local_http",
    features: new Set(["streaming", "cancellation", "usage_accounting"]),
    capabilitySource: "configured",
  });
  return {
    descriptor: { kind: "local_http", adapterId: "public-loopback" },
    registrations: [
      {
        kind: "local_http",
        adapterId: "public-loopback",
        create: () => adapter,
      },
    ],
    policy: {
      policyId: "public-model-admission-v1",
      allowedTransports: ["local_http"],
      requiredCapabilities: request.requiredCapabilities,
      requirePrivateEndpoint: true,
      requireTlsForRemote: true,
      requireDerivedEndpointSecurity: true,
    },
    evidence: {
      record: async (record) => {
        order.push("evidence");
        evidence.push(record);
      },
    },
    observer: {
      emit: async (trace) => {
        order.push("observe");
        traces.push(trace);
      },
    },
    now: () => "2026-07-29T12:00:00.000Z",
    nextTraceId: () => "trace-public-loopback",
  };
}

describe("public model composition", () => {
  test("executes an evidence-gated loopback Responses adapter from package-root exports", async () => {
    const order: string[] = [];
    const evidence: EvidenceRecord[] = [];
    const traces: DecisionTrace[] = [];
    const { server, baseUrl } = await startResponsesServer(order);
    try {
      const events = await collect(
        executeComposedModel(
          publicComposition(baseUrl, order, evidence, traces),
          request,
          new AbortController().signal,
        ),
      );

      expect(order).toEqual(["evidence", "observe", "request"]);
      expect(events.map((event) => event.kind)).toEqual([
        "response_metadata",
        "output_delta",
        "usage",
        "completed",
      ]);
      expect(evidence[0]?.trace).toMatchObject({
        traceId: "trace-public-loopback",
        verdict: "allow",
        providerId: "public-loopback",
        modelId: "public-model",
        transport: "local_http",
      });
      expect(traces).toEqual([evidence[0]!.trace]);
    } finally {
      await closeServer(server);
    }
  });
});
