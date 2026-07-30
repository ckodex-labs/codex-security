import { createServer, type RequestListener, type Server } from "node:http";
import { describe, expect, test } from "bun:test";
import type {
  DecisionTrace,
  EvidenceRecord,
  ModelCapabilities,
  ModelExecutionEvent,
  ModelExecutionRequest,
} from "../src/kernel/contracts.js";
import type { ModelExecutionPort } from "../src/kernel/ports.js";
import {
  ModelAdmissionDeniedError,
  ModelEventStreamIncompleteError,
} from "../src/kernel/model-execution-application.js";
import {
  executeComposedModel,
  type ModelExecutionComposition,
} from "../src/transport/composition/model-execution-composition.js";
import { OpenAIResponsesAdapter } from "../src/transport/model/openai-compatible.js";

const request: ModelExecutionRequest = {
  requestId: "request-1",
  systemPrompt: "Inspect the bounded target.",
  input: "Run the scan.",
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

function capabilities(
  features: ModelCapabilities["features"],
): ModelCapabilities {
  return {
    providerId: "private-model-service",
    modelId: "security-model",
    transport: "private_http",
    endpointSecurity: {
      tls: true,
      privateNetwork: true,
      loopbackOnly: false,
      source: "derived",
      endpointIdentityDigest: `sha256:${"a".repeat(64)}`,
    },
    features,
    capabilitySource: "probed",
  };
}

function composition(
  adapter: ModelExecutionPort,
  evidence: EvidenceRecord[],
  traces: DecisionTrace[],
): ModelExecutionComposition {
  return {
    descriptor: {
      kind: "private_http",
      adapterId: "private-service",
    },
    registrations: [
      {
        kind: "private_http" as const,
        adapterId: "private-service",
        create: () => adapter,
      },
    ],
    policy: {
      policyId: "model-admission-v1",
      allowedTransports: ["private_http"] as const,
      requiredCapabilities: request.requiredCapabilities,
      requirePrivateEndpoint: true,
      requireTlsForRemote: true,
      requireDerivedEndpointSecurity: true,
    },
    evidence: {
      record: async (record: EvidenceRecord) => {
        evidence.push(record);
      },
    },
    observer: {
      emit: async (trace: DecisionTrace) => {
        traces.push(trace);
      },
    },
    now: () => "2026-07-29T12:00:00.000Z",
    nextTraceId: () => "trace-host-generated",
  };
}

async function closeServer(server: Server): Promise<void> {
  server.closeAllConnections();
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
  });
}

async function withLoopbackServer<T>(
  listener: RequestListener,
  run: (baseUrl: string) => Promise<T>,
): Promise<T> {
  const server = createServer(listener);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    await closeServer(server);
    throw new Error("loopback server did not expose a TCP address");
  }
  try {
    return await run(`http://127.0.0.1:${address.port}/v1`);
  } finally {
    await closeServer(server);
  }
}

function localAdapter(baseUrl: string): OpenAIResponsesAdapter {
  return new OpenAIResponsesAdapter({
    providerId: "loopback-responses",
    modelId: "security-model",
    baseUrl,
    transport: "local_http",
    features: new Set(["streaming", "cancellation", "usage_accounting"]),
    capabilitySource: "configured",
  });
}

function localComposition(
  adapter: OpenAIResponsesAdapter,
  evidence: EvidenceRecord[],
  traces: DecisionTrace[],
): ModelExecutionComposition {
  return {
    descriptor: { kind: "local_http", adapterId: "loopback-responses" },
    registrations: [
      {
        kind: "local_http",
        adapterId: "loopback-responses",
        create: () => adapter,
      },
    ],
    policy: {
      policyId: "loopback-model-admission-v1",
      allowedTransports: ["local_http"],
      requiredCapabilities: request.requiredCapabilities,
      requirePrivateEndpoint: true,
      requireTlsForRemote: true,
      requireDerivedEndpointSecurity: true,
    },
    evidence: { record: async (record) => void evidence.push(record) },
    observer: { emit: async (trace) => void traces.push(trace) },
    now: () => "2026-07-29T12:00:00.000Z",
    nextTraceId: () => "trace-loopback-host",
  };
}

async function collectEvents(
  iterable: AsyncIterable<ModelExecutionEvent>,
): Promise<ModelExecutionEvent[]> {
  const events: ModelExecutionEvent[] = [];
  for await (const event of iterable) events.push(event);
  return events;
}

function writeSse(
  response: import("node:http").ServerResponse,
  value: unknown,
) {
  response.write(`data: ${JSON.stringify(value)}\n\n`);
}

describe("four-space model execution composition", () => {
  test("records a denial and performs zero adapter execution", async () => {
    let executions = 0;
    const evidence: EvidenceRecord[] = [];
    const traces: DecisionTrace[] = [];
    const adapter: ModelExecutionPort = {
      capabilities: async () => capabilities(new Set(["streaming"])),
      execute: async function* () {
        executions += 1;
        yield {
          kind: "completed",
          sequence: 0,
          finishReason: "stop",
          responseId: "must-not-run",
        };
      },
      cancel: async () => {},
    };

    const consume = async () => {
      for await (const _event of executeComposedModel(
        composition(adapter, evidence, traces),
        request,
        new AbortController().signal,
      )) {
        // A denied provider must not produce any event.
      }
    };

    await expect(consume()).rejects.toBeInstanceOf(ModelAdmissionDeniedError);
    expect(executions).toBe(0);
    expect(evidence).toHaveLength(1);
    expect(evidence[0]?.trace.verdict).toBe("deny");
    expect(traces).toHaveLength(1);
  });

  test("combines request capabilities with policy requirements", async () => {
    let executions = 0;
    const evidence: EvidenceRecord[] = [];
    const traces: DecisionTrace[] = [];
    const adapter: ModelExecutionPort = {
      capabilities: async () => capabilities(new Set(["streaming"])),
      execute: async function* () {
        executions += 1;
        yield {
          kind: "completed",
          sequence: 0,
          finishReason: "stop",
          responseId: "must-not-run",
        };
      },
      cancel: async () => {},
    };
    const configured = composition(adapter, evidence, traces);
    configured.policy.requiredCapabilities = [];

    const consume = async () => {
      for await (const _event of executeComposedModel(
        configured,
        request,
        new AbortController().signal,
      )) {
        // Request requirements remain mandatory even under a weaker policy.
      }
    };

    await expect(consume()).rejects.toBeInstanceOf(ModelAdmissionDeniedError);
    expect(executions).toBe(0);
    expect(evidence[0]?.trace.reasons).toContain(
      "required capability usage_accounting is unavailable",
    );
  });

  test("denies an adapter whose observed transport contradicts its descriptor", async () => {
    let executions = 0;
    const evidence: EvidenceRecord[] = [];
    const adapter: ModelExecutionPort = {
      capabilities: async () => ({
        ...capabilities(new Set(["streaming", "usage_accounting"])),
        transport: "hosted_api",
      }),
      execute: async function* () {
        executions += 1;
        yield {
          kind: "completed",
          sequence: 0,
          finishReason: "stop",
          responseId: "must-not-run",
        };
      },
      cancel: async () => {},
    };
    const configured = composition(adapter, evidence, []);
    configured.policy.allowedTransports = ["private_http", "hosted_api"];
    const consume = async () => {
      for await (const _event of executeComposedModel(
        configured,
        request,
        new AbortController().signal,
      )) {
        // Descriptor and observed transport must remain bound.
      }
    };

    await expect(consume()).rejects.toBeInstanceOf(ModelAdmissionDeniedError);
    expect(executions).toBe(0);
    expect(evidence[0]?.trace.reasons).toContain(
      "transport hosted_api is not allowed",
    );
  });

  test("cancels an admitted execution whose stream ends without a terminal event", async () => {
    const canceled: string[] = [];
    const adapter: ModelExecutionPort = {
      capabilities: async () =>
        capabilities(new Set(["streaming", "usage_accounting"])),
      execute: async function* () {
        yield { kind: "output_delta", sequence: 0, text: "partial" };
      },
      cancel: async (requestId) => {
        canceled.push(requestId);
      },
    };
    const consume = async () => {
      for await (const _event of executeComposedModel(
        composition(adapter, [], []),
        request,
        new AbortController().signal,
      )) {
        // Consume the incomplete stream to exercise terminal enforcement.
      }
    };

    await expect(consume()).rejects.toBeInstanceOf(
      ModelEventStreamIncompleteError,
    );
    expect(canceled).toEqual(["request-1"]);
  });

  test("carries real loopback SSE events through evidence-gated composition", async () => {
    const order: string[] = [];
    const evidence: EvidenceRecord[] = [];
    const traces: DecisionTrace[] = [];
    await withLoopbackServer(
      (_incoming, response) => {
        order.push("request");
        response.writeHead(200, {
          "content-type": "text/event-stream",
          "x-request-id": "loopback-request-1",
        });
        writeSse(response, {
          type: "response.created",
          response: { id: "response-loopback", model: "security-model" },
        });
        writeSse(response, {
          type: "response.output_text.delta",
          delta: "live",
        });
        writeSse(response, {
          type: "response.completed",
          response: {
            id: "response-loopback",
            model: "security-model",
            status: "completed",
            usage: {
              input_tokens: 4,
              output_tokens: 1,
              total_tokens: 5,
            },
          },
        });
        response.end();
      },
      async (baseUrl) => {
        const configured = localComposition(
          localAdapter(baseUrl),
          evidence,
          traces,
        );
        configured.evidence.record = async (record) => {
          order.push("evidence");
          evidence.push(record);
        };
        configured.observer.emit = async (trace) => {
          order.push("observe");
          traces.push(trace);
        };
        const events = await collectEvents(
          executeComposedModel(
            configured,
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
        expect(events.map((event) => event.sequence)).toEqual([0, 1, 2, 3]);
        expect(evidence[0]?.trace).toMatchObject({
          verdict: "allow",
          providerId: "loopback-responses",
          transport: "local_http",
        });
        expect(traces).toEqual([evidence[0]!.trace]);
      },
    );
  });

  test("aborts a real loopback stream and releases the active request ID", async () => {
    let requests = 0;
    let firstResponse: import("node:http").ServerResponse | undefined;
    await withLoopbackServer(
      (_incoming, response) => {
        requests += 1;
        response.writeHead(200, { "content-type": "text/event-stream" });
        if (requests === 1) {
          firstResponse = response;
          writeSse(response, {
            type: "response.created",
            response: { id: "response-cancel", model: "security-model" },
          });
          return;
        }
        writeSse(response, {
          type: "response.completed",
          response: {
            id: "response-after-cancel",
            status: "completed",
            usage: {
              input_tokens: 1,
              output_tokens: 1,
              total_tokens: 2,
            },
          },
        });
        response.end();
      },
      async (baseUrl) => {
        const controller = new AbortController();
        const adapter = localAdapter(baseUrl);
        const configured = localComposition(adapter, [], []);
        const iterator = executeComposedModel(
          configured,
          request,
          controller.signal,
        )[Symbol.asyncIterator]();
        expect((await iterator.next()).value?.kind).toBe("response_metadata");
        controller.abort();
        expect(await iterator.next()).toEqual({
          done: false,
          value: {
            kind: "canceled",
            sequence: 1,
            reason: "operation aborted",
          },
        });
        expect((await iterator.next()).done).toBe(true);
        firstResponse?.end();
        const retry = await collectEvents(
          executeComposedModel(
            configured,
            request,
            new AbortController().signal,
          ),
        );
        expect(retry.at(-1)?.kind).toBe("completed");
        expect(requests).toBe(2);
      },
    );
  });

  test("releases the actual adapter after an incomplete loopback stream", async () => {
    let requests = 0;
    await withLoopbackServer(
      (_incoming, response) => {
        requests += 1;
        response.writeHead(200, { "content-type": "text/event-stream" });
        writeSse(response, {
          type: "response.created",
          response: { id: `response-incomplete-${requests}` },
        });
        response.end();
      },
      async (baseUrl) => {
        const adapter = localAdapter(baseUrl);
        const configured = localComposition(adapter, [], []);
        const execute = async () =>
          await collectEvents(
            executeComposedModel(
              configured,
              request,
              new AbortController().signal,
            ),
          );

        await expect(execute()).rejects.toThrow(
          "model stream ended without a terminal completion",
        );
        await expect(execute()).rejects.toThrow(
          "model stream ended without a terminal completion",
        );
        expect(requests).toBe(2);
      },
    );
  });
});
