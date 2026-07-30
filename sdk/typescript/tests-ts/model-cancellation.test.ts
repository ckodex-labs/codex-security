import { describe, expect, test } from "bun:test";
import type {
  ModelExecutionEvent,
  ModelExecutionRequest,
} from "../src/kernel/contracts.js";
import type {
  ModelHttpConnector,
  PreparedModelConnection,
} from "../src/transport/model/endpoint-security.js";
import { OpenAIResponsesAdapter } from "../src/transport/model/openai-compatible.js";

const limits = {
  maxRequestBytes: 1024,
  maxResponseBytes: 1024,
  maxToolArgumentBytes: 512,
  headerTimeoutMillis: 1_000,
  streamIdleTimeoutMillis: 1_000,
  wallClockMillis: 2_000,
} as const;

function request(overrides: Partial<ModelExecutionRequest> = {}) {
  return {
    requestId: "cancellation-request",
    systemPrompt: "System",
    input: "Input",
    requiredCapabilities: ["streaming", "cancellation"],
    limits,
    ...overrides,
  } satisfies ModelExecutionRequest;
}

function adapter(connector: ModelHttpConnector) {
  return new OpenAIResponsesAdapter(
    {
      providerId: "private-provider",
      modelId: "model-a",
      baseUrl: "https://models.internal/v1",
      transport: "private_http",
      features: new Set(["streaming", "cancellation"]),
      capabilitySource: "configured",
    },
    { connector },
  );
}

async function collect(
  iterable: AsyncIterable<ModelExecutionEvent>,
): Promise<ModelExecutionEvent[]> {
  const events = [];
  for await (const event of iterable) events.push(event);
  return events;
}

describe("model request cancellation and deadlines", () => {
  test("short-circuits pre-aborted requests and reports deadlines as errors", async () => {
    let preparations = 0;
    const connector: ModelHttpConnector = {
      async prepare(): Promise<PreparedModelConnection> {
        preparations += 1;
        return {
          evidence: {
            resolvedAddress: "10.20.30.40",
            addressPinned: true,
            tlsAuthenticated: true,
          },
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
    const aborted = new AbortController();
    aborted.abort();
    expect(
      await collect(adapter(connector).execute(request(), aborted.signal)),
    ).toEqual([{ kind: "canceled", sequence: 0, reason: "operation aborted" }]);
    expect(preparations).toBe(0);

    await expect(
      collect(
        adapter(connector).execute(
          request({
            requestId: "deadline-request",
            limits: { ...limits, wallClockMillis: 10 },
          }),
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("exceeded its deadline");
  });
});
