import { createServer } from "node:http";
import { describe, expect, test } from "bun:test";
import type {
  DecisionTrace,
  EvidenceRecord,
  ModelCapabilities,
  ModelExecutionEvent,
  ModelExecutionRequest,
} from "../src/kernel/contracts.js";
import type { ModelExecutionPort } from "../src/kernel/ports.js";
import { ModelAdmissionDeniedError } from "../src/kernel/model-execution-application.js";
import { executeComposedModel } from "../src/transport/composition/model-execution-composition.js";
import { OpenAIResponsesAdapter } from "../src/transport/model/openai-compatible.js";
import {
  DuplicateModelProviderRegistrationError,
  InvalidModelProviderDescriptorError,
  requireModelProviderDescriptor,
  resolveModelProvider,
  UnknownModelProviderError,
} from "../src/transport/composition/provider-selection.js";

function inertAdapter(): ModelExecutionPort {
  return {
    capabilities: async (): Promise<ModelCapabilities> => {
      throw new Error("not used");
    },
    execute: async function* (
      _request: ModelExecutionRequest,
      _signal: AbortSignal,
    ): AsyncGenerator<ModelExecutionEvent> {
      throw new Error("not used");
    },
    cancel: async () => {},
  };
}

async function withCountingServer(
  run: (baseUrl: string, requests: () => number) => Promise<void>,
): Promise<void> {
  let requestCount = 0;
  const server = createServer((_incoming, response) => {
    requestCount += 1;
    response.writeHead(500).end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("loopback server did not expose a TCP address");
  }
  try {
    await run(`http://127.0.0.1:${address.port}/v1`, () => requestCount);
  } finally {
    server.closeAllConnections();
    if (server.listening) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) =>
          error === undefined ? resolve() : reject(error),
        );
      });
    }
  }
}

describe("four-space provider selection", () => {
  test("resolves only an exact kind and adapter identifier", () => {
    const adapter = inertAdapter();
    const descriptor = requireModelProviderDescriptor({
      kind: "local_http",
      adapterId: "ollama-loopback",
    });
    const resolved = resolveModelProvider(descriptor, [
      {
        kind: "local_http",
        adapterId: "ollama-loopback",
        create: () => adapter,
      },
    ]);
    expect(resolved).toBe(adapter);
  });

  test("rejects unknown provider kinds before an adapter can be created", () => {
    let creations = 0;
    expect(() =>
      requireModelProviderDescriptor({
        kind: "implicit-network-provider",
        adapterId: "default",
      }),
    ).toThrow(InvalidModelProviderDescriptorError);
    expect(creations).toBe(0);
  });

  test("rejects unregistered adapters without falling back by kind", () => {
    let creations = 0;
    const descriptor = requireModelProviderDescriptor({
      kind: "private_http",
      adapterId: "missing",
    });
    expect(() =>
      resolveModelProvider(descriptor, [
        {
          kind: "private_http",
          adapterId: "approved",
          create: () => {
            creations += 1;
            return inertAdapter();
          },
        },
      ]),
    ).toThrow(UnknownModelProviderError);
    expect(creations).toBe(0);
  });

  test("rejects duplicate exact registrations instead of choosing by order", () => {
    const descriptor = requireModelProviderDescriptor({
      kind: "hosted_api",
      adapterId: "codex",
    });
    const registration = {
      kind: "hosted_api" as const,
      adapterId: "codex",
      create: inertAdapter,
    };
    expect(() =>
      resolveModelProvider(descriptor, [registration, registration]),
    ).toThrow(DuplicateModelProviderRegistrationError);
  });

  test("rejects extra descriptor fields so endpoint security cannot be asserted ad hoc", () => {
    expect(() =>
      requireModelProviderDescriptor({
        kind: "local_http",
        adapterId: "ollama-loopback",
        loopbackOnly: true,
      }),
    ).toThrow(InvalidModelProviderDescriptorError);
  });

  test("rejects noncanonical adapter identifiers", () => {
    expect(() =>
      requireModelProviderDescriptor({
        kind: "local_process",
        adapterId: " local-model ",
      }),
    ).toThrow(InvalidModelProviderDescriptorError);
  });

  test("unknown and denied real adapters make zero loopback requests", async () => {
    await withCountingServer(async (baseUrl, requests) => {
      const adapter = new OpenAIResponsesAdapter({
        providerId: "loopback-denied",
        modelId: "security-model",
        baseUrl,
        transport: "local_http",
        features: new Set(["streaming"]),
        capabilitySource: "configured",
      });
      const evidence: EvidenceRecord[] = [];
      const traces: DecisionTrace[] = [];
      const base = {
        registrations: [
          {
            kind: "local_http" as const,
            adapterId: "loopback",
            create: () => adapter,
          },
        ],
        policy: {
          policyId: "loopback-deny-v1",
          allowedTransports: ["local_http"] as const,
          requiredCapabilities: ["streaming", "usage_accounting"] as const,
          requirePrivateEndpoint: true,
          requireTlsForRemote: true,
          requireDerivedEndpointSecurity: true,
        },
        evidence: {
          record: async (record: EvidenceRecord) => void evidence.push(record),
        },
        observer: {
          emit: async (trace: DecisionTrace) => void traces.push(trace),
        },
        now: () => "2026-07-29T12:00:00.000Z",
        nextTraceId: () => "trace-denied-loopback",
      };
      const executionRequest: ModelExecutionRequest = {
        requestId: "denied-loopback",
        systemPrompt: "System",
        input: "Input",
        requiredCapabilities: ["streaming", "usage_accounting"],
        limits: {
          maxRequestBytes: 1024,
          maxResponseBytes: 1024,
          maxToolArgumentBytes: 512,
          headerTimeoutMillis: 1000,
          streamIdleTimeoutMillis: 1000,
          wallClockMillis: 2000,
        },
      };

      expect(() =>
        executeComposedModel(
          {
            ...base,
            descriptor: { kind: "local_http", adapterId: "unknown" },
          },
          executionRequest,
          new AbortController().signal,
        ),
      ).toThrow(UnknownModelProviderError);
      expect(requests()).toBe(0);

      const denied = async () => {
        for await (const _event of executeComposedModel(
          {
            ...base,
            descriptor: { kind: "local_http", adapterId: "loopback" },
          },
          executionRequest,
          new AbortController().signal,
        )) {
          // A denied adapter must not reach the network.
        }
      };
      await expect(denied()).rejects.toBeInstanceOf(ModelAdmissionDeniedError);
      expect(requests()).toBe(0);
      expect(evidence[0]?.trace.verdict).toBe("deny");
      expect(traces).toEqual([evidence[0]!.trace]);
    });
  });
});
