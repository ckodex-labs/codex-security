import {
  Server,
  ServerCredentials,
  type sendUnaryData,
  type ServerUnaryCall,
  type ServerWritableStream,
  type UntypedServiceImplementation,
} from "@grpc/grpc-js";
import { describe, expect, test } from "bun:test";
import type { ModelExecutionEvent } from "../src/kernel/contracts.js";
import {
  MODEL_EXECUTION_GRPC_SERVICE,
  PrivateGrpcModelAdapter,
} from "../src/transport/model/private-grpc.js";
import { createTlsFixture, privateIpv4Address } from "./support/tls-fixture.js";

interface JsonEnvelope {
  json: Buffer;
}

const address = privateIpv4Address();
const liveTest = address === undefined ? test.skip : test;

describe("private gRPC model adapter", () => {
  liveTest(
    "streams normalized events over certificate-pinned TLS",
    async () => {
      if (address === undefined)
        throw new Error("private IPv4 test address missing");
      const liveAddress = address;
      const tls = await createTlsFixture();
      const seen: Record<string, unknown>[] = [];
      const server = new Server();
      const handlers: UntypedServiceImplementation = {
        execute(call: ServerWritableStream<JsonEnvelope, JsonEnvelope>) {
          seen.push(JSON.parse(call.request.json.toString("utf8")));
          for (const event of grpcEvents()) {
            call.write({ json: Buffer.from(JSON.stringify(event)) });
          }
          call.end();
        },
        cancel(
          _call: ServerUnaryCall<JsonEnvelope, JsonEnvelope>,
          callback: sendUnaryData<JsonEnvelope>,
        ) {
          callback(null, { json: Buffer.from("{}") });
        },
      };
      server.addService(MODEL_EXECUTION_GRPC_SERVICE, handlers);
      const port = await bind(
        server,
        liveAddress,
        ServerCredentials.createSsl(
          tls.ca,
          [{ private_key: tls.privateKey, cert_chain: tls.certificate }],
          true,
        ),
      );
      const adapter = new PrivateGrpcModelAdapter({
        providerId: "private-grpc",
        modelId: "fixture-model",
        pinnedAddress: liveAddress,
        port,
        serverName: "model.internal",
        rootCertificate: tls.ca,
        clientCertificate: tls.clientCertificate,
        clientPrivateKey: tls.clientPrivateKey,
        expectedPeerFingerprint: tls.fingerprint,
        features: new Set(["streaming", "usage_accounting", "cancellation"]),
      });
      const events = [];
      try {
        for await (const event of adapter.execute(
          {
            requestId: "grpc-request",
            systemPrompt: "Inspect.",
            input: "Run.",
            requiredCapabilities: ["streaming", "usage_accounting"],
            limits: {
              maxRequestBytes: 4096,
              maxResponseBytes: 4096,
              maxToolArgumentBytes: 1024,
              headerTimeoutMillis: 2000,
              streamIdleTimeoutMillis: 2000,
              wallClockMillis: 5000,
            },
          },
          new AbortController().signal,
        )) {
          events.push(event);
        }
      } finally {
        await shutdown(server);
      }
      expect(seen).toHaveLength(1);
      expect(seen[0]).toMatchObject({
        requestId: "grpc-request",
        input: "Run.",
      });
      expect(events.map((event) => event.kind)).toEqual([
        "response_metadata",
        "usage",
        "completed",
      ]);
    },
  );

  test("rejects public and loopback targets before opening a channel", () => {
    const common = {
      providerId: "private-grpc",
      modelId: "fixture-model",
      port: 443,
      serverName: "model.internal",
      rootCertificate: Buffer.from("ca"),
      expectedPeerFingerprint: `sha256:${"a".repeat(64)}` as const,
      features: new Set(["streaming"] as const),
    };
    expect(
      () =>
        new PrivateGrpcModelAdapter({
          ...common,
          pinnedAddress: "127.0.0.1",
        }),
    ).toThrow("private IP literal");
    expect(
      () =>
        new PrivateGrpcModelAdapter({
          ...common,
          pinnedAddress: "8.8.8.8",
        }),
    ).toThrow("private IP literal");
  });
});

function grpcEvents(): readonly ModelExecutionEvent[] {
  return [
    {
      kind: "response_metadata",
      sequence: 0,
      responseId: "grpc-response",
    },
    {
      kind: "usage",
      sequence: 1,
      inputTokens: 1,
      outputTokens: 1,
      totalTokens: 2,
    },
    {
      kind: "completed",
      sequence: 2,
      finishReason: "stop",
      responseId: "grpc-response",
    },
  ];
}

async function bind(
  server: Server,
  host: string,
  credentials: ServerCredentials,
): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    server.bindAsync(`${host}:0`, credentials, (error, port) => {
      if (error === null) resolve(port);
      else reject(error);
    });
  });
}

async function shutdown(server: Server): Promise<void> {
  await new Promise<void>((resolve) => server.tryShutdown(() => resolve()));
}
