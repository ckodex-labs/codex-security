import { createServer, type Server } from "node:https";
import { describe, expect, test } from "bun:test";
import type { ModelExecutionRequest } from "../src/kernel/contracts.js";
import { executeModelApplication } from "../src/kernel/model-execution-application.js";
import { createDecisionEvidence } from "../src/proof/decision-trace.js";
import { OpenAIResponsesAdapter } from "../src/transport/model/openai-compatible.js";
import { PinnedTlsHttpConnector } from "../src/transport/model/pinned-tls.js";
import { validateModelCapabilities } from "../src/validation/model-capabilities.js";
import { createTlsFixture, privateIpv4Address } from "./support/tls-fixture.js";

const address = privateIpv4Address();
const liveTest = address === undefined ? test.skip : test;

describe("pinned private-DNS TLS connector", () => {
  liveTest("uses one resolution and one admitted TLS connection", async () => {
    if (address === undefined)
      throw new Error("private IPv4 test address missing");
    const liveAddress = address;
    const tls = await createTlsFixture();
    let requests = 0;
    const server = createServer(
      { key: tls.privateKey, cert: tls.certificate },
      (_request, response) => {
        requests += 1;
        response.writeHead(200, { "content-type": "text/event-stream" });
        response.write(
          `data: ${JSON.stringify({
            type: "response.created",
            response: { id: "resp-tls", model: "private-model" },
          })}\n\n`,
        );
        response.end(
          `data: ${JSON.stringify({
            type: "response.completed",
            response: {
              id: "resp-tls",
              model: "private-model",
              status: "completed",
              usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
            },
          })}\n\n`,
        );
      },
    );
    const port = await listen(server, liveAddress);
    let resolutions = 0;
    const connector = new PinnedTlsHttpConnector(
      {
        pinnedAddress: liveAddress,
        ca: tls.ca,
        expectedPeerFingerprint: tls.fingerprint,
      },
      {
        resolve: async () => {
          resolutions += 1;
          return [{ address: liveAddress, family: 4 }];
        },
      },
    );
    const adapter = new OpenAIResponsesAdapter(
      {
        providerId: "private-dns",
        modelId: "private-model",
        baseUrl: `https://model.internal:${port}/v1`,
        transport: "private_http",
        features: new Set(["streaming", "usage_accounting"]),
        capabilitySource: "configured",
      },
      { connector },
    );
    const events = [];
    let admittedFingerprint: string | undefined;
    try {
      for await (const event of executeModelApplication(
        {
          model: adapter,
          evidence: { record: async () => {} },
          observer: { emit: async () => {} },
          admit: ({ capabilities, request }) => {
            admittedFingerprint =
              capabilities.endpointSecurity.peerCertificateFingerprint;
            return validateModelCapabilities(capabilities, {
              policyId: "private-tls",
              allowedTransports: ["private_http"],
              requiredCapabilities: request.requiredCapabilities,
              requirePrivateEndpoint: true,
              requireTlsForRemote: true,
              requireDerivedEndpointSecurity: true,
            });
          },
          createEvidence: createDecisionEvidence,
          now: () => "2026-07-29T00:00:00.000Z",
          nextTraceId: () => "trace-tls",
        },
        modelRequest(),
        new AbortController().signal,
      )) {
        events.push(event);
      }
    } finally {
      await close(server);
    }
    expect(resolutions).toBe(1);
    expect(requests).toBe(1);
    expect(admittedFingerprint).toBe(tls.fingerprint);
    expect(events[0]).toMatchObject({
      kind: "response_metadata",
      peerCertificateFingerprint: tls.fingerprint,
    });
  });
});

function modelRequest(): ModelExecutionRequest {
  return {
    requestId: "tls-request",
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
  };
}

async function listen(server: Server, host: string): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => {
      const bound = server.address();
      if (bound === null || typeof bound === "string") {
        reject(new Error("TLS fixture did not expose a port"));
      } else {
        resolve(bound.port);
      }
    });
  });
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}
