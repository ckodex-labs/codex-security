import { describe, expect, test } from "bun:test";
import type { ModelExecutionRequest } from "../src/kernel/contracts.js";
import {
  buildRequestBody,
  validateRequest,
} from "../src/transport/model/responses-protocol.js";
import { validateModelConfig } from "../src/transport/model/model-config.js";

const limits = {
  maxRequestBytes: 4096,
  maxResponseBytes: 4096,
  maxToolArgumentBytes: 128,
  headerTimeoutMillis: 1000,
  streamIdleTimeoutMillis: 1000,
  wallClockMillis: 2000,
};

function continuationRequest(): ModelExecutionRequest {
  return {
    requestId: "request-continuation",
    systemPrompt: "Continue.",
    input: "",
    continuation: {
      previousResponseId: "resp-1",
      outputs: [{ callId: "call-1", output: '{"safe":true}' }],
    },
    requiredCapabilities: ["streaming", "tool_calling"],
    tools: [
      {
        name: "inspect",
        description: "Inspect.",
        inputSchema: { type: "object" },
      },
    ],
    limits,
  };
}

describe("model tool continuation", () => {
  test("projects validated function results onto the Responses protocol", () => {
    const request = continuationRequest();
    validateRequest(request);
    const config = validateModelConfig({
      providerId: "local",
      modelId: "model-a",
      baseUrl: "http://127.0.0.1:8080/v1",
      transport: "local_http",
      features: new Set(["streaming", "tool_calling"]),
      capabilitySource: "configured",
    });
    expect(buildRequestBody(config, request)).toMatchObject({
      previous_response_id: "resp-1",
      input: [
        {
          type: "function_call_output",
          call_id: "call-1",
          output: '{"safe":true}',
        },
      ],
    });
  });

  test("rejects duplicate calls and oversized output before transport", () => {
    const duplicate = continuationRequest();
    duplicate.continuation = {
      previousResponseId: "resp-1",
      outputs: [
        { callId: "call-1", output: "a" },
        { callId: "call-1", output: "b" },
      ],
    };
    expect(() => validateRequest(duplicate)).toThrow("must be unique");

    const oversized = continuationRequest();
    oversized.continuation = {
      previousResponseId: "resp-1",
      outputs: [{ callId: "call-1", output: "x".repeat(129) }],
    };
    expect(() => validateRequest(oversized)).toThrow("exceeded its byte limit");
  });
});
