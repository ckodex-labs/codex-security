import { describe, expect, test } from "bun:test";
import type { ModelCapabilities } from "../src/kernel/contracts.js";
import { validateModelCapabilities } from "../src/validation/model-capabilities.js";

const required = [
  "streaming",
  "structured_output",
  "tool_calling",
  "cancellation",
  "usage_accounting",
] as const;

describe("model capability gate", () => {
  test("admits a loopback local provider only when the full execution contract is present", () => {
    const capabilities: ModelCapabilities = {
      providerId: "ollama-local",
      modelId: "example-model",
      transport: "local_process",
      endpointSecurity: {
        tls: false,
        privateNetwork: true,
        loopbackOnly: true,
        source: "derived",
      },
      features: new Set(required),
      capabilitySource: "probed",
    };
    expect(
      validateModelCapabilities(capabilities, {
        policyId: "model-policy/v1",
        allowedTransports: ["local_process", "private_http"],
        requiredCapabilities: required,
        requirePrivateEndpoint: true,
        requireTlsForRemote: true,
        requireDerivedEndpointSecurity: true,
      }).verdict,
    ).toBe("allow");
  });

  test("fails closed for an incomplete or exposed private API adapter", () => {
    const decision = validateModelCapabilities(
      {
        providerId: "private-api",
        modelId: "example-model",
        transport: "private_http",
        endpointSecurity: {
          tls: false,
          privateNetwork: false,
          loopbackOnly: false,
          source: "derived",
        },
        features: new Set(["streaming"]),
        capabilitySource: "configured",
      },
      {
        policyId: "model-policy/v1",
        allowedTransports: ["private_http"],
        requiredCapabilities: required,
        requirePrivateEndpoint: true,
        requireTlsForRemote: true,
        requireDerivedEndpointSecurity: true,
      },
    );
    expect(decision.verdict).toBe("deny");
    expect(decision.reasons).toContain("remote model endpoint is not private");
    expect(decision.reasons).toContain(
      "required capability tool_calling is unavailable",
    );
  });
});
