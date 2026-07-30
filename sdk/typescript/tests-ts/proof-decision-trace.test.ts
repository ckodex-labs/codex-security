import { describe, expect, test } from "bun:test";
import type { ModelCapabilities } from "../src/kernel/contracts.js";
import { createDecisionEvidence } from "../src/proof/decision-trace.js";

describe("decision evidence", () => {
  test("host code deterministically binds a gate verdict to its model identity", () => {
    const input = {
      traceId: "trace-1",
      actionId: "scan-1",
      decision: {
        verdict: "allow",
        policyId: "model-policy/v1",
        reasons: ["capabilities satisfied"],
      } as const,
      timestamp: "2026-01-01T00:00:00Z",
      model: {
        providerId: "local-provider",
        modelId: "example-model",
        transport: "local_process",
        endpointSecurity: {
          tls: false,
          privateNetwork: true,
          loopbackOnly: true,
          source: "derived",
        },
        features: new Set(["streaming"] as const),
        capabilitySource: "probed",
      } satisfies ModelCapabilities,
    };
    const first = createDecisionEvidence(input);
    const second = createDecisionEvidence(input);
    expect(first).toEqual(second);
    expect(first.digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(first.trace.providerId).toBe("local-provider");
  });
});
