import { describe, expect, test } from "bun:test";
import {
  resolveCredential,
  validateModelConfig,
} from "../src/transport/model/model-config.js";

const base = {
  providerId: "local",
  modelId: "model-a",
  transport: "local_http",
  features: new Set(["streaming"] as const),
  capabilitySource: "configured",
} as const;

describe("model adapter configuration", () => {
  test("stores a credential reference and never accepts URL credentials", () => {
    expect(() =>
      validateModelConfig({
        ...base,
        baseUrl: "http://secret@127.0.0.1:11434/v1",
      }),
    ).toThrow("must not contain credentials");
    expect(() =>
      validateModelConfig({
        ...base,
        baseUrl: "http://127.0.0.1:11434/v1?api_key=secret",
      }),
    ).toThrow("must not contain a query");
  });

  test("resolves only the named environment variable at execution time", () => {
    const config = validateModelConfig({
      ...base,
      baseUrl: "http://127.0.0.1:11434/v1",
      credential: { environmentVariable: "PRIVATE_MODEL_TOKEN" },
    });
    expect(
      resolveCredential(config, { PRIVATE_MODEL_TOKEN: " current-value " }),
    ).toBe("current-value");
    expect(() =>
      resolveCredential(config, { PRIVATE_MODEL_TOKEN: " " }),
    ).toThrow("PRIVATE_MODEL_TOKEN is empty");
  });

  test("rejects ambiguous credential variable names", () => {
    expect(() =>
      validateModelConfig({
        ...base,
        baseUrl: "http://127.0.0.1:11434/v1",
        credential: { environmentVariable: "private-token" },
      }),
    ).toThrow("canonical environment variable");
  });
});
