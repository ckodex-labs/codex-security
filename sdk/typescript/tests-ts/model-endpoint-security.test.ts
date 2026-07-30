import { describe, expect, test } from "bun:test";
import {
  deriveEndpointSecurity,
  isPrivateAddress,
} from "../src/transport/model/endpoint-security.js";
import { validateModelConfig } from "../src/transport/model/model-config.js";

function config(transport: "local_http" | "private_http", baseUrl: string) {
  return validateModelConfig({
    providerId: "provider",
    modelId: "model",
    baseUrl,
    transport,
    features: new Set(["streaming"]),
    capabilitySource: "configured",
  });
}

describe("model endpoint security derivation", () => {
  test("derives loopback facts from a pinned literal address", () => {
    expect(
      deriveEndpointSecurity(config("local_http", "http://127.0.0.1/v1"), {
        resolvedAddress: "127.0.0.1",
        addressPinned: true,
        tlsAuthenticated: false,
      }),
    ).toMatchObject({
      tls: false,
      privateNetwork: true,
      loopbackOnly: true,
      source: "derived",
    });
  });

  test("requires address pinning and authenticated TLS for private remote APIs", () => {
    const remote = config("private_http", "https://models.internal/v1");
    expect(() =>
      deriveEndpointSecurity(remote, {
        resolvedAddress: "10.2.3.4",
        addressPinned: false,
        tlsAuthenticated: true,
      }),
    ).toThrow("does not pin");
    expect(() =>
      deriveEndpointSecurity(remote, {
        resolvedAddress: "10.2.3.4",
        addressPinned: true,
        tlsAuthenticated: false,
      }),
    ).toThrow("authenticated TLS");
  });

  test("recognizes only explicit private address ranges", () => {
    expect(isPrivateAddress("10.0.0.8")).toBe(true);
    expect(isPrivateAddress("172.31.0.8")).toBe(true);
    expect(isPrivateAddress("192.168.4.8")).toBe(true);
    expect(isPrivateAddress("fd00::8")).toBe(true);
    expect(isPrivateAddress("8.8.8.8")).toBe(false);
  });
});
