import type { ScanModelProvider } from "../kernel/contracts.js";

export type ModelProviderConfigDecision =
  | { ok: true }
  | { ok: false; message: string };

export function validateModelProviderConfig(
  provider: Exclude<ScanModelProvider, { kind: "codex" }>,
): ModelProviderConfigDecision {
  const identity = validateIdentity(provider);
  if (!identity.ok) return identity;
  const bridgeKind =
    provider.kind === "local_process" || provider.kind === "private_grpc";
  const endpointValue =
    "bridgeBaseUrl" in provider ? provider.bridgeBaseUrl : provider.baseUrl;
  let endpoint: URL;
  try {
    endpoint = new URL(endpointValue);
  } catch {
    return {
      ok: false,
      message: "Custom provider baseUrl must be a valid URL.",
    };
  }
  const endpointShape = validateEndpointShape(endpoint);
  if (!endpointShape.ok) return endpointShape;
  const address = endpoint.hostname.replace(/^\[|\]$/gu, "");
  if (
    provider.kind === "local" ||
    provider.kind === "local_http" ||
    bridgeKind
  ) {
    return validateLocalEndpoint(endpoint, address, bridgeKind);
  }
  return validatePrivateEndpoint(provider, endpoint, address);
}

function validateIdentity(
  provider: Exclude<ScanModelProvider, { kind: "codex" }>,
): ModelProviderConfigDecision {
  if (!/^ckodex-[a-z0-9][a-z0-9_-]{0,55}$/u.test(provider.id)) {
    return {
      ok: false,
      message:
        "Custom provider id must start with ckodex- and contain only lowercase letters, digits, underscores, or hyphens.",
    };
  }
  if (provider.model.trim().length === 0 || provider.model.length > 256) {
    return {
      ok: false,
      message:
        "Custom provider model must be a nonempty string of at most 256 characters.",
    };
  }
  if (
    provider.credentialEnv !== undefined &&
    !/^[A-Z_][A-Z0-9_]{0,127}$/u.test(provider.credentialEnv)
  ) {
    return {
      ok: false,
      message:
        "Custom provider credentialEnv must be a canonical environment variable name.",
    };
  }
  return { ok: true };
}

function validateEndpointShape(endpoint: URL): ModelProviderConfigDecision {
  if (
    endpoint.username === "" &&
    endpoint.password === "" &&
    endpoint.search === "" &&
    endpoint.hash === ""
  ) {
    return { ok: true };
  }
  return {
    ok: false,
    message:
      "Custom provider baseUrl cannot contain credentials, query parameters, or a fragment.",
  };
}

function validateLocalEndpoint(
  endpoint: URL,
  address: string,
  bridgeKind: boolean,
): ModelProviderConfigDecision {
  if (
    endpoint.protocol === "http:" &&
    (address === "::1" || isIpv4Loopback(address))
  ) {
    return { ok: true };
  }
  return {
    ok: false,
    message: bridgeKind
      ? "Process and gRPC model providers require an HTTP literal loopback Responses bridge."
      : "Local model providers require an HTTP literal loopback baseUrl.",
  };
}

function validatePrivateEndpoint(
  provider: Exclude<ScanModelProvider, { kind: "codex" }>,
  endpoint: URL,
  address: string,
): ModelProviderConfigDecision {
  if (
    endpoint.protocol !== "https:" ||
    !isPrivateLiteralAddress(address) ||
    (provider.credentialEnv?.trim().length ?? 0) === 0
  ) {
    return {
      ok: false,
      message:
        "Private model providers require authenticated HTTPS to a literal private IP address.",
    };
  }
  return { ok: true };
}

function ipv4Octets(address: string): readonly number[] | null {
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/u.test(address)) {
    return null;
  }
  const octets = address.split(".").map(Number);
  return octets.every((octet) => octet <= 255) ? octets : null;
}

function isIpv4Loopback(address: string): boolean {
  return ipv4Octets(address)?.[0] === 127;
}

function isPrivateLiteralAddress(address: string): boolean {
  const octets = ipv4Octets(address);
  if (octets !== null) {
    return (
      octets[0] === 10 ||
      (octets[0] === 172 &&
        octets[1] !== undefined &&
        octets[1] >= 16 &&
        octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168)
    );
  }
  return /^f[cd][0-9a-f]{2}(?::[0-9a-f]{0,4}){1,7}$/iu.test(address);
}
