import type { ScanModelProvider } from "../../kernel/contracts.js";

export interface ProviderCliOptions {
  providerKind?:
    | "local"
    | "private"
    | "local-http"
    | "private-http"
    | "local-process"
    | "private-grpc";
  providerId?: string;
  providerBaseUrl?: string;
  providerBridgeBaseUrl?: string;
  providerCredentialEnv?: string;
  model?: string;
}

function requireOption(value: string | undefined, label: string): string {
  if (value === undefined) throw new Error(`${label} is required`);
  return value;
}

function commonOptions(options: ProviderCliOptions): {
  id: string;
  model: string;
} {
  return {
    id: requireOption(options.providerId, "provider id"),
    model: requireOption(options.model, "provider model"),
  };
}

function bridgeProvider(
  options: ProviderCliOptions,
  common: { id: string; model: string },
): ScanModelProvider | undefined {
  if (
    options.providerKind !== "local-process" &&
    options.providerKind !== "private-grpc"
  ) {
    return undefined;
  }
  return {
    kind:
      options.providerKind === "local-process"
        ? "local_process"
        : "private_grpc",
    ...common,
    bridgeBaseUrl: requireOption(
      options.providerBridgeBaseUrl,
      "provider bridge base URL",
    ),
    ...(options.providerCredentialEnv === undefined
      ? {}
      : { credentialEnv: options.providerCredentialEnv }),
  };
}

export function modelProviderFromCli(
  options: ProviderCliOptions,
): ScanModelProvider | undefined {
  if (options.providerKind === undefined) return undefined;
  const common = commonOptions(options);
  const bridge = bridgeProvider(options, common);
  if (bridge !== undefined) return bridge;
  const baseUrl = requireOption(options.providerBaseUrl, "provider base URL");
  if (
    options.providerKind === "private" ||
    options.providerKind === "private-http"
  ) {
    return {
      kind:
        options.providerKind === "private-http" ? "private_http" : "private",
      ...common,
      baseUrl,
      credentialEnv: requireOption(
        options.providerCredentialEnv,
        "provider credential environment",
      ),
    };
  }
  return {
    kind: options.providerKind === "local-http" ? "local_http" : "local",
    ...common,
    baseUrl,
    ...(options.providerCredentialEnv === undefined
      ? {}
      : { credentialEnv: options.providerCredentialEnv }),
  };
}

export function providerOptionsComplete(options: ProviderCliOptions): boolean {
  if (options.providerKind === undefined) {
    return [
      options.providerId,
      options.providerBaseUrl,
      options.providerBridgeBaseUrl,
      options.providerCredentialEnv,
    ].every((value) => value === undefined);
  }
  if (options.providerId === undefined || options.model === undefined) {
    return false;
  }
  const bridge =
    options.providerKind === "local-process" ||
    options.providerKind === "private-grpc";
  return bridge
    ? options.providerBridgeBaseUrl !== undefined &&
        options.providerBaseUrl === undefined
    : options.providerBaseUrl !== undefined &&
        options.providerBridgeBaseUrl === undefined;
}

export function privateHttpCredentialPresent(
  options: ProviderCliOptions,
): boolean {
  return (
    (options.providerKind !== "private" &&
      options.providerKind !== "private-http") ||
    options.providerCredentialEnv !== undefined
  );
}
