import { createHash } from "node:crypto";
import type {
  ModelCapability,
  ModelTransport,
} from "../../kernel/contracts.js";

export interface ModelCredentialReference {
  environmentVariable: string;
}

export interface OpenAIResponsesAdapterConfig {
  providerId: string;
  modelId: string;
  baseUrl: string;
  transport: Extract<ModelTransport, "local_http" | "private_http">;
  credential?: ModelCredentialReference;
  features: ReadonlySet<ModelCapability>;
  capabilitySource: "configured";
}

export interface ValidatedModelConfig
  extends Omit<OpenAIResponsesAdapterConfig, "baseUrl"> {
  endpoint: URL;
  endpointIdentityDigest: `sha256:${string}`;
}

const ENVIRONMENT_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/u;

export function validateModelConfig(
  config: OpenAIResponsesAdapterConfig,
): ValidatedModelConfig {
  if (config.providerId.trim() === "") {
    throw new Error("model provider ID must not be empty");
  }
  if (config.modelId.trim() === "") {
    throw new Error("model ID must not be empty");
  }
  const endpoint = parseEndpoint(config.baseUrl);
  if (
    config.credential !== undefined &&
    !ENVIRONMENT_NAME.test(config.credential.environmentVariable)
  ) {
    throw new Error(
      "model credential must reference a canonical environment variable",
    );
  }
  const identity = `${config.transport}\n${endpoint.toString()}`;
  return {
    ...config,
    providerId: config.providerId.trim(),
    modelId: config.modelId.trim(),
    features: new Set(config.features),
    ...(config.credential === undefined
      ? {}
      : { credential: { ...config.credential } }),
    endpoint,
    endpointIdentityDigest: `sha256:${createHash("sha256")
      .update(identity)
      .digest("hex")}`,
  };
}

export function resolveCredential(
  config: ValidatedModelConfig,
  environment: Readonly<Record<string, string | undefined>>,
): string | undefined {
  const name = config.credential?.environmentVariable;
  if (name === undefined) return undefined;
  const credential = environment[name]?.trim();
  if (credential === undefined || credential === "") {
    throw new Error(`model credential environment variable ${name} is empty`);
  }
  if (Buffer.byteLength(credential, "utf8") > 16 * 1024) {
    throw new Error(
      `model credential environment variable ${name} is too large`,
    );
  }
  return credential;
}

function parseEndpoint(value: string): URL {
  let base: URL;
  try {
    base = new URL(value);
  } catch {
    throw new Error("model base URL is invalid");
  }
  if (base.protocol !== "http:" && base.protocol !== "https:") {
    throw new Error("model base URL must use HTTP or HTTPS");
  }
  if (base.username !== "" || base.password !== "") {
    throw new Error("model base URL must not contain credentials");
  }
  if (base.search !== "" || base.hash !== "") {
    throw new Error("model base URL must not contain a query or fragment");
  }
  const path = base.pathname.replace(/\/+$/u, "");
  base.pathname = `${path}/responses`;
  return base;
}
