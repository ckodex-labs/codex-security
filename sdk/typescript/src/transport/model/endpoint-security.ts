import { request as requestHttp } from "node:http";
import { request as requestHttps } from "node:https";
import { isIP } from "node:net";
import type {
  ModelEndpointSecurity,
  ModelExecutionLimits,
} from "../../kernel/contracts.js";
import type { ValidatedModelConfig } from "./model-config.js";
import { abortReason, responseFromIncoming } from "./node-http-response.js";

export interface ConnectionEvidence {
  resolvedAddress: string;
  addressPinned: boolean;
  tlsAuthenticated: boolean;
  peerCertificateFingerprint?: `sha256:${string}`;
}

export interface PreparedModelConnection {
  evidence: ConnectionEvidence;
  send(init: RequestInit, signal: AbortSignal): Promise<Response>;
}

export interface ModelHttpConnector {
  prepare(
    endpoint: URL,
    limits: ModelExecutionLimits,
    signal: AbortSignal,
  ): Promise<PreparedModelConnection>;
}

export class LocalFetchConnector implements ModelHttpConnector {
  public async prepare(
    endpoint: URL,
    _limits: ModelExecutionLimits,
    _signal: AbortSignal,
  ): Promise<PreparedModelConnection> {
    if (!isLiteralLoopback(endpoint.hostname)) {
      throw new Error(
        "default model connector only permits literal loopback endpoints",
      );
    }
    return {
      evidence: {
        resolvedAddress: stripIpv6Brackets(endpoint.hostname),
        addressPinned: true,
        tlsAuthenticated: endpoint.protocol === "https:",
      },
      send: async (init, signal) =>
        await sendNodeHttpRequest(endpoint, init, signal),
    };
  }
}

export function deriveEndpointSecurity(
  config: ValidatedModelConfig,
  evidence: ConnectionEvidence,
): ModelEndpointSecurity {
  if (!evidence.addressPinned) {
    throw new Error("model connection does not pin its validated address");
  }
  const loopback = isLiteralLoopback(evidence.resolvedAddress);
  const privateNetwork = loopback || isPrivateAddress(evidence.resolvedAddress);
  const tls = config.endpoint.protocol === "https:";

  validateEndpointEvidence(config, evidence, loopback, privateNetwork, tls);

  return {
    tls,
    privateNetwork,
    loopbackOnly: loopback,
    source: "derived",
    endpointIdentityDigest: config.endpointIdentityDigest,
    ...(evidence.peerCertificateFingerprint === undefined
      ? {}
      : {
          peerCertificateFingerprint: evidence.peerCertificateFingerprint,
        }),
  };
}

function validateEndpointEvidence(
  config: ValidatedModelConfig,
  evidence: ConnectionEvidence,
  loopback: boolean,
  privateNetwork: boolean,
  tls: boolean,
): void {
  if (config.transport === "local_http") {
    if (!loopback)
      throw new Error("local model endpoint did not resolve to loopback");
    if (config.endpoint.protocol !== "http:" && !evidence.tlsAuthenticated) {
      throw new Error("local HTTPS model connection is not authenticated");
    }
    return;
  }
  if (!tls || !evidence.tlsAuthenticated) {
    throw new Error("private model endpoint requires authenticated TLS");
  }
  if (!privateNetwork || loopback) {
    throw new Error("private model endpoint did not resolve privately");
  }
}

export function isLiteralLoopback(host: string): boolean {
  const value = stripIpv6Brackets(host).toLowerCase();
  if (value === "::1") return true;
  if (isIP(value) !== 4) return false;
  const first = Number(value.split(".")[0]);
  return first === 127;
}

export function isPrivateAddress(address: string): boolean {
  const value = stripIpv6Brackets(address).toLowerCase();
  const version = isIP(value);
  if (version === 4) {
    const octets = value.split(".").map(Number);
    const first = octets[0] ?? -1;
    const second = octets[1] ?? -1;
    return (
      first === 10 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168)
    );
  }
  return version === 6 && (value.startsWith("fc") || value.startsWith("fd"));
}

function stripIpv6Brackets(value: string): string {
  return value.startsWith("[") && value.endsWith("]")
    ? value.slice(1, -1)
    : value;
}

async function sendNodeHttpRequest(
  endpoint: URL,
  init: RequestInit,
  signal: AbortSignal,
): Promise<Response> {
  requireStringBody(init.body);
  const headers = Object.fromEntries(new Headers(init.headers));
  return await new Promise<Response>((resolve, reject) => {
    let activeResponse: import("node:http").IncomingMessage | undefined;
    const request = (
      endpoint.protocol === "https:" ? requestHttps : requestHttp
    )(
      endpoint,
      {
        method: init.method ?? "POST",
        headers,
        agent: false,
      },
      (incoming) => {
        activeResponse = incoming;
        incoming.once("end", () => signal.removeEventListener("abort", abort));
        settleLocalResponse(incoming, resolve, reject);
      },
    );
    const abort = (): void => {
      const reason = abortReason(signal);
      activeResponse?.socket.destroy(reason);
      activeResponse?.destroy(reason);
      request.destroy(reason);
    };
    signal.addEventListener("abort", abort, { once: true });
    request.once("error", (error) => {
      signal.removeEventListener("abort", abort);
      reject(error);
    });
    if (signal.aborted) {
      abort();
      return;
    }
    request.end(init.body);
  });
}

function settleLocalResponse(
  incoming: import("node:http").IncomingMessage,
  resolve: (response: Response) => void,
  reject: (error: unknown) => void,
): void {
  try {
    resolve(
      responseFromIncoming(
        incoming,
        "local model endpoint returned an invalid status",
      ),
    );
  } catch (error) {
    reject(error);
  }
}

function requireStringBody(body: unknown): void {
  if (body !== undefined && body !== null && typeof body !== "string") {
    throw new Error("local model connector requires a serialized string body");
  }
}
