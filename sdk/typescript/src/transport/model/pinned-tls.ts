import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request as requestHttps } from "node:https";
import type { IncomingMessage } from "node:http";
import { isIP, type LookupFunction } from "node:net";
import {
  checkServerIdentity,
  connect,
  type ConnectionOptions,
  type PeerCertificate,
  type TLSSocket,
} from "node:tls";
import type { ModelExecutionLimits } from "../../kernel/contracts.js";
import {
  isPrivateAddress,
  type ModelHttpConnector,
  type PreparedModelConnection,
} from "./endpoint-security.js";
import { abortReason, responseFromIncoming } from "./node-http-response.js";

export interface PinnedTlsHttpConnectorConfig {
  pinnedAddress: string;
  ca?: string | Buffer;
  certificate?: string | Buffer;
  privateKey?: string | Buffer;
  expectedPeerFingerprint?: `sha256:${string}`;
}

export interface PinnedTlsHttpConnectorDependencies {
  resolve?(
    hostname: string,
    signal: AbortSignal,
  ): Promise<readonly { address: string; family: number }[]>;
}

export class PinnedTlsHttpConnector implements ModelHttpConnector {
  readonly #config: PinnedTlsHttpConnectorConfig;
  readonly #resolve: NonNullable<PinnedTlsHttpConnectorDependencies["resolve"]>;

  public constructor(
    config: PinnedTlsHttpConnectorConfig,
    dependencies: PinnedTlsHttpConnectorDependencies = {},
  ) {
    if (
      isIP(config.pinnedAddress) === 0 ||
      !isPrivateAddress(config.pinnedAddress)
    ) {
      throw new Error("pinned model address must be a private IP literal");
    }
    this.#config = { ...config };
    this.#resolve = dependencies.resolve ?? resolveAll;
  }

  public async prepare(
    endpoint: URL,
    limits: ModelExecutionLimits,
    signal: AbortSignal,
  ): Promise<PreparedModelConnection> {
    validateEndpoint(endpoint);
    const addresses = await this.#resolve(endpoint.hostname, signal);
    validateResolution(addresses, this.#config.pinnedAddress);
    const socket = await openAuthenticatedSocket(
      endpoint,
      this.#config,
      limits.headerTimeoutMillis,
      signal,
    );
    const fingerprint = peerFingerprint(socket);
    requireFingerprint(fingerprint, this.#config.expectedPeerFingerprint);
    socket.destroy();
    let sent = false;
    return {
      evidence: {
        resolvedAddress: this.#config.pinnedAddress,
        addressPinned: true,
        tlsAuthenticated: true,
        peerCertificateFingerprint: fingerprint,
      },
      send: async (init, requestSignal) => {
        if (sent) throw new Error("prepared model connection is single use");
        sent = true;
        return await sendPinnedRequest(
          endpoint,
          this.#config,
          init,
          requestSignal,
        );
      },
    };
  }
}

function validateEndpoint(endpoint: URL): void {
  if (endpoint.protocol !== "https:" || isIP(endpoint.hostname) !== 0) {
    throw new Error(
      "pinned TLS connector requires a private DNS HTTPS endpoint",
    );
  }
}

function validateResolution(
  addresses: readonly { address: string }[],
  pinnedAddress: string,
): void {
  if (!addresses.some(({ address }) => address === pinnedAddress)) {
    throw new Error(
      "private DNS did not resolve to the configured pinned address",
    );
  }
}

function requireFingerprint(
  actual: `sha256:${string}`,
  expected: `sha256:${string}` | undefined,
): void {
  if (expected !== undefined && actual !== expected) {
    throw new Error("model peer certificate fingerprint did not match");
  }
}

async function resolveAll(
  hostname: string,
  signal: AbortSignal,
): Promise<readonly { address: string; family: number }[]> {
  signal.throwIfAborted();
  const result = await lookup(hostname, { all: true, verbatim: true });
  signal.throwIfAborted();
  return result;
}

async function openAuthenticatedSocket(
  endpoint: URL,
  config: PinnedTlsHttpConnectorConfig,
  timeoutMillis: number,
  signal: AbortSignal,
): Promise<TLSSocket> {
  const options: ConnectionOptions = {
    host: config.pinnedAddress,
    port: Number(endpoint.port || "443"),
    servername: endpoint.hostname,
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
    ...(config.ca === undefined ? {} : { ca: config.ca }),
    ...(config.certificate === undefined ? {} : { cert: config.certificate }),
    ...(config.privateKey === undefined ? {} : { key: config.privateKey }),
    checkServerIdentity: peerVerifier(
      endpoint.hostname,
      config.expectedPeerFingerprint,
    ),
  };
  return await new Promise<TLSSocket>((resolve, reject) => {
    const socket = connect(options);
    const timer = setTimeout(
      () => socket.destroy(new Error("model TLS handshake timed out")),
      timeoutMillis,
    );
    const abort = (): void => {
      socket.destroy(abortReason(signal));
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      socket.removeListener("error", reject);
    };
    socket.once("secureConnect", () => {
      cleanup();
      if (!socket.authorized) {
        socket.destroy();
        reject(new Error("model TLS peer was not authorized"));
        return;
      }
      resolve(socket);
    });
    socket.once("error", reject);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
}

function peerVerifier(
  expectedHostname: string,
  expectedFingerprint: `sha256:${string}` | undefined,
): (hostname: string, certificate: PeerCertificate) => Error | undefined {
  return (hostname, certificate) => {
    const identityError = checkServerIdentity(hostname, certificate);
    if (identityError !== undefined) return identityError;
    if (hostname !== expectedHostname) {
      return new Error("model TLS hostname changed during connection");
    }
    if (certificate.raw === undefined) {
      return new Error("model TLS peer did not provide a certificate");
    }
    const fingerprint = `sha256:${createHash("sha256")
      .update(certificate.raw)
      .digest("hex")}` as const;
    return fingerprint === expectedFingerprint ||
      expectedFingerprint === undefined
      ? undefined
      : new Error("model peer certificate fingerprint did not match");
  };
}

function peerFingerprint(socket: TLSSocket): `sha256:${string}` {
  const certificate = socket.getPeerCertificate(true);
  if (certificate.raw === undefined) {
    throw new Error("model TLS peer did not provide a certificate");
  }
  return `sha256:${createHash("sha256").update(certificate.raw).digest("hex")}`;
}

async function sendPinnedRequest(
  endpoint: URL,
  config: PinnedTlsHttpConnectorConfig,
  init: RequestInit,
  signal: AbortSignal,
): Promise<Response> {
  if (init.body !== undefined && typeof init.body !== "string") {
    throw new Error("pinned TLS connector requires a serialized string body");
  }
  return await new Promise<Response>((resolve, reject) => {
    const headers = new Headers(init.headers);
    if (!headers.has("host")) headers.set("host", endpoint.host);
    const request = requestHttps(
      endpoint,
      pinnedRequestOptions(endpoint, config, init, headers),
      (incoming) => settlePinnedResponse(incoming, resolve, reject),
    );
    const abort = (): void => {
      request.destroy(abortReason(signal));
    };
    signal.addEventListener("abort", abort, { once: true });
    request.once("close", () => signal.removeEventListener("abort", abort));
    request.once("error", reject);
    if (signal.aborted) {
      abort();
      return;
    }
    request.end(init.body);
  });
}

function pinnedRequestOptions(
  endpoint: URL,
  config: PinnedTlsHttpConnectorConfig,
  init: RequestInit,
  headers: Headers,
): import("node:https").RequestOptions {
  return {
    method: init.method ?? "POST",
    headers: Object.fromEntries(headers),
    agent: false,
    servername: endpoint.hostname,
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
    ca: config.ca,
    cert: config.certificate,
    key: config.privateKey,
    checkServerIdentity: peerVerifier(
      endpoint.hostname,
      config.expectedPeerFingerprint,
    ),
    lookup: pinnedLookup(config.pinnedAddress),
  };
}

function pinnedLookup(address: string): LookupFunction {
  return (_hostname, options, callback) => {
    const family = isIP(address) as 4 | 6;
    if (options.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
}

function settlePinnedResponse(
  incoming: IncomingMessage,
  resolve: (response: Response) => void,
  reject: (error: unknown) => void,
): void {
  try {
    resolve(
      responseFromIncoming(
        incoming,
        "model endpoint returned an invalid status",
      ),
    );
  } catch (error) {
    reject(error);
  }
}
