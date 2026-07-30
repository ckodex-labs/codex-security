import { createHash } from "node:crypto";
import { isIP } from "node:net";
import {
  checkServerIdentity,
  connect,
  type PeerCertificate,
  type TLSSocket,
} from "node:tls";
import {
  Client,
  Metadata,
  credentials,
  type ChannelCredentials,
  type ClientReadableStream,
  type ServiceDefinition,
} from "@grpc/grpc-js";
import type {
  ModelCapabilities,
  ModelCapability,
  ModelExecutionEvent,
  ModelExecutionLimits,
  ModelExecutionRequest,
} from "../../kernel/contracts.js";
import type {
  ModelExecutionPort,
  PreparedModelExecution,
} from "../../kernel/ports.js";
import { isPrivateAddress } from "./endpoint-security.js";
import { requireModelEvent } from "./model-event-validation.js";
import { validateRequest } from "./responses-protocol.js";

interface JsonEnvelope {
  json: Buffer;
}

const EXECUTE_PATH = "/ckodex.model.v1.ModelExecution/Execute";

export const MODEL_EXECUTION_GRPC_SERVICE: ServiceDefinition = {
  execute: {
    path: EXECUTE_PATH,
    requestStream: false,
    responseStream: true,
    requestSerialize: serializeEnvelope,
    requestDeserialize: deserializeEnvelope,
    responseSerialize: serializeEnvelope,
    responseDeserialize: deserializeEnvelope,
  },
  cancel: {
    path: "/ckodex.model.v1.ModelExecution/Cancel",
    requestStream: false,
    responseStream: false,
    requestSerialize: serializeEnvelope,
    requestDeserialize: deserializeEnvelope,
    responseSerialize: serializeEnvelope,
    responseDeserialize: deserializeEnvelope,
  },
};

export interface PrivateGrpcModelAdapterConfig {
  providerId: string;
  modelId: string;
  pinnedAddress: string;
  port: number;
  serverName: string;
  rootCertificate: Buffer;
  clientCertificate?: Buffer;
  clientPrivateKey?: Buffer;
  expectedPeerFingerprint: `sha256:${string}`;
  credentialEnv?: string;
  features: ReadonlySet<ModelCapability>;
}

export interface PrivateGrpcModelAdapterDependencies {
  environment?: Readonly<Record<string, string | undefined>>;
  createClient?(
    target: string,
    credentials: ChannelCredentials,
    options: Readonly<Record<string, string | number>>,
  ): Client;
}

export class PrivateGrpcModelAdapter implements ModelExecutionPort {
  readonly #config: PrivateGrpcModelAdapterConfig;
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #createClient: NonNullable<
    PrivateGrpcModelAdapterDependencies["createClient"]
  >;
  readonly #active = new Map<
    string,
    { call: ClientReadableStream<JsonEnvelope>; client: Client }
  >();

  public constructor(
    config: PrivateGrpcModelAdapterConfig,
    dependencies: PrivateGrpcModelAdapterDependencies = {},
  ) {
    validateConfig(config);
    this.#config = { ...config, features: new Set(config.features) };
    this.#environment = dependencies.environment ?? process.env;
    this.#createClient =
      dependencies.createClient ??
      ((target, channelCredentials, options) =>
        new Client(target, channelCredentials, options));
  }

  public async capabilities(): Promise<ModelCapabilities> {
    const limits = defaultCapabilityLimits();
    const fingerprint = await verifyPeer(
      this.#config,
      limits,
      new AbortController().signal,
    );
    return this.#capabilities(fingerprint);
  }

  public async prepare(
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): Promise<PreparedModelExecution> {
    validateRequest(request);
    const fingerprint = await verifyPeer(this.#config, request.limits, signal);
    const client = this.#client(request.limits);
    let consumed = false;
    return {
      capabilities: this.#capabilities(fingerprint),
      execute: () => {
        if (consumed)
          throw new Error("prepared gRPC model execution was already consumed");
        consumed = true;
        return this.#executeClient(client, request, signal);
      },
      cancel: async () => {
        client.close();
      },
    };
  }

  public async *execute(
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): AsyncIterable<ModelExecutionEvent> {
    const prepared = await this.prepare(request, signal);
    for await (const event of prepared.execute()) yield event;
  }

  public async cancel(requestId: string): Promise<void> {
    const active = this.#active.get(requestId);
    active?.call.cancel();
    active?.client.close();
  }

  async *#executeClient(
    client: Client,
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): AsyncIterable<ModelExecutionEvent> {
    requireCapabilities(this.#config.features, request.requiredCapabilities);
    const encoded = encodeRequest(request, client);
    const call = client.makeServerStreamRequest(
      EXECUTE_PATH,
      serializeEnvelope,
      deserializeEnvelope,
      { json: encoded },
      this.#metadata(),
      { deadline: Date.now() + request.limits.wallClockMillis },
    );
    this.#active.set(request.requestId, { call, client });
    const abort = (): void => call.cancel();
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    let bytes = 0;
    let nextSequence = 0;
    try {
      for await (const envelope of call) {
        bytes += envelope.json.byteLength;
        if (bytes > request.limits.maxResponseBytes) {
          call.cancel();
          throw new Error("gRPC model response exceeded its byte limit");
        }
        const event = requireModelEvent(parseJson(envelope.json));
        nextSequence = event.sequence + 1;
        yield event;
      }
    } catch (error) {
      if (signal.aborted) {
        yield {
          kind: "canceled",
          sequence: nextSequence,
          reason: "operation aborted",
        };
        return;
      }
      throw error;
    } finally {
      signal.removeEventListener("abort", abort);
      this.#active.delete(request.requestId);
      client.close();
    }
  }

  #client(limits: ModelExecutionLimits): Client {
    const channelCredentials = credentials.createSsl(
      this.#config.rootCertificate,
      this.#config.clientPrivateKey,
      this.#config.clientCertificate,
      {
        rejectUnauthorized: true,
        checkServerIdentity: verifyGrpcCertificate(this.#config),
      },
    );
    return this.#createClient(
      `${this.#config.pinnedAddress}:${this.#config.port}`,
      channelCredentials,
      {
        "grpc.ssl_target_name_override": this.#config.serverName,
        "grpc.default_authority": this.#config.serverName,
        "grpc.max_receive_message_length": limits.maxResponseBytes + 16,
        "grpc.max_send_message_length": limits.maxRequestBytes + 16,
      },
    );
  }

  #metadata(): Metadata {
    const metadata = new Metadata();
    const name = this.#config.credentialEnv;
    if (name === undefined) return metadata;
    const value = this.#environment[name]?.trim();
    if (
      value === undefined ||
      value === "" ||
      Buffer.byteLength(value) > 8 * 1024
    ) {
      throw new Error(
        `gRPC model credential environment variable ${name} is invalid`,
      );
    }
    metadata.set("authorization", `Bearer ${value}`);
    return metadata;
  }

  #capabilities(fingerprint: `sha256:${string}`): ModelCapabilities {
    return {
      providerId: this.#config.providerId,
      modelId: this.#config.modelId,
      transport: "private_grpc",
      endpointSecurity: {
        tls: true,
        privateNetwork: true,
        loopbackOnly: false,
        source: "derived",
        endpointIdentityDigest: grpcIdentity(this.#config),
        peerCertificateFingerprint: fingerprint,
      },
      features: new Set(this.#config.features),
      capabilitySource: "configured",
    };
  }
}

function encodeRequest(request: ModelExecutionRequest, client: Client): Buffer {
  const encoded = Buffer.from(JSON.stringify(request));
  if (encoded.byteLength > request.limits.maxRequestBytes) {
    client.close();
    throw new Error("gRPC model request exceeded its byte limit");
  }
  return encoded;
}

function verifyGrpcCertificate(
  config: PrivateGrpcModelAdapterConfig,
): (hostname: string, certificate: PeerCertificate) => Error | undefined {
  return (hostname, certificate) => {
    const identityError = checkServerIdentity(hostname, certificate);
    if (identityError !== undefined) return identityError;
    if (hostname !== config.serverName) {
      return new Error("gRPC TLS hostname changed during connection");
    }
    if (certificate.raw === undefined)
      return new Error("gRPC peer certificate is missing");
    const fingerprint = `sha256:${createHash("sha256")
      .update(certificate.raw)
      .digest("hex")}`;
    return fingerprint === config.expectedPeerFingerprint
      ? undefined
      : new Error("gRPC peer certificate fingerprint did not match");
  };
}

function validateConfig(config: PrivateGrpcModelAdapterConfig): void {
  if (config.providerId.trim() === "" || config.modelId.trim() === "") {
    throw new Error("gRPC model identity must not be empty");
  }
  if (
    isIP(config.pinnedAddress) === 0 ||
    !isPrivateAddress(config.pinnedAddress)
  ) {
    throw new Error("gRPC model address must be a private IP literal");
  }
  if (
    !Number.isSafeInteger(config.port) ||
    config.port < 1 ||
    config.port > 65_535
  ) {
    throw new Error("gRPC model port is invalid");
  }
  if (isIP(config.serverName) !== 0 || config.serverName.trim() === "") {
    throw new Error("gRPC TLS server name must be a DNS name");
  }
  if (
    (config.clientCertificate === undefined) !==
    (config.clientPrivateKey === undefined)
  ) {
    throw new Error(
      "gRPC mTLS certificate and private key must be configured together",
    );
  }
  if (
    config.credentialEnv !== undefined &&
    !/^[A-Z_][A-Z0-9_]{0,127}$/u.test(config.credentialEnv)
  ) {
    throw new Error("gRPC credential environment name is invalid");
  }
}

async function verifyPeer(
  config: PrivateGrpcModelAdapterConfig,
  limits: ModelExecutionLimits,
  signal: AbortSignal,
): Promise<`sha256:${string}`> {
  const socket = await openTlsSocket(
    config,
    limits.headerTimeoutMillis,
    signal,
  );
  try {
    const certificate = socket.getPeerCertificate(true);
    if (certificate.raw === undefined)
      throw new Error("gRPC peer certificate is missing");
    const fingerprint = `sha256:${createHash("sha256")
      .update(certificate.raw)
      .digest("hex")}` as const;
    if (fingerprint !== config.expectedPeerFingerprint) {
      throw new Error("gRPC peer certificate fingerprint did not match");
    }
    return fingerprint;
  } finally {
    socket.destroy();
  }
}

async function openTlsSocket(
  config: PrivateGrpcModelAdapterConfig,
  timeoutMillis: number,
  signal: AbortSignal,
): Promise<TLSSocket> {
  return await new Promise<TLSSocket>((resolve, reject) => {
    const socket = connect({
      host: config.pinnedAddress,
      port: config.port,
      servername: config.serverName,
      ca: config.rootCertificate,
      cert: config.clientCertificate,
      key: config.clientPrivateKey,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    });
    const timer = setTimeout(
      () => socket.destroy(new Error("gRPC TLS timed out")),
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
      resolve(socket);
    });
    socket.once("error", reject);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
}

function serializeEnvelope(value: JsonEnvelope): Buffer {
  return Buffer.concat([
    Buffer.from([0x0a]),
    encodeVarint(value.json.length),
    value.json,
  ]);
}

function deserializeEnvelope(value: Buffer): JsonEnvelope {
  if (value[0] !== 0x0a) throw new Error("gRPC model envelope is invalid");
  const length = decodeVarint(value, 1);
  const start = 1 + length.bytes;
  if (start + length.value !== value.length) {
    throw new Error("gRPC model envelope length is invalid");
  }
  return { json: value.subarray(start) };
}

function encodeVarint(value: number): Buffer {
  const bytes: number[] = [];
  let remaining = value;
  do {
    const next = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
    bytes.push(remaining === 0 ? next : next | 0x80);
  } while (remaining !== 0);
  return Buffer.from(bytes);
}

function decodeVarint(
  value: Buffer,
  offset: number,
): { value: number; bytes: number } {
  let result = 0;
  let multiplier = 1;
  for (
    let index = offset;
    index < value.length && index < offset + 5;
    index += 1
  ) {
    const byte = value[index];
    if (byte === undefined)
      throw new Error("gRPC model envelope varint is invalid");
    result += (byte & 0x7f) * multiplier;
    if ((byte & 0x80) === 0)
      return { value: result, bytes: index - offset + 1 };
    multiplier *= 128;
  }
  throw new Error("gRPC model envelope varint is invalid");
}

function parseJson(value: Buffer): unknown {
  try {
    return JSON.parse(value.toString("utf8"));
  } catch {
    throw new Error("gRPC model event is invalid JSON");
  }
}

function requireCapabilities(
  available: ReadonlySet<ModelCapability>,
  required: readonly ModelCapability[],
): void {
  for (const capability of required) {
    if (!available.has(capability)) {
      throw new Error(`model capability ${capability} is unavailable`);
    }
  }
}

function grpcIdentity(
  config: PrivateGrpcModelAdapterConfig,
): `sha256:${string}` {
  const value = [
    "private_grpc",
    config.pinnedAddress,
    String(config.port),
    config.serverName,
    config.expectedPeerFingerprint,
  ].join("\n");
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function defaultCapabilityLimits(): ModelExecutionLimits {
  return {
    maxRequestBytes: 1,
    maxResponseBytes: 1,
    maxToolArgumentBytes: 1,
    headerTimeoutMillis: 5_000,
    streamIdleTimeoutMillis: 5_000,
    wallClockMillis: 5_000,
  };
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException("operation aborted", "AbortError");
}
