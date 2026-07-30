import { connect, type Socket } from "node:net";
import type {
  ModelHttpConnector,
  PreparedModelConnection,
} from "../src/transport/model/endpoint-security.js";

export class ClosingLoopbackConnector implements ModelHttpConnector {
  public readonly closed: Promise<void>;
  readonly #markClosed: () => void;

  public constructor() {
    let markClosed: (() => void) | undefined;
    this.closed = new Promise((resolve) => {
      markClosed = resolve;
    });
    this.#markClosed = () => markClosed?.();
  }

  public async prepare(endpoint: URL): Promise<PreparedModelConnection> {
    return {
      evidence: {
        resolvedAddress: "127.0.0.1",
        addressPinned: true,
        tlsAuthenticated: false,
      },
      send: async (init, signal) =>
        await sendRawLoopbackRequest(endpoint, init, signal, this.#markClosed),
    };
  }
}

async function sendRawLoopbackRequest(
  endpoint: URL,
  init: RequestInit,
  signal: AbortSignal,
  onSocketClose: () => void,
): Promise<Response> {
  const port = Number(endpoint.port);
  if (!Number.isSafeInteger(port) || port <= 0) {
    throw new Error("test connector requires an explicit port");
  }
  return await new Promise<Response>((resolve, reject) => {
    let socket: Socket;
    let responseController:
      | ReadableStreamDefaultController<Uint8Array>
      | undefined;
    let streamCanceled = false;
    let headersComplete = false;
    let headerBuffer = Buffer.alloc(0);
    const body = typeof init.body === "string" ? init.body : "";
    const requestHeaders = new Headers(init.headers);
    requestHeaders.set("content-length", String(Buffer.byteLength(body)));
    requestHeaders.set("connection", "close");
    const serializedHeaders = [...requestHeaders]
      .map(([name, value]) => `${name}: ${value}\r\n`)
      .join("");
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        responseController = controller;
      },
      cancel() {
        streamCanceled = true;
        socket.destroy();
      },
    });
    const abort = (): void => {
      socket.destroy();
    };
    socket = connect({ host: "127.0.0.1", port }, () => {
      signal.addEventListener("abort", abort, { once: true });
      socket.write(
        `${init.method ?? "POST"} ${endpoint.pathname} HTTP/1.1\r\n` +
          `Host: 127.0.0.1:${port}\r\n${serializedHeaders}\r\n${body}`,
      );
    });
    socket.on("data", (chunk: Buffer) => {
      if (headersComplete) {
        responseController?.enqueue(chunk);
        return;
      }
      headerBuffer = Buffer.concat([headerBuffer, chunk]);
      const boundary = headerBuffer.indexOf("\r\n\r\n");
      if (boundary < 0) return;
      const headerText = headerBuffer.subarray(0, boundary).toString("latin1");
      const [statusLine = "", ...headerLines] = headerText.split("\r\n");
      const status = Number(/^HTTP\/1\.1 (\d{3})/u.exec(statusLine)?.[1]);
      const responseHeaders = new Headers();
      for (const line of headerLines) {
        const separator = line.indexOf(":");
        if (separator > 0) {
          responseHeaders.append(
            line.slice(0, separator),
            line.slice(separator + 1).trim(),
          );
        }
      }
      headersComplete = true;
      resolve(new Response(stream, { status, headers: responseHeaders }));
      const remainder = headerBuffer.subarray(boundary + 4);
      if (remainder.length > 0) responseController?.enqueue(remainder);
    });
    socket.once("end", () => {
      if (!streamCanceled) responseController?.close();
    });
    socket.once("error", (error) => {
      if (headersComplete && !streamCanceled) responseController?.error(error);
      else reject(error);
    });
    socket.once("close", () => {
      signal.removeEventListener("abort", abort);
      onSocketClose();
    });
    if (signal.aborted) abort();
  });
}
