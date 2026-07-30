import { Readable } from "node:stream";
import type { IncomingMessage } from "node:http";

export function responseFromIncoming(
  incoming: IncomingMessage,
  invalidStatusMessage: string,
): Response {
  const status = incoming.statusCode ?? 0;
  if (status < 200 || status > 599) {
    incoming.destroy();
    throw new Error(invalidStatusMessage);
  }
  const body =
    status === 204 || status === 205 || status === 304
      ? null
      : (Readable.toWeb(incoming) as unknown as ReadableStream<Uint8Array>);
  return new Response(body, {
    status,
    statusText: incoming.statusMessage,
    headers: headersFromIncoming(incoming),
  });
}

function headersFromIncoming(incoming: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) {
      headers.append(name, item);
    }
  }
  return headers;
}

export function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException("operation aborted", "AbortError");
}
