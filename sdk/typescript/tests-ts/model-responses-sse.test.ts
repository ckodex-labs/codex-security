import { describe, expect, test } from "bun:test";
import { parseServerSentEvents } from "../src/transport/model/responses-sse.js";

function chunkedBody(chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

describe("bounded model SSE parsing", () => {
  test("handles chunk boundaries, CRLF, comments, and multiline data", async () => {
    const events = [];
    for await (const event of parseServerSentEvents(
      chunkedBody([
        ': heartbeat\r\nevent: response.created\r\ndata: {"a":',
        "1}\r\n\r\ndata: first\ndata: second\n\n",
      ]),
      {
        maxResponseBytes: 1024,
        maxEventBytes: 512,
        streamIdleTimeoutMillis: 1_000,
      },
      new AbortController().signal,
      () => undefined,
    )) {
      events.push(event);
    }
    expect(events).toEqual([
      { event: "response.created", data: '{"a":1}' },
      { data: "first\nsecond" },
    ]);
  });

  test("does not split an event when CRLF itself crosses chunks and dispatches at EOF", async () => {
    const events = [];
    for await (const event of parseServerSentEvents(
      chunkedBody([
        "event: response.created\r",
        '\ndata: {"id":"one"}\r',
        "\n\r",
        '\ndata: {"id":"eof"}',
      ]),
      {
        maxResponseBytes: 1024,
        maxEventBytes: 512,
        streamIdleTimeoutMillis: 1_000,
      },
      new AbortController().signal,
      () => undefined,
    )) {
      events.push(event);
    }
    expect(events).toEqual([
      { event: "response.created", data: '{"id":"one"}' },
      { data: '{"id":"eof"}' },
    ]);
  });

  test("fails before an oversized event can be consumed", async () => {
    const collect = async (): Promise<void> => {
      for await (const _event of parseServerSentEvents(
        chunkedBody([`data: ${"x".repeat(40)}\n\n`]),
        {
          maxResponseBytes: 256,
          maxEventBytes: 32,
          streamIdleTimeoutMillis: 1_000,
        },
        new AbortController().signal,
        () => undefined,
      )) {
        // The parser must reject before yielding this event.
      }
    };
    await expect(collect()).rejects.toThrow("event exceeded");
  });
});
