export interface ServerSentEvent {
  event?: string;
  data: string;
}

export interface SseLimits {
  maxResponseBytes: number;
  maxEventBytes: number;
  streamIdleTimeoutMillis: number;
}

interface ByteReader {
  read(): Promise<
    { done: false; value: Uint8Array } | { done: true; value?: Uint8Array }
  >;
}

class SseDecoder {
  readonly #maxEventBytes: number;
  #buffer = "";
  #eventLines: string[] = [];
  #eventBytes = 0;

  public constructor(maxEventBytes: number) {
    this.#maxEventBytes = maxEventBytes;
  }

  public push(text: string, eof = false): ServerSentEvent[] {
    this.#buffer += text;
    const events: ServerSentEvent[] = [];
    let offset = 0;
    while (offset < this.#buffer.length) {
      const ending = findLineEnding(this.#buffer, offset, eof);
      if (ending === null) break;
      const line = this.#buffer.slice(offset, ending.index);
      offset = ending.next;
      const event = this.#acceptLine(line);
      if (event !== null) events.push(event);
    }
    this.#buffer = this.#buffer.slice(offset);
    if (
      Buffer.byteLength(this.#buffer, "utf8") + this.#eventBytes >
      this.#maxEventBytes
    ) {
      throw new Error("model SSE event exceeded its byte limit");
    }
    if (eof) {
      if (this.#buffer !== "") {
        const event = this.#acceptLine(this.#buffer);
        if (event !== null) events.push(event);
        this.#buffer = "";
      }
      const trailing = this.#dispatch();
      if (trailing !== null) events.push(trailing);
    }
    return events;
  }

  #acceptLine(line: string): ServerSentEvent | null {
    this.#eventBytes += Buffer.byteLength(line, "utf8") + 2;
    if (this.#eventBytes > this.#maxEventBytes) {
      throw new Error("model SSE event exceeded its byte limit");
    }
    if (line === "") return this.#dispatch();
    this.#eventLines.push(line);
    return null;
  }

  #dispatch(): ServerSentEvent | null {
    const lines = this.#eventLines;
    this.#eventLines = [];
    this.#eventBytes = 0;
    if (lines.length === 0) return null;
    return parseEvent(lines);
  }
}

export async function* parseServerSentEvents(
  body: ReadableStream<Uint8Array>,
  limits: SseLimits,
  signal: AbortSignal,
  onIdleTimeout: () => void,
): AsyncGenerator<ServerSentEvent> {
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const sse = new SseDecoder(limits.maxEventBytes);
  let responseBytes = 0;
  try {
    while (true) {
      throwIfAborted(signal);
      const result = await readWithIdleTimeout(
        reader,
        limits.streamIdleTimeoutMillis,
        onIdleTimeout,
      );
      if (result.done) break;
      responseBytes += result.value.byteLength;
      if (responseBytes > limits.maxResponseBytes) {
        throw new Error("model response exceeded its byte limit");
      }
      for (const event of sse.push(
        decoder.decode(result.value, { stream: true }),
      )) {
        yield event;
      }
    }
    for (const event of sse.push(decoder.decode(), true)) yield event;
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

function parseEvent(lines: readonly string[]): ServerSentEvent | null {
  const parsed = lines.filter((line) => !line.startsWith(":")).map(parseField);
  const event = parsed.find(({ field }) => field === "event")?.value;
  const data = parsed
    .filter(({ field }) => field === "data")
    .map(({ value }) => value);
  if (data.length === 0) return null;
  return { ...(event === undefined ? {} : { event }), data: data.join("\n") };
}

function parseField(line: string): { field: string; value: string } {
  const separator = line.indexOf(":");
  const field = separator < 0 ? line : line.slice(0, separator);
  const rawValue = separator < 0 ? "" : line.slice(separator + 1);
  return {
    field,
    value: rawValue.startsWith(" ") ? rawValue.slice(1) : rawValue,
  };
}

function findLineEnding(
  value: string,
  offset: number,
  eof: boolean,
): { index: number; next: number } | null {
  for (let index = offset; index < value.length; index += 1) {
    const character = value[index];
    if (character === "\n") return { index, next: index + 1 };
    if (character !== "\r") continue;
    if (index + 1 === value.length && !eof) return null;
    return {
      index,
      next: value[index + 1] === "\n" ? index + 2 : index + 1,
    };
  }
  return null;
}

async function readWithIdleTimeout(
  reader: ByteReader,
  timeoutMillis: number,
  onIdleTimeout: () => void,
): Promise<
  { done: false; value: Uint8Array } | { done: true; value?: Uint8Array }
> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      reader.read(),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          onIdleTimeout();
          reject(new Error("model response stream timed out"));
        }, timeoutMillis);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) {
    throw signal.reason ?? new DOMException("aborted", "AbortError");
  }
}
