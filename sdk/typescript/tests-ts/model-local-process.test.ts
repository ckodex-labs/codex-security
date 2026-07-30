import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, test } from "bun:test";
import type {
  ModelProcessSession,
  ModelProcessSpec,
  SandboxedModelProcessRunnerPort,
} from "../src/kernel/ports.js";
import { LocalProcessModelAdapter } from "../src/transport/model/local-process.js";

class FixtureSandboxRunner implements SandboxedModelProcessRunnerPort {
  public seenEnvironment?: Readonly<Record<string, string>>;

  public async start(
    spec: ModelProcessSpec,
    signal: AbortSignal,
  ): Promise<ModelProcessSession> {
    this.seenEnvironment = spec.environment;
    const child = spawn(spec.executable, spec.arguments, {
      env: { ...spec.environment },
      detached: process.platform !== "win32",
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const timer = setTimeout(() => killTree(child), spec.wallClockMillis);
    const abort = (): void => killTree(child);
    signal.addEventListener("abort", abort, { once: true });
    const completion = new Promise<{
      exitCode: number | null;
      signal: string | null;
    }>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (exitCode, childSignal) => {
        clearTimeout(timer);
        signal.removeEventListener("abort", abort);
        resolve({ exitCode, signal: childSignal });
      });
    });
    return {
      stdout: child.stdout,
      stderr: child.stderr,
      write: async (chunk) => await writeChunk(child, chunk),
      closeInput: async () => {
        child.stdin.end();
      },
      cancel: async () => {
        killTree(child);
        await completion;
      },
      completion,
    };
  }
}

describe("local process model adapter", () => {
  test("streams bounded NDJSON through a scrubbed runner environment", async () => {
    const fixture = await fixtureScript();
    const runner = new FixtureSandboxRunner();
    process.env["AMBIENT_MODEL_SECRET"] = "must-not-cross";
    const adapter = new LocalProcessModelAdapter(
      {
        providerId: "local-process",
        modelId: "fixture-model",
        executable: process.execPath,
        arguments: [fixture],
        environment: { FIXTURE_ALLOWED: "yes" },
        features: new Set(["streaming", "usage_accounting", "cancellation"]),
      },
      runner,
    );
    const events = [];
    try {
      for await (const event of adapter.execute(
        {
          requestId: "process-request",
          systemPrompt: "Inspect.",
          input: "Run.",
          requiredCapabilities: ["streaming", "usage_accounting"],
          limits: {
            maxRequestBytes: 4096,
            maxResponseBytes: 4096,
            maxToolArgumentBytes: 1024,
            headerTimeoutMillis: 1000,
            streamIdleTimeoutMillis: 1000,
            wallClockMillis: 5000,
          },
        },
        new AbortController().signal,
      )) {
        events.push(event);
      }
    } finally {
      delete process.env["AMBIENT_MODEL_SECRET"];
    }
    expect(runner.seenEnvironment).toEqual({ FIXTURE_ALLOWED: "yes" });
    expect(events.map((event) => event.kind)).toEqual([
      "response_metadata",
      "usage",
      "completed",
    ]);
  });

  test("kills the process group when execution is canceled", async () => {
    const fixture = await fixtureScript();
    const adapter = new LocalProcessModelAdapter(
      {
        providerId: "local-process",
        modelId: "fixture-model",
        executable: process.execPath,
        arguments: [fixture, "hang"],
        features: new Set(["streaming", "cancellation"]),
      },
      new FixtureSandboxRunner(),
    );
    const controller = new AbortController();
    const events = adapter.execute(
      {
        requestId: "process-cancel",
        systemPrompt: "Inspect.",
        input: "Run.",
        requiredCapabilities: ["streaming", "cancellation"],
        limits: {
          maxRequestBytes: 4096,
          maxResponseBytes: 4096,
          maxToolArgumentBytes: 1024,
          headerTimeoutMillis: 1000,
          streamIdleTimeoutMillis: 1000,
          wallClockMillis: 5000,
        },
      },
      controller.signal,
    );
    const pending = events[Symbol.asyncIterator]().next();
    await Bun.sleep(50);
    controller.abort();
    expect(await pending).toMatchObject({
      value: { kind: "canceled", reason: "operation aborted" },
    });
  });

  test("enforces subprocess request and response byte limits", async () => {
    const fixture = await fixtureScript();
    const adapter = new LocalProcessModelAdapter(
      {
        providerId: "local-process",
        modelId: "fixture-model",
        executable: process.execPath,
        arguments: [fixture],
        environment: { FIXTURE_ALLOWED: "yes" },
        features: new Set(["streaming"]),
      },
      new FixtureSandboxRunner(),
    );
    const baseRequest = {
      requestId: "process-bounds",
      systemPrompt: "Inspect.",
      input: "Run.",
      requiredCapabilities: ["streaming"] as const,
      limits: {
        maxRequestBytes: 4096,
        maxResponseBytes: 4096,
        maxToolArgumentBytes: 1024,
        headerTimeoutMillis: 1000,
        streamIdleTimeoutMillis: 1000,
        wallClockMillis: 5000,
      },
    };
    await expect(
      collect(
        adapter.execute(
          {
            ...baseRequest,
            limits: { ...baseRequest.limits, maxRequestBytes: 1 },
          },
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("request exceeded its byte limit");
    await expect(
      collect(
        adapter.execute(
          {
            ...baseRequest,
            requestId: "process-response-bounds",
            limits: { ...baseRequest.limits, maxResponseBytes: 16 },
          },
          new AbortController().signal,
        ),
      ),
    ).rejects.toThrow("stdout exceeded its byte limit");
  });
});

async function collect<T>(values: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const value of values) result.push(value);
  return result;
}

async function fixtureScript(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codex-process-model-"));
  const path = join(directory, "model.mjs");
  await writeFile(
    path,
    `
process.stdin.setEncoding("utf8");
let body = "";
for await (const chunk of process.stdin) body += chunk;
if (process.argv[2] === "hang") await new Promise(() => {});
if (process.env.AMBIENT_MODEL_SECRET) process.exit(9);
if (process.env.FIXTURE_ALLOWED !== "yes") process.exit(8);
const envelope = JSON.parse(body.trim());
if (envelope.type !== "execute") process.exit(7);
for (const event of [
  {kind:"response_metadata",sequence:0,responseId:"process-response"},
  {kind:"usage",sequence:1,inputTokens:1,outputTokens:1,totalTokens:2},
  {kind:"completed",sequence:2,finishReason:"stop",responseId:"process-response"}
]) process.stdout.write(JSON.stringify(event) + "\\n");
`,
    { mode: 0o500 },
  );
  return path;
}

async function writeChunk(
  child: ChildProcessWithoutNullStreams,
  chunk: Uint8Array,
): Promise<void> {
  if (child.stdin.write(chunk)) return;
  await new Promise<void>((resolve) => child.stdin.once("drain", resolve));
}

function killTree(child: ChildProcessWithoutNullStreams): void {
  if (child.pid === undefined || child.killed) return;
  if (process.platform === "win32") {
    child.kill("SIGKILL");
    return;
  }
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    child.kill("SIGKILL");
  }
}
