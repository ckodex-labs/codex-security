import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import {
  createProductionLocalProcessRuntime,
  DockerModelProcessRunner,
  executeComposedModel,
  type DockerModelProcessEvidence,
  type ModelExecutionEvent,
  type ModelExecutionRequest,
} from "../src/index.js";

const imageRef = `fixture/model@sha256:${"a".repeat(64)}`;
const request: ModelExecutionRequest = {
  requestId: "docker-process-request",
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
};

describe("Docker model process runner", () => {
  test("fails closed on unsafe configuration", rejectUnsafeConfiguration);
  test("rejects mount escapes and overlaps", rejectUnsafeMounts);
  test("emits scrubbed failure evidence before spawn", verifyFailureEvidence);
  test("streams and emits scrubbed evidence", executeDockerFixture);
  test("preserves output-limit termination evidence", verifyOutputLimit);
  test("keeps cancellation and cleanup idempotent", verifyRepeatedCancellation);
  test("retains the explicit bridge path", verifyBridgeCompatibility);
});

async function rejectUnsafeConfiguration(): Promise<void> {
  const evidence: DockerModelProcessEvidence[] = [];
  expect(
    () =>
      new DockerModelProcessRunner({
        ...runnerOptions("/bin/false", evidence),
        imageRef: "fixture/model:latest",
      }),
  ).toThrow("digest-pinned");
  const runner = new DockerModelProcessRunner(
    runnerOptions("/bin/false", evidence),
  );
  await expect(
    runner.start(processSpec("/different", {}), new AbortController().signal),
  ).rejects.toThrow("fixed sandbox executable");
  await expect(
    runner.start(
      processSpec("/model", { AMBIENT_SECRET: "no" }),
      new AbortController().signal,
    ),
  ).rejects.toThrow("not allowed");
}

function processSpec(
  executable: string,
  environment: Readonly<Record<string, string>>,
) {
  return {
    executable,
    arguments: [],
    environment,
    maxStdoutBytes: 10,
    maxStderrBytes: 10,
    wallClockMillis: 10,
  };
}

async function executeDockerFixture(): Promise<void> {
  const fixture = await dockerFixture();
  const evidence: DockerModelProcessEvidence[] = [];
  const runner = new DockerModelProcessRunner(
    runnerOptions(fixture.docker, evidence),
  );
  const events = await executeDirectRuntime(runner);
  expect(events.map((event) => event.kind)).toEqual([
    "response_metadata",
    "usage",
    "completed",
  ]);
  expect(JSON.stringify(evidence)).not.toContain("secret-value");
  expect(evidence[0]?.execution).toMatchObject({
    imageRef,
    executable: "/model",
    environmentNames: ["FIXTURE_TOKEN"],
    termination: "exited",
    cleanup: "complete",
  });
  const invocations = await readFile(fixture.calls, "utf8");
  expect(invocations).toContain('"--network","none"');
  expect(invocations).toContain('"--read-only"');
  expect(invocations).toContain('"--cap-drop=ALL"');
  expect(invocations).not.toContain("secret-value");
}

async function dockerFixture(): Promise<{ docker: string; calls: string }> {
  const root = await mkdtemp(join(tmpdir(), "ckodex-fake-docker-"));
  const docker = join(root, "docker.mjs");
  const calls = join(root, "calls.jsonl");
  await writeFile(docker, fakeDockerSource(calls), { mode: 0o700 });
  await chmod(docker, 0o700);
  return { docker, calls };
}

async function rejectUnsafeMounts(): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "ckodex-model-mount-"));
  const evidence: DockerModelProcessEvidence[] = [];
  const common = runnerOptions("/bin/false", evidence);
  const badTarget = new DockerModelProcessRunner({
    ...common,
    mounts: [{ source: root, target: "/model/../escape" }],
  });
  await expect(
    badTarget.start(processSpec("/model", {}), new AbortController().signal),
  ).rejects.toThrow("canonical absolute paths");
  const overlap = new DockerModelProcessRunner({
    ...common,
    mounts: [
      { source: root, target: "/model" },
      { source: root, target: "/other" },
    ],
  });
  await expect(
    overlap.start(processSpec("/model", {}), new AbortController().signal),
  ).rejects.toThrow("source paths overlap");
}

async function verifyFailureEvidence(): Promise<void> {
  const evidence: DockerModelProcessEvidence[] = [];
  const runner = new DockerModelProcessRunner(
    runnerOptions("/does/not/exist/docker", evidence),
  );
  await expect(
    runner.start(
      processSpec("/model", { FIXTURE_TOKEN: "secret-value" }),
      new AbortController().signal,
    ),
  ).rejects.toThrow();
  expect(evidence).toHaveLength(1);
  expect(evidence[0]?.execution).toMatchObject({
    termination: "failed",
    cleanup: "not_started",
    environmentNames: ["FIXTURE_TOKEN"],
  });
  expect(JSON.stringify(evidence)).not.toContain("secret-value");
}

async function verifyRepeatedCancellation(): Promise<void> {
  const fixture = await dockerFixture();
  const evidence: DockerModelProcessEvidence[] = [];
  const runner = new DockerModelProcessRunner({
    ...runnerOptions(fixture.docker, evidence),
    executionId: () => "fixed-cancel-id",
  });
  const session = await runner.start(
    {
      ...processSpec("/model", { FIXTURE_TOKEN: "secret-value" }),
      wallClockMillis: 5000,
    },
    new AbortController().signal,
  );
  await expect(
    runner.start(
      processSpec("/model", { FIXTURE_TOKEN: "secret-value" }),
      new AbortController().signal,
    ),
  ).rejects.toThrow("already active");
  await Promise.all([session.cancel(), session.cancel(), session.cancel()]);
  expect(evidence).toHaveLength(2);
  expect(evidence[1]?.execution).toMatchObject({
    termination: "canceled",
    cleanup: "complete",
  });
  const calls = (await readFile(fixture.calls, "utf8")).trim().split("\n");
  expect(calls.filter((line) => line.startsWith('["rm"'))).toHaveLength(2);
}

async function verifyOutputLimit(): Promise<void> {
  const fixture = await dockerFixture();
  const evidence: DockerModelProcessEvidence[] = [];
  const runner = new DockerModelProcessRunner(
    runnerOptions(fixture.docker, evidence),
  );
  const session = await runner.start(
    {
      ...processSpec("/model", { FIXTURE_TOKEN: "secret-value" }),
      arguments: ["overflow"],
      maxStdoutBytes: 8,
      wallClockMillis: 5000,
    },
    new AbortController().signal,
  );
  await expect(collectBytes(session.stdout)).rejects.toThrow("byte limit");
  await session.completion;
  expect(evidence[0]?.execution).toMatchObject({
    termination: "output_limited",
    cleanup: "complete",
  });
}

async function collectBytes(source: AsyncIterable<Uint8Array>): Promise<void> {
  for await (const _chunk of source) {
    // Consumption is required to surface the bounded stream error.
  }
}

async function executeDirectRuntime(
  runner: DockerModelProcessRunner,
): Promise<ModelExecutionEvent[]> {
  const runtime = createProductionLocalProcessRuntime({
    mode: "direct_model_port",
    adapterId: "docker-process",
    modelId: "fixture-model",
    executable: "/model",
    environment: { FIXTURE_TOKEN: "secret-value" },
    features: new Set(["streaming", "usage_accounting"]),
    runner,
  });
  if (runtime.mode !== "direct_model_port") throw new Error("wrong runtime");
  const events: ModelExecutionEvent[] = [];
  for await (const event of executeComposedModel(
    {
      descriptor: runtime.descriptor,
      registrations: [runtime.registration],
      policy: {
        policyId: "docker-model-v1",
        allowedTransports: ["local_process"],
        requiredCapabilities: request.requiredCapabilities,
        requirePrivateEndpoint: true,
        requireTlsForRemote: true,
        requireDerivedEndpointSecurity: true,
      },
      evidence: { record: async () => undefined },
      observer: { emit: async () => undefined },
    },
    request,
    new AbortController().signal,
  )) {
    events.push(event);
  }
  return events;
}

function verifyBridgeCompatibility(): void {
  expect(
    createProductionLocalProcessRuntime({
      mode: "codex_loopback_bridge",
      id: "ckodex-process",
      model: "fixture-model",
      bridgeBaseUrl: "http://127.0.0.1:19090/v1",
    }),
  ).toEqual({
    mode: "codex_loopback_bridge",
    scanProvider: {
      kind: "local_process",
      id: "ckodex-process",
      model: "fixture-model",
      bridgeBaseUrl: "http://127.0.0.1:19090/v1",
    },
  });
}

function runnerOptions(
  dockerExecutable: string,
  evidence: DockerModelProcessEvidence[],
) {
  return {
    imageRef,
    executable: "/model",
    runAsUser: 65532,
    allowedEnvironmentNames: ["FIXTURE_TOKEN"],
    cpuMillis: 500,
    memoryBytes: 128 * 1024 * 1024,
    processCount: 16,
    dockerExecutable,
    evidence: {
      emit: async (record: DockerModelProcessEvidence) => {
        evidence.push(record);
      },
    },
  };
}

function fakeDockerSource(calls: string): string {
  return `#!/usr/bin/env node
import {appendFileSync,readFileSync} from "node:fs";
appendFileSync(${JSON.stringify(calls)},JSON.stringify(process.argv.slice(2))+"\\n");
if(process.argv[2]==="rm") process.exit(0);
const at=process.argv.indexOf("--env-file");
const env=readFileSync(process.argv[at+1],"utf8");
if(!env.includes("FIXTURE_TOKEN=secret-value")) process.exit(9);
if(process.argv.includes("overflow")) { process.stdout.write("x".repeat(128)); await new Promise(()=>{}); }
let input=""; for await (const chunk of process.stdin) input+=chunk;
if(JSON.parse(input.trim()).type!=="execute") process.exit(8);
for(const event of [
 {kind:"response_metadata",sequence:0,responseId:"docker-response"},
 {kind:"usage",sequence:1,inputTokens:1,outputTokens:1,totalTokens:2},
 {kind:"completed",sequence:2,finishReason:"stop",responseId:"docker-response"}
]) process.stdout.write(JSON.stringify(event)+"\\n");
`;
}
