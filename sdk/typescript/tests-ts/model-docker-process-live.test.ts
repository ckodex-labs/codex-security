import { execFile as execFileCallback } from "node:child_process";
import {
  chmod,
  mkdtemp,
  mkdir,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, test } from "bun:test";
import {
  createProductionLocalProcessRuntime,
  DockerModelProcessRunner,
  executeComposedModel,
  type DockerModelProcessEvidence,
  type ModelExecutionEvent,
  type ModelExecutionRequest,
} from "../src/index.js";

const execFile = promisify(execFileCallback);
const liveDocker = process.env["CKODEX_LIVE_DOCKER"] === "1";
const imageRef =
  "node@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3";

describe("live Docker model process runner", () => {
  test.skipIf(!liveDocker)(
    "proves streamed execution, isolation, bounds, evidence, and cleanup",
    verifyLiveModelRunner,
    60_000,
  );
});

async function verifyLiveModelRunner(): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "ckodex-live-model-"));
  const assets = join(root, "assets");
  await mkdir(assets);
  await writeFile(join(assets, "model.txt"), "pinned fixture model");
  await chmod(root, 0o755);
  await chmod(assets, 0o555);
  await chmod(join(assets, "model.txt"), 0o444);
  const beforeEnv = await environmentDirectories();
  const evidence: DockerModelProcessEvidence[] = [];
  const runner = liveRunner(assets, evidence);
  process.env["CKODEX_LIVE_MODEL_SECRET"] = "must-not-cross";
  try {
    const events = await phase(
      "success",
      collect(executeFixture(runner, request("success"), "success")),
    );
    verifySecurityProbe(events);
    await expect(
      collect(executeFixture(runner, request("overflow", 32), "overflow")),
    ).rejects.toThrow("byte limit");
    await expect(
      collect(executeFixture(runner, request("timeout", 4096, 500), "hang")),
    ).rejects.toThrow();
    await verifyCancellation(runner);
    verifyEvidence(evidence);
    expect(await modelResidue()).toEqual([]);
    expect(await environmentDirectories()).toEqual(beforeEnv);
  } finally {
    delete process.env["CKODEX_LIVE_MODEL_SECRET"];
    await chmod(assets, 0o755);
    await rm(root, { recursive: true, force: true });
  }
  process.stdout.write("CKODEX_LIVE_MODEL_PROCESS_VERIFIED\n");
}

async function phase<T>(name: string, operation: Promise<T>): Promise<T> {
  try {
    return await operation;
  } catch (error) {
    throw new Error(`live model phase ${name} failed`, { cause: error });
  }
}

function liveRunner(
  assets: string,
  evidence: DockerModelProcessEvidence[],
): DockerModelProcessRunner {
  const dockerHost = process.env["CKODEX_TEST_DOCKER_HOST"];
  return new DockerModelProcessRunner({
    imageRef,
    executable: "/usr/local/bin/node",
    runAsUser: 65532,
    allowedEnvironmentNames: ["FIXTURE_ALLOWED"],
    mounts: [{ source: assets, target: "/model-assets" }],
    cpuMillis: 500,
    memoryBytes: 268_435_456,
    processCount: 32,
    ...(dockerHost === undefined ? {} : { dockerHost }),
    evidence: { emit: async (record) => void evidence.push(record) },
  });
}

function request(
  requestId: string,
  maxResponseBytes = 16_384,
  wallClockMillis = 10_000,
): ModelExecutionRequest {
  return {
    requestId,
    systemPrompt: "Inspect.",
    input: "Run.",
    requiredCapabilities: ["streaming", "usage_accounting", "cancellation"],
    limits: {
      maxRequestBytes: 4096,
      maxResponseBytes,
      maxToolArgumentBytes: 1024,
      headerTimeoutMillis: 1000,
      streamIdleTimeoutMillis: 1000,
      wallClockMillis,
    },
  };
}

function executeFixture(
  runner: DockerModelProcessRunner,
  modelRequest: ModelExecutionRequest,
  mode: string,
  signal = new AbortController().signal,
): AsyncIterable<ModelExecutionEvent> {
  const runtime = createProductionLocalProcessRuntime({
    mode: "direct_model_port",
    adapterId: "live-docker-process",
    modelId: "fixture-model",
    executable: "/usr/local/bin/node",
    arguments: ["-e", fixtureProgram(), mode],
    environment: { FIXTURE_ALLOWED: "yes" },
    features: new Set(["streaming", "usage_accounting", "cancellation"]),
    runner,
  });
  if (runtime.mode !== "direct_model_port") throw new Error("wrong runtime");
  return executeComposedModel(
    {
      descriptor: runtime.descriptor,
      registrations: [runtime.registration],
      policy: {
        policyId: "live-docker-model-v1",
        allowedTransports: ["local_process"],
        requiredCapabilities: modelRequest.requiredCapabilities,
        requirePrivateEndpoint: true,
        requireTlsForRemote: true,
        requireDerivedEndpointSecurity: true,
      },
      evidence: { record: async () => undefined },
      observer: { emit: async () => undefined },
    },
    modelRequest,
    signal,
  );
}

async function verifyCancellation(
  runner: DockerModelProcessRunner,
): Promise<void> {
  const controller = new AbortController();
  const pending = collect(
    executeFixture(runner, request("canceled"), "hang", controller.signal),
  );
  setTimeout(() => controller.abort(), 250);
  expect((await pending).at(-1)).toMatchObject({ kind: "canceled" });
}

function verifySecurityProbe(events: readonly ModelExecutionEvent[]): void {
  const delta = events.find((event) => event.kind === "output_delta");
  if (delta?.kind !== "output_delta") throw new Error("missing probe output");
  if (delta.text.startsWith("fixture-error:")) throw new Error(delta.text);
  expect(JSON.parse(delta.text)).toEqual({
    uid: 65532,
    model: "pinned fixture model",
    sourceWriteError: "EROFS",
    rootWriteError: "EROFS",
    tmpWritable: true,
    capEffZero: true,
    noNewPrivileges: true,
    interfaces: ["lo"],
    networkDenied: true,
    ambientSecret: null,
    dockerSocket: false,
  });
}

function verifyEvidence(evidence: readonly DockerModelProcessEvidence[]): void {
  expect(evidence.map((item) => item.execution.termination).sort()).toEqual([
    "canceled",
    "exited",
    "output_limited",
    "timed_out",
  ]);
  expect(evidence.every((item) => item.execution.cleanup === "complete")).toBe(
    true,
  );
  expect(evidence.every((item) => item.digest.startsWith("sha256:"))).toBe(
    true,
  );
  expect(JSON.stringify(evidence)).not.toContain("must-not-cross");
}

async function collect<T>(values: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const value of values) result.push(value);
  return result;
}

async function modelResidue(): Promise<string[]> {
  const { stdout } = await execFile("docker", [
    ...(process.env["CKODEX_TEST_DOCKER_HOST"] === undefined
      ? []
      : ["--host", process.env["CKODEX_TEST_DOCKER_HOST"]]),
    "ps",
    "--all",
    "--quiet",
    "--filter",
    "label=io.ckodex.model-process=true",
  ]);
  return stdout.trim().split("\n").filter(Boolean);
}

async function environmentDirectories(): Promise<string[]> {
  return (await readdir(tmpdir()))
    .filter((name) => name.startsWith("ckodex-model-env-"))
    .sort();
}

function fixtureProgram(): string {
  return [
    "(async()=>{try{",
    "const fs=require('node:fs'),os=require('node:os');",
    "let body='';for await(const chunk of process.stdin)body+=chunk;",
    "if(JSON.parse(body.trim()).type!=='execute')process.exit(8);",
    "const mode=process.argv[1];",
    "if(mode==='overflow'){process.stdout.write('x'.repeat(4096));await new Promise(()=>setInterval(()=>{},1000));}",
    "if(mode==='hang')await new Promise(()=>setInterval(()=>{},1000));",
    "const denied=(path)=>{try{fs.writeFileSync(path,'x');return null}catch(e){return e.code}};",
    "const status=fs.readFileSync('/proc/self/status','utf8');",
    "let networkDenied=false;try{await fetch('http://1.1.1.1',{signal:AbortSignal.timeout(500)})}catch{networkDenied=true}",
    "const report={uid:process.getuid(),model:fs.readFileSync('/model-assets/model.txt','utf8'),",
    "sourceWriteError:denied('/model-assets/new'),rootWriteError:denied('/var/tmp/new'),",
    "tmpWritable:denied('/tmp/ok')===null,capEffZero:/^CapEff:\\s+0+$/m.test(status),",
    "noNewPrivileges:/^NoNewPrivs:\\s+1$/m.test(status),interfaces:Object.keys(os.networkInterfaces()).sort(),",
    "networkDenied,ambientSecret:process.env.CKODEX_LIVE_MODEL_SECRET??null,",
    "dockerSocket:fs.existsSync('/var/run/docker.sock')};",
    "for(const event of [{kind:'response_metadata',sequence:0,responseId:'live-response'},",
    "{kind:'output_delta',sequence:1,text:JSON.stringify(report)},",
    "{kind:'usage',sequence:2,inputTokens:1,outputTokens:1,totalTokens:2},",
    "{kind:'completed',sequence:3,finishReason:'stop',responseId:'live-response'}])",
    "process.stdout.write(JSON.stringify(event)+'\\n');",
    "}catch(error){process.stdout.write(JSON.stringify({kind:'output_delta',sequence:0,text:'fixture-error:'+error.message})+'\\n');",
    "process.stdout.write(JSON.stringify({kind:'completed',sequence:1,finishReason:'stop',responseId:'fixture-error'})+'\\n');}})();",
  ].join("");
}
