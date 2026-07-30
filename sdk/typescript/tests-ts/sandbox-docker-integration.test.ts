import { describe, expect, test } from "bun:test";
import { execFile as execFileCallback } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { SandboxSpec } from "../src/kernel/contracts.js";
import { DockerSandboxAdapter } from "../src/transport/sandbox/adapter.js";
import { DockerCliEngine } from "../src/transport/sandbox/docker-cli.js";
import type { SandboxEvidenceRecord } from "../src/transport/sandbox/types.js";

const execFile = promisify(execFileCallback);
const liveDocker = process.env["CKODEX_LIVE_DOCKER"] === "1";
const imageRef =
  "node@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3";

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

async function residue(names: readonly string[]): Promise<string[]> {
  const { stdout } = await execFile("docker", [
    "ps",
    "--all",
    "--quiet",
    "--filter",
    "label=io.ckodex.sandbox=true",
  ]);
  const ids = stdout.trim().split("\n").filter(Boolean);
  if (ids.length === 0) return [];
  const { stdout: inspected } = await execFile("docker", [
    "inspect",
    "--format",
    "{{.Name}}",
    ...ids,
  ]);
  return inspected
    .trim()
    .split("\n")
    .map((name) => name.replace(/^\//, ""))
    .filter((name) => names.includes(name));
}

describe("live Docker sandbox adapter", () => {
  test.skipIf(!liveDocker)(
    "enforces isolation, limits, digests, termination, and cleanup",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "ckodex-live-sandbox-"));
      const source = join(root, "source");
      const output = join(root, "output");
      const state = join(root, "state");
      const runId = randomUUID();
      const executionIds = [
        `live-success-${runId}`,
        `live-nonzero-${runId}`,
        `live-timeout-${runId}`,
      ];
      const containerNames = executionIds.map((id) => `ckodex-sandbox-${id}`);
      const evidence: SandboxEvidenceRecord[] = [];
      try {
        process.env["CKODEX_LIVE_SECRET"] = "must-not-cross";
        await Promise.all([mkdir(source), mkdir(output), mkdir(state)]);
        await writeFile(join(source, "input.txt"), "immutable source");
        await Promise.all([
          chmod(source, 0o777),
          chmod(output, 0o777),
          chmod(state, 0o777),
        ]);
        let nextExecution = 0;
        const dockerHost = process.env["CKODEX_TEST_DOCKER_HOST"];
        const adapter = new DockerSandboxAdapter({
          engine: new DockerCliEngine(
            dockerHost === undefined ? {} : { host: dockerHost },
          ),
          policy: {
            policyId: "sandbox-policy/live-v1",
            requireNetworkDeny: true,
            allowedDestinations: [],
          },
          evidence: {
            async emit(record) {
              evidence.push(record);
            },
          },
          executionId: () => executionIds[nextExecution++]!,
        });
        const spec: SandboxSpec = {
          imageRef,
          runAsUser: 65532,
          privileged: false,
          linuxCapabilities: [],
          dockerSocketMounted: false,
          ambientCredentials: false,
          network: { mode: "deny" },
          mounts: [
            {
              role: "source",
              source,
              target: "/source",
              access: "read_only",
            },
            {
              role: "output",
              source: output,
              target: "/output",
              access: "read_write",
            },
            {
              role: "state",
              source: state,
              target: "/state",
              access: "read_write",
            },
          ],
          limits: {
            cpuMillis: 500,
            memoryBytes: 268_435_456,
            processCount: 32,
            wallClockMillis: 10_000,
            maxOutputBytes: 4_096,
          },
        };
        const probe = [
          "const fs=require('node:fs'),os=require('node:os');",
          "const denied=(path,value)=>{try{fs.writeFileSync(path,value);return null}catch(error){return error.code}};",
          "const status=fs.readFileSync('/proc/self/status','utf8');",
          "const report={",
          "uid:process.getuid(),",
          "source:fs.readFileSync('/source/input.txt','utf8'),",
          "sourceWriteError:denied('/source/new.txt','mutation'),",
          "rootfsWriteError:denied('/var/tmp/ckodex-rootfs-write','mutation'),",
          "varTmpMode:(fs.statSync('/var/tmp').mode&0o7777).toString(8),",
          "capEff:/^CapEff:\\s+0+$/m.test(status),",
          "noNewPrivileges:/^NoNewPrivs:\\s+1$/m.test(status),",
          "interfaces:Object.keys(os.networkInterfaces()).sort(),",
          "ambientSecret:process.env.CKODEX_LIVE_SECRET??null",
          "};",
          "fs.writeFileSync('/output/live.json',JSON.stringify(report));",
          "fs.writeFileSync('/state/live.state','state writable');",
          "process.stdout.write('live-stdout');process.stderr.write('live-stderr');",
        ].join("");
        const success = await adapter.execute(
          spec,
          ["node", "-e", probe],
          new AbortController().signal,
        );
        const report = JSON.parse(
          await readFile(join(output, "live.json"), "utf8"),
        ) as {
          uid: number;
          source: string;
          sourceWriteError: string;
          rootfsWriteError: string;
          varTmpMode: string;
          capEff: boolean;
          noNewPrivileges: boolean;
          interfaces: string[];
          ambientSecret: string | null;
        };
        expect(success).toMatchObject({
          exitCode: 0,
          termination: "exited",
          stdoutDigest: sha256("live-stdout"),
          stderrDigest: sha256("live-stderr"),
        });
        expect(success.outputDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
        expect(success.durationMillis).toBeGreaterThan(0);
        expect(report).toEqual({
          uid: 65532,
          source: "immutable source",
          sourceWriteError: "EROFS",
          rootfsWriteError: "EROFS",
          varTmpMode: "1777",
          capEff: true,
          noNewPrivileges: true,
          interfaces: ["lo"],
          ambientSecret: null,
        });
        expect(await readFile(join(state, "live.state"), "utf8")).toBe(
          "state writable",
        );

        const nonzero = await adapter.execute(
          spec,
          ["node", "-e", "process.exit(23)"],
          new AbortController().signal,
        );
        expect(nonzero.exitCode).toBe(23);
        expect(nonzero.termination).toBe("exited");

        const timedOut = await adapter.execute(
          {
            ...spec,
            limits: { ...spec.limits, wallClockMillis: 1_000 },
          },
          ["node", "-e", "setInterval(()=>{},1000)"],
          new AbortController().signal,
        );
        expect(timedOut.exitCode).toBe(137);
        expect(timedOut.termination).toBe("timed_out");
        expect(evidence).toHaveLength(3);
        expect(
          evidence.every((item) => item.execution.cleanup === "complete"),
        ).toBe(true);
        expect(
          evidence.every((item) => item.digest.startsWith("sha256:")),
        ).toBe(true);
        expect(await residue(containerNames)).toEqual([]);
      } finally {
        delete process.env["CKODEX_LIVE_SECRET"];
        await rm(root, { recursive: true, force: true });
      }
      process.stdout.write("CKODEX_LIVE_DOCKER_VERIFIED\n");
    },
    30_000,
  );
});
