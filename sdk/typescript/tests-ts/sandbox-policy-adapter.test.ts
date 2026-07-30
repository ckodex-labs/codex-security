import { describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SandboxResult, SandboxSpec } from "../src/kernel/contracts.js";
import { DockerSandboxAdapter } from "../src/transport/sandbox/adapter.js";
import type {
  EngineRunRequest,
  SandboxContainerEngine,
  SandboxEvidenceRecord,
} from "../src/transport/sandbox/types.js";
import {
  SandboxExecutionError,
  SandboxPolicyDeniedError,
} from "../src/transport/sandbox/types.js";

class RecordingEngine implements SandboxContainerEngine {
  readonly id = "recording-engine/v1";
  readonly destinationAllowlistEnforced: boolean;
  readonly runs: EngineRunRequest[] = [];
  readonly removals: string[] = [];
  result = {
    exitCode: 0,
    stdout: new TextEncoder().encode("stdout"),
    stderr: new TextEncoder().encode("stderr"),
  };

  constructor(allowlist = false) {
    this.destinationAllowlistEnforced = allowlist;
  }

  destinationAllowlistNetwork(_destinations: readonly string[]): string {
    return "ckodex-allowlist";
  }

  async run(request: EngineRunRequest): Promise<typeof this.result> {
    this.runs.push(request);
    return this.result;
  }

  async remove(containerName: string): Promise<void> {
    this.removals.push(containerName);
  }
}

async function fixture(): Promise<{
  spec: SandboxSpec;
  output: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "ckodex-sandbox-test-"));
  const source = join(root, "source");
  const output = join(root, "output");
  const state = join(root, "state");
  await Promise.all([
    mkdir(source),
    mkdir(output),
    mkdir(state),
    writeFile(join(root, "outside"), "unrelated"),
  ]);
  return {
    output,
    spec: {
      imageRef:
        "registry.example/scanner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
          target: "/workspace",
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
        memoryBytes: 134_217_728,
        processCount: 16,
        wallClockMillis: 5_000,
        maxOutputBytes: 65_536,
      },
    },
  };
}

function adapter(
  engine: SandboxContainerEngine,
  evidence: SandboxEvidenceRecord[],
): DockerSandboxAdapter {
  let clock = Date.parse("2026-07-29T12:00:00.000Z");
  return new DockerSandboxAdapter({
    engine,
    policy: {
      policyId: "sandbox-policy/v1",
      requireNetworkDeny: false,
      allowedDestinations: ["api.example.test:443"],
    },
    evidence: {
      async emit(record) {
        evidence.push(record);
      },
    },
    executionId: () => "execution-1",
    now: () => new Date((clock += 5)),
  });
}

describe("Docker sandbox adapter", () => {
  test("gates before the engine and records a host denial receipt", async () => {
    const { spec } = await fixture();
    const engine = new RecordingEngine();
    const evidence: SandboxEvidenceRecord[] = [];
    await expect(
      adapter(engine, evidence).execute(
        { ...spec, runAsUser: 0 },
        ["scanner"],
        new AbortController().signal,
      ),
    ).rejects.toBeInstanceOf(SandboxPolicyDeniedError);
    expect(engine.runs).toHaveLength(0);
    expect(engine.removals).toHaveLength(0);
    expect(evidence[0]?.execution.verdict).toBe("deny");
  });

  test("maps every isolation and resource constraint to argv without a shell", async () => {
    const { spec, output } = await fixture();
    await writeFile(join(output, "receipt.json"), "{}");
    const engine = new RecordingEngine();
    engine.result.exitCode = 23;
    const evidence: SandboxEvidenceRecord[] = [];
    const result = await adapter(engine, evidence).execute(
      spec,
      ["scanner", "argument with spaces", "$(not-a-shell)"],
      new AbortController().signal,
    );
    expect(result.exitCode).toBe(23);
    expect(result.termination).toBe("exited");
    expect(result.stdoutDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(result.outputDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    const args = engine.runs[0]?.args ?? [];
    expect(args).not.toContain("--rm");
    expect(args).toContain("--pull=never");
    expect(args).toContain("--privileged=false");
    expect(args).toContain("--cap-drop=ALL");
    expect(args).toContain("no-new-privileges=true");
    expect(args).toContain("--read-only");
    expect(args).toContain("--pids-limit");
    expect(args).toContain("16");
    expect(args).toContain("--memory");
    expect(args).toContain("134217728");
    expect(args).toContain("--cpu-period");
    expect(args).toContain("100000");
    expect(args).toContain("--cpu-quota");
    expect(args).toContain("50000");
    expect(args).toContain("none");
    expect(args.slice(-3)).toEqual([
      "scanner",
      "argument with spaces",
      "$(not-a-shell)",
    ]);
    expect(engine.removals).toEqual(["ckodex-sandbox-execution-1"]);
    expect(evidence[0]?.execution.cleanup).toBe("complete");
    expect(evidence[0]?.execution.result).toEqual(result);
  });

  test("fails closed before running when the engine cannot enforce an allowlist", async () => {
    const { spec } = await fixture();
    const engine = new RecordingEngine();
    const evidence: SandboxEvidenceRecord[] = [];
    await expect(
      adapter(engine, evidence).execute(
        {
          ...spec,
          network: {
            mode: "allowlist",
            destinations: ["api.example.test:443"],
          },
        },
        ["scanner"],
        new AbortController().signal,
      ),
    ).rejects.toThrow("cannot enforce destination allowlists");
    expect(engine.runs).toHaveLength(0);
  });

  test("uses an enforcing backend's exact allowlist arguments", async () => {
    const { spec } = await fixture();
    const engine = new RecordingEngine(true);
    const evidence: SandboxEvidenceRecord[] = [];
    await adapter(engine, evidence).execute(
      {
        ...spec,
        network: {
          mode: "allowlist",
          destinations: ["api.example.test:443"],
        },
      },
      ["scanner"],
      new AbortController().signal,
    );
    expect(engine.runs[0]?.args).toContain("ckodex-allowlist");
  });

  test("rejects unsafe network names returned by an allowlist backend", async () => {
    const { spec } = await fixture();
    const engine = new RecordingEngine(true);
    engine.destinationAllowlistNetwork = () => "host";
    const evidence: SandboxEvidenceRecord[] = [];
    await expect(
      adapter(engine, evidence).execute(
        {
          ...spec,
          network: {
            mode: "allowlist",
            destinations: ["api.example.test:443"],
          },
        },
        ["scanner"],
        new AbortController().signal,
      ),
    ).rejects.toThrow("unsafe allowlist network");
    expect(engine.runs).toHaveLength(0);
    expect(evidence[0]?.execution.cleanup).toBe("not_started");
  });

  test("classifies caller cancellation and still forces cleanup", async () => {
    const { spec } = await fixture();
    const engine = new RecordingEngine();
    engine.run = async (request): Promise<typeof engine.result> => {
      engine.runs.push(request);
      await new Promise<void>((resolve) => {
        if (request.signal.aborted) {
          resolve();
          return;
        }
        request.signal.addEventListener("abort", () => resolve(), {
          once: true,
        });
      });
      return engine.result;
    };
    const controller = new AbortController();
    const pending = adapter(engine, []).execute(
      spec,
      ["scanner"],
      controller.signal,
    );
    controller.abort(new DOMException("canceled", "AbortError"));
    const result: SandboxResult = await pending;
    expect(result.termination).toBe("canceled");
    expect(result.exitCode).toBe(137);
    expect(engine.removals).toHaveLength(1);
  });

  test("keeps the first timeout classification if the caller aborts later", async () => {
    const { spec } = await fixture();
    const engine = new RecordingEngine();
    let markEngineStarted: (() => void) | undefined;
    const engineStarted = new Promise<void>((resolve) => {
      markEngineStarted = resolve;
    });
    engine.run = async (request): Promise<typeof engine.result> => {
      engine.runs.push(request);
      markEngineStarted?.();
      await new Promise<void>((resolve) => {
        if (request.signal.aborted) {
          resolve();
          return;
        }
        request.signal.addEventListener(
          "abort",
          () => setTimeout(resolve, 15),
          { once: true },
        );
      });
      return engine.result;
    };
    const controller = new AbortController();
    const pending = adapter(engine, []).execute(
      {
        ...spec,
        limits: { ...spec.limits, wallClockMillis: 10 },
      },
      ["scanner"],
      controller.signal,
    );
    await engineStarted;
    setTimeout(() => controller.abort(), 12);
    expect((await pending).termination).toBe("timed_out");
  });

  test("turns an abort-aware engine rejection into a cancellation result", async () => {
    const { spec } = await fixture();
    const engine = new RecordingEngine();
    engine.run = async (request): Promise<never> => {
      engine.runs.push(request);
      await new Promise<void>((resolve) => {
        if (request.signal.aborted) {
          resolve();
          return;
        }
        request.signal.addEventListener("abort", () => resolve(), {
          once: true,
        });
      });
      throw request.signal.reason;
    };
    const controller = new AbortController();
    const pending = adapter(engine, []).execute(
      spec,
      ["scanner"],
      controller.signal,
    );
    setTimeout(() => controller.abort(), 1);
    const result = await pending;
    expect(result.termination).toBe("canceled");
    expect(result.stdoutDigest).toBe(
      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  test("rejects commands before invoking the engine", async () => {
    const { spec } = await fixture();
    const engine = new RecordingEngine();
    await expect(
      adapter(engine, []).execute(
        spec,
        ["scanner", ""],
        new AbortController().signal,
      ),
    ).rejects.toBeInstanceOf(SandboxExecutionError);
    expect(engine.runs).toHaveLength(0);
  });

  test("rejects host mount aliases after resolving symlinks", async () => {
    const { spec } = await fixture();
    const engine = new RecordingEngine();
    const output = spec.mounts.find((mount) => mount.role === "output")!;
    const evidence: SandboxEvidenceRecord[] = [];
    await expect(
      adapter(engine, evidence).execute(
        {
          ...spec,
          mounts: spec.mounts.map((mount) =>
            mount.role === "state"
              ? { ...mount, source: output.source }
              : mount,
          ),
        },
        ["scanner"],
        new AbortController().signal,
      ),
    ).rejects.toThrow("mount sources overlap");
    expect(engine.runs).toHaveLength(0);
    expect(engine.removals).toHaveLength(0);
    expect(evidence[0]?.execution.cleanup).toBe("not_started");
  });

  test("rejects file and socket-shaped bind sources before Docker", async () => {
    const { spec } = await fixture();
    const engine = new RecordingEngine();
    const root = await mkdtemp(join(tmpdir(), "ckodex-sandbox-file-mount-"));
    const file = join(root, "not-a-directory");
    await writeFile(file, "not a mountable source tree");
    const evidence: SandboxEvidenceRecord[] = [];
    await expect(
      adapter(engine, evidence).execute(
        {
          ...spec,
          mounts: spec.mounts.map((mount) =>
            mount.role === "source" ? { ...mount, source: file } : mount,
          ),
        },
        ["scanner"],
        new AbortController().signal,
      ),
    ).rejects.toThrow("source mount source is not a directory");
    expect(engine.runs).toHaveLength(0);
    expect(engine.removals).toHaveLength(0);
    expect(evidence[0]?.execution.cleanup).toBe("not_started");
  });
});
