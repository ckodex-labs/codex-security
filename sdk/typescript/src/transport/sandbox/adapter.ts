import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { SandboxResult, SandboxSpec } from "../../kernel/contracts.js";
import type { SandboxExecutionPort } from "../../kernel/ports.js";
import { validateSandboxSpec } from "../../validation/sandbox-policy.js";
import { digestOutputTree } from "./output-digest.js";
import {
  SandboxExecutionError,
  SandboxPolicyDeniedError,
  type SandboxAdapterOptions,
  type SandboxEvidenceRecord,
} from "./types.js";

function digest(value: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function normalizedSpecDigest(spec: SandboxSpec): `sha256:${string}` {
  const mounts = [...spec.mounts]
    .sort((left, right) => left.role.localeCompare(right.role))
    .map((mount) => ({
      role: mount.role,
      source: resolve(mount.source),
      target: mount.target,
      access: mount.access,
    }));
  const network =
    spec.network.mode === "deny"
      ? { mode: "deny" as const }
      : {
          mode: "allowlist" as const,
          destinations: [...spec.network.destinations].sort(),
        };
  return digest(
    JSON.stringify({
      imageRef: spec.imageRef,
      runAsUser: spec.runAsUser,
      privileged: spec.privileged,
      linuxCapabilities: [...spec.linuxCapabilities].sort(),
      dockerSocketMounted: spec.dockerSocketMounted,
      ambientCredentials: spec.ambientCredentials,
      network,
      mounts,
      limits: {
        cpuMillis: spec.limits.cpuMillis,
        memoryBytes: spec.limits.memoryBytes,
        processCount: spec.limits.processCount,
        wallClockMillis: spec.limits.wallClockMillis,
        maxOutputBytes: spec.limits.maxOutputBytes,
      },
    }),
  );
}

function isWithin(parent: string, child: string): boolean {
  const path = relative(parent, child);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
}

async function canonicalMountSources(
  spec: SandboxSpec,
): Promise<Map<string, string>> {
  const sources = new Map<string, string>();
  for (const mount of spec.mounts) {
    if (!isAbsolute(mount.source)) {
      throw new SandboxExecutionError(`${mount.role} mount is not absolute`);
    }
    const lexical = resolve(mount.source);
    if (lexical.includes(",")) {
      throw new SandboxExecutionError(
        `${mount.role} mount cannot be represented safely by Docker`,
      );
    }
    if (mount.role !== "source") await mkdir(lexical, { recursive: true });
    const canonical = await realpath(lexical);
    if (!(await lstat(canonical)).isDirectory()) {
      throw new SandboxExecutionError(
        `${mount.role} mount source is not a directory`,
      );
    }
    sources.set(mount.role, canonical);
  }
  requireSeparatedMounts([...sources.entries()]);
  return sources;
}

function requireSeparatedMounts(values: readonly [string, string][]): void {
  for (let index = 0; index < values.length; index += 1) {
    const left = values[index];
    if (left === undefined) continue;
    for (const right of values.slice(index + 1)) {
      if (isWithin(left[1], right[1]) || isWithin(right[1], left[1])) {
        throw new SandboxExecutionError(
          `${left[0]} and ${right[0]} mount sources overlap`,
        );
      }
    }
  }
}

function containerName(executionId: string): string {
  const safe = executionId.toLowerCase().replace(/[^a-z0-9_.-]/g, "-");
  return `ckodex-sandbox-${safe}`.slice(0, 63);
}

function networkName(
  spec: SandboxSpec,
  allowlistNetwork: string | undefined,
): string {
  if (spec.network.mode === "deny") return "none";
  if (allowlistNetwork === undefined) {
    throw new SandboxExecutionError("sandbox allowlist network is unavailable");
  }
  return allowlistNetwork;
}

function baseDockerArgs(
  spec: SandboxSpec,
  name: string,
  allowlistNetwork: string | undefined,
): string[] {
  return [
    "run",
    "--pull=never",
    "--name",
    name,
    "--label",
    "io.ckodex.sandbox=true",
    "--user",
    String(spec.runAsUser),
    "--privileged=false",
    "--cap-drop=ALL",
    "--security-opt",
    "no-new-privileges=true",
    "--read-only",
    "--pids-limit",
    String(spec.limits.processCount),
    "--memory",
    String(spec.limits.memoryBytes),
    "--cpu-period",
    "100000",
    "--cpu-quota",
    String(spec.limits.cpuMillis * 100),
    "--tmpfs",
    `/tmp:rw,nosuid,nodev,noexec,size=${Math.min(
      spec.limits.memoryBytes,
      64 * 1024 * 1024,
    )}`,
    "--network",
    networkName(spec, allowlistNetwork),
  ];
}

function dockerArgs(
  spec: SandboxSpec,
  command: readonly string[],
  name: string,
  sources: ReadonlyMap<string, string>,
  allowlistNetwork: string | undefined,
): string[] {
  const args = baseDockerArgs(spec, name, allowlistNetwork);
  for (const mount of spec.mounts) {
    const source = sources.get(mount.role);
    if (source === undefined) {
      throw new SandboxExecutionError(`missing canonical ${mount.role} mount`);
    }
    args.push(
      "--mount",
      [
        "type=bind",
        `src=${source}`,
        `dst=${mount.target}`,
        ...(mount.access === "read_only" ? ["readonly"] : []),
      ].join(","),
    );
  }
  return [...args, spec.imageRef, ...command];
}

type EvidenceBase = Omit<
  SandboxEvidenceRecord["execution"],
  "completedAt" | "result" | "error" | "cleanup"
>;

interface TerminationControl {
  controller: AbortController;
  deadline: AbortSignal;
  forced: { value?: SandboxResult["termination"] };
  detach(): void;
}

interface ExecutionOutcome {
  result?: SandboxResult;
  failure?: unknown;
  cleanup: "not_started" | "complete" | "failed";
}

function terminationControl(
  signal: AbortSignal,
  wallClockMillis: number,
): TerminationControl {
  const controller = new AbortController();
  const deadline = AbortSignal.timeout(wallClockMillis);
  const forced: { value?: SandboxResult["termination"] } = {};
  const abort = (
    termination: SandboxResult["termination"],
    reason: unknown,
  ): void => {
    if (forced.value !== undefined) return;
    forced.value = termination;
    controller.abort(reason);
  };
  const cancel = (): void => abort("canceled", signal.reason);
  const timeout = (): void => abort("timed_out", deadline.reason);
  signal.addEventListener("abort", cancel, { once: true });
  deadline.addEventListener("abort", timeout, { once: true });
  if (signal.aborted) cancel();
  if (deadline.aborted) timeout();
  return {
    controller,
    deadline,
    forced,
    detach() {
      signal.removeEventListener("abort", cancel);
      deadline.removeEventListener("abort", timeout);
    },
  };
}

function requireOutputSource(sources: ReadonlyMap<string, string>): string {
  const output = sources.get("output");
  if (output === undefined) {
    throw new SandboxExecutionError("missing canonical output mount");
  }
  return output;
}

export class DockerSandboxAdapter implements SandboxExecutionPort {
  readonly #options: Required<
    Pick<SandboxAdapterOptions, "engine" | "policy" | "evidence">
  > &
    Pick<SandboxAdapterOptions, "now" | "executionId">;

  constructor(options: SandboxAdapterOptions) {
    this.#options = options;
  }

  async execute(
    spec: SandboxSpec,
    command: readonly string[],
    signal: AbortSignal,
  ): Promise<SandboxResult> {
    const started = (this.#options.now ?? (() => new Date()))();
    const decision = validateSandboxSpec(spec, this.#options.policy);
    const baseEvidence: EvidenceBase = {
      executionId: (this.#options.executionId ?? randomUUID)(),
      policyId: decision.policyId,
      verdict: decision.verdict,
      reasons: decision.reasons,
      engineId: this.#options.engine.id,
      specDigest: normalizedSpecDigest(spec),
      commandDigest: digest(JSON.stringify(command)),
      startedAt: started.toISOString(),
    };
    if (decision.verdict === "deny") {
      await this.#failBeforeRun(baseEvidence, started, "policy_denied");
      throw new SandboxPolicyDeniedError(decision);
    }
    await this.#requireCommand(command, baseEvidence, started);
    const allowlistNetwork = await this.#resolveAllowlist(
      spec,
      baseEvidence,
      started,
    );
    const sources = await this.#resolveSources(spec, baseEvidence, started);
    const outcome = await this.#run(
      spec,
      command,
      baseEvidence.executionId,
      sources,
      allowlistNetwork,
      signal,
      started,
    );
    return await this.#complete(baseEvidence, outcome);
  }

  async #requireCommand(
    command: readonly string[],
    evidence: EvidenceBase,
    started: Date,
  ): Promise<void> {
    const invalid =
      command.length === 0 ||
      command.some((argument) => argument === "" || argument.includes("\0"));
    if (!invalid) return;
    const error = new SandboxExecutionError(
      "sandbox command must contain non-empty, NUL-free arguments",
    );
    await this.#failBeforeRun(evidence, started, error.message);
    throw error;
  }

  async #resolveAllowlist(
    spec: SandboxSpec,
    evidence: EvidenceBase,
    started: Date,
  ): Promise<string | undefined> {
    if (spec.network.mode === "deny") return undefined;
    const resolveNetwork = this.#options.engine.destinationAllowlistNetwork;
    if (
      !this.#options.engine.destinationAllowlistEnforced ||
      resolveNetwork === undefined
    ) {
      const error = new SandboxExecutionError(
        "container engine cannot enforce destination allowlists",
      );
      await this.#failBeforeRun(evidence, started, error.message);
      throw error;
    }
    try {
      const network = await resolveNetwork.call(
        this.#options.engine,
        spec.network.destinations,
      );
      if (
        !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$/.test(network) ||
        ["bridge", "default", "host", "none"].includes(network)
      ) {
        throw new SandboxExecutionError(
          "container engine returned an unsafe allowlist network",
        );
      }
      return network;
    } catch (error) {
      const failure =
        error instanceof Error
          ? error
          : new SandboxExecutionError(String(error));
      await this.#failBeforeRun(evidence, started, failure.message);
      throw failure;
    }
  }

  async #resolveSources(
    spec: SandboxSpec,
    evidence: EvidenceBase,
    started: Date,
  ): Promise<Map<string, string>> {
    try {
      return await canonicalMountSources(spec);
    } catch (error) {
      const failure =
        error instanceof Error
          ? error
          : new SandboxExecutionError(String(error));
      await this.#failBeforeRun(evidence, started, failure.message);
      throw failure;
    }
  }

  async #run(
    spec: SandboxSpec,
    command: readonly string[],
    executionId: string,
    sources: ReadonlyMap<string, string>,
    allowlistNetwork: string | undefined,
    signal: AbortSignal,
    started: Date,
  ): Promise<ExecutionOutcome> {
    const name = containerName(executionId);
    const args = dockerArgs(spec, command, name, sources, allowlistNetwork);
    const control = terminationControl(signal, spec.limits.wallClockMillis);
    let cleanup: "not_started" | "complete" | "failed" = "not_started";
    let result: SandboxResult | undefined;
    let failure: unknown;
    try {
      result = await this.#runEngine(spec, args, sources, control, started);
    } catch (error) {
      failure = error;
    } finally {
      control.detach();
      try {
        await this.#options.engine.remove(name);
        cleanup = "complete";
      } catch (error) {
        cleanup = "failed";
        failure ??= error;
      }
    }
    return { result, failure, cleanup };
  }

  async #runEngine(
    spec: SandboxSpec,
    args: readonly string[],
    sources: ReadonlyMap<string, string>,
    control: TerminationControl,
    started: Date,
  ): Promise<SandboxResult> {
    let run;
    try {
      run = await this.#options.engine.run({
        args,
        signal: control.controller.signal,
        maxOutputBytes: spec.limits.maxOutputBytes,
      });
    } catch (error) {
      if (control.forced.value === undefined) throw error;
      run = {
        exitCode: 137,
        stdout: new Uint8Array(),
        stderr: new Uint8Array(),
      };
    }
    const termination = control.forced.value ?? "exited";
    const completed = (this.#options.now ?? (() => new Date()))();
    return {
      exitCode: termination === "exited" ? run.exitCode : 137,
      termination,
      durationMillis: Math.max(0, completed.getTime() - started.getTime()),
      stdoutDigest: digest(run.stdout),
      stderrDigest: digest(run.stderr),
      outputDigest: await digestOutputTree(requireOutputSource(sources)),
    };
  }

  async #complete(
    evidence: EvidenceBase,
    outcome: ExecutionOutcome,
  ): Promise<SandboxResult> {
    const completed = (this.#options.now ?? (() => new Date()))();
    await this.#emit({
      ...evidence,
      completedAt: completed.toISOString(),
      ...(outcome.result === undefined ? {} : { result: outcome.result }),
      ...(outcome.failure === undefined
        ? {}
        : {
            error:
              outcome.failure instanceof Error
                ? outcome.failure.message
                : String(outcome.failure),
          }),
      cleanup: outcome.cleanup,
    });
    if (outcome.failure !== undefined) {
      throw outcome.failure instanceof Error
        ? outcome.failure
        : new SandboxExecutionError(String(outcome.failure));
    }
    if (outcome.result === undefined) {
      throw new SandboxExecutionError("sandbox execution produced no result");
    }
    return outcome.result;
  }

  async #failBeforeRun(
    evidence: EvidenceBase,
    completed: Date,
    error: string,
  ): Promise<void> {
    await this.#emit({
      ...evidence,
      completedAt: completed.toISOString(),
      error,
      cleanup: "not_started",
    });
  }

  async #emit(execution: SandboxEvidenceRecord["execution"]): Promise<void> {
    const digestValue = digest(JSON.stringify(execution));
    await this.#options.evidence.emit({
      mediaType: "application/vnd.ckodex.sandbox-execution+json",
      digest: digestValue,
      execution,
    });
  }
}
