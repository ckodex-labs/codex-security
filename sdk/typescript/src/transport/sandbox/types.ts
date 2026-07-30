import type { GateDecision, SandboxResult } from "../../kernel/contracts.js";

export interface EngineRunRequest {
  args: readonly string[];
  signal: AbortSignal;
  maxOutputBytes: number;
}

export interface EngineRunResult {
  exitCode: number;
  stdout: Uint8Array;
  stderr: Uint8Array;
}

export interface SandboxContainerEngine {
  readonly id: string;
  readonly destinationAllowlistEnforced: boolean;
  destinationAllowlistNetwork?(
    destinations: readonly string[],
  ): Promise<string> | string;
  run(request: EngineRunRequest): Promise<EngineRunResult>;
  remove(containerName: string): Promise<void>;
}

export interface SandboxEvidenceRecord {
  mediaType: "application/vnd.ckodex.sandbox-execution+json";
  digest: `sha256:${string}`;
  execution: {
    executionId: string;
    policyId: string;
    verdict: GateDecision["verdict"];
    reasons: readonly string[];
    engineId: string;
    specDigest: `sha256:${string}`;
    commandDigest: `sha256:${string}`;
    startedAt: string;
    completedAt: string;
    result?: SandboxResult;
    error?: string;
    cleanup: "not_started" | "complete" | "failed";
  };
}

export interface SandboxEvidenceObserver {
  emit(record: SandboxEvidenceRecord): Promise<void>;
}

export interface SandboxAdapterOptions {
  engine: SandboxContainerEngine;
  policy: import("../../validation/sandbox-policy.js").SandboxPolicy;
  evidence: SandboxEvidenceObserver;
  now?: () => Date;
  executionId?: () => string;
}

export class SandboxPolicyDeniedError extends Error {
  readonly decision: GateDecision;

  constructor(decision: GateDecision) {
    super(`sandbox execution denied: ${decision.reasons.join("; ")}`);
    this.name = "SandboxPolicyDeniedError";
    this.decision = decision;
  }
}

export class SandboxExecutionError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SandboxExecutionError";
  }
}

export class SandboxOutputLimitError extends SandboxExecutionError {
  constructor(limit: number) {
    super(`sandbox output exceeded ${limit} bytes`);
    this.name = "SandboxOutputLimitError";
  }
}
