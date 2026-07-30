import type {
  DecisionTrace,
  EvidenceRecord,
  ModelCapabilities,
  ModelExecutionEvent,
  ModelExecutionRequest,
  SandboxResult,
  SandboxSpec,
  ScanLifecycleState,
} from "./contracts.js";
import type {
  SignatureVerification,
  SignedEvidenceEnvelope,
  SkillBundleManifest,
  VerifiedCapabilityBundle,
} from "./supply-chain-contracts.js";

export interface ModelExecutionPort {
  prepare?(
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): Promise<PreparedModelExecution>;
  capabilities(): Promise<ModelCapabilities>;
  execute(
    request: ModelExecutionRequest,
    signal: AbortSignal,
  ): AsyncIterable<ModelExecutionEvent>;
  cancel(requestId: string): Promise<void>;
}

export interface PreparedModelExecution {
  capabilities: ModelCapabilities;
  execute(): AsyncIterable<ModelExecutionEvent>;
  cancel(): Promise<void>;
}

export interface ModelProcessSpec {
  executable: string;
  arguments: readonly string[];
  environment: Readonly<Record<string, string>>;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  wallClockMillis: number;
}

export interface ModelProcessSession {
  readonly stdout: AsyncIterable<Uint8Array>;
  readonly stderr: AsyncIterable<Uint8Array>;
  write(chunk: Uint8Array): Promise<void>;
  closeInput(): Promise<void>;
  cancel(): Promise<void>;
  completion: Promise<{ exitCode: number | null; signal: string | null }>;
}

export interface SandboxedModelProcessRunnerPort {
  start(
    spec: ModelProcessSpec,
    signal: AbortSignal,
  ): Promise<ModelProcessSession>;
}

export interface SandboxExecutionPort {
  execute(
    spec: SandboxSpec,
    command: readonly string[],
    signal: AbortSignal,
  ): Promise<SandboxResult>;
}

export interface ScanStateRepositoryPort {
  load(scanId: string): Promise<ScanLifecycleState | undefined>;
  compareAndSet(
    scanId: string,
    expected: ScanLifecycleState,
    next: ScanLifecycleState,
  ): Promise<boolean>;
}

export interface EvidenceRecorderPort {
  record(record: EvidenceRecord): Promise<void>;
}

export interface DecisionTraceObserverPort {
  emit(trace: DecisionTrace): Promise<void>;
}

export interface CapabilityRegistryPort {
  resolve(bundleRef: string): Promise<VerifiedCapabilityBundle>;
}

export interface SignatureVerifierPort {
  verify(input: {
    artifactPath: string;
    signatureBundlePath: string;
    publicKeyPath?: string;
    proofMode: "offline_key" | "sigstore_transparency";
  }): Promise<SignatureVerification>;
}

export interface EvidenceSignerPort {
  sign(payload: Uint8Array): Promise<SignedEvidenceEnvelope>;
}

export interface SkillBundleReaderPort {
  read(bundleRef: string): Promise<SkillBundleManifest>;
}
