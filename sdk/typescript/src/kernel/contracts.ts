export type ScanStatus = "running" | "complete" | "failed";

export interface ScanLifecycleState {
  status: ScanStatus;
  completedAt?: string;
  canceledAt?: string;
  failureMessage?: string;
}

export type ScanLifecycleCommand =
  | { kind: "complete"; at: string }
  | { kind: "fail"; at: string; message?: string }
  | { kind: "cancel"; at: string };

export type ScanLifecycleEvent =
  | { kind: "scan_completed"; at: string }
  | { kind: "scan_failed"; at: string; message?: string }
  | { kind: "scan_canceled"; at: string };

export type ScanTransition =
  | {
      ok: true;
      changed: boolean;
      state: ScanLifecycleState;
      event?: ScanLifecycleEvent;
    }
  | { ok: false; reason: string };

export type ModelTransport =
  | "local_process"
  | "local_http"
  | "private_http"
  | "private_grpc"
  | "hosted_api";

export type ModelCapability =
  | "streaming"
  | "structured_output"
  | "tool_calling"
  | "cancellation"
  | "usage_accounting";

export type ScanModelProvider =
  | { kind: "codex" }
  | {
      kind: "local" | "local_http";
      id: string;
      model: string;
      baseUrl: string;
      credentialEnv?: string;
    }
  | {
      kind: "private" | "private_http";
      id: string;
      model: string;
      baseUrl: string;
      credentialEnv: string;
    }
  | {
      kind: "local_process" | "private_grpc";
      id: string;
      model: string;
      bridgeBaseUrl: string;
      credentialEnv?: string;
    };

export interface ScanModelProviderConfiguration {
  kind: ScanModelProvider["kind"];
  id: string;
  model: string;
  baseUrl?: string;
  bridgeBaseUrl?: string;
  credentialEnv?: string;
}

export interface ModelEndpointSecurity {
  tls: boolean;
  privateNetwork: boolean;
  loopbackOnly: boolean;
  source: "derived" | "declared";
  endpointIdentityDigest?: `sha256:${string}`;
  peerCertificateFingerprint?: `sha256:${string}`;
}

export interface ModelCapabilities {
  providerId: string;
  modelId: string;
  transport: ModelTransport;
  endpointSecurity: ModelEndpointSecurity;
  features: ReadonlySet<ModelCapability>;
  capabilitySource: "configured" | "probed";
}

export type KernelJsonPrimitive = string | number | boolean | null;
export type KernelJsonValue =
  | KernelJsonPrimitive
  | readonly KernelJsonValue[]
  | { readonly [key: string]: KernelJsonValue };

export interface ModelToolDefinition {
  name: string;
  description: string;
  inputSchema: Readonly<Record<string, KernelJsonValue>>;
}

export type ModelToolChoice = "auto" | "none" | "required" | { name: string };

export interface StructuredOutputSpec {
  name: string;
  schema: Readonly<Record<string, KernelJsonValue>>;
  strict: true;
}

export interface ModelExecutionLimits {
  maxRequestBytes: number;
  maxResponseBytes: number;
  maxToolArgumentBytes: number;
  headerTimeoutMillis: number;
  streamIdleTimeoutMillis: number;
  wallClockMillis: number;
}

export interface ModelExecutionRequest {
  requestId: string;
  systemPrompt: string;
  input: string;
  continuation?: ModelToolContinuation;
  requiredCapabilities: readonly ModelCapability[];
  tools?: readonly ModelToolDefinition[];
  toolChoice?: ModelToolChoice;
  outputFormat?: StructuredOutputSpec;
  limits: ModelExecutionLimits;
}

export interface ModelToolOutput {
  callId: string;
  output: string;
}

export interface ModelToolContinuation {
  previousResponseId: string;
  outputs: readonly ModelToolOutput[];
}

export type ModelExecutionEvent =
  | { kind: "output_delta"; sequence: number; text: string }
  | {
      kind: "tool_call";
      sequence: number;
      callId: string;
      name: string;
      argumentsJson: string;
    }
  | {
      kind: "structured_output";
      sequence: number;
      value: KernelJsonValue;
    }
  | {
      kind: "response_metadata";
      sequence: number;
      responseId: string;
      providerRequestId?: string;
      returnedModelId?: string;
      peerCertificateFingerprint?: `sha256:${string}`;
    }
  | {
      kind: "usage";
      sequence: number;
      inputTokens: number;
      outputTokens: number;
      cachedInputTokens?: number;
      totalTokens: number;
    }
  | {
      kind: "completed";
      sequence: number;
      finishReason: string;
      responseId: string;
    }
  | { kind: "canceled"; sequence: number; reason: string };

export interface ResourceLimits {
  cpuMillis: number;
  memoryBytes: number;
  processCount: number;
  wallClockMillis: number;
  maxOutputBytes: number;
}

export type SandboxMountRole = "source" | "output" | "state";

export interface SandboxMount {
  role: SandboxMountRole;
  source: string;
  target: string;
  access: "read_only" | "read_write";
}

export interface SandboxSpec {
  imageRef: string;
  runAsUser: number;
  privileged: boolean;
  linuxCapabilities: readonly string[];
  dockerSocketMounted: boolean;
  ambientCredentials: boolean;
  network:
    | { mode: "deny" }
    | { mode: "allowlist"; destinations: readonly string[] };
  mounts: readonly SandboxMount[];
  limits: ResourceLimits;
}

export interface SandboxResult {
  exitCode: number;
  termination: "exited" | "canceled" | "timed_out";
  durationMillis: number;
  stdoutDigest: string;
  stderrDigest: string;
  outputDigest: string;
}

export type GateDecision =
  | {
      verdict: "allow";
      policyId: string;
      reasons: readonly string[];
    }
  | {
      verdict: "deny";
      policyId: string;
      reasons: readonly string[];
      remediation: readonly string[];
    };

export interface DecisionTrace {
  traceId: string;
  actionId: string;
  policyId: string;
  verdict: GateDecision["verdict"];
  reasons: readonly string[];
  providerId?: string;
  modelId?: string;
  transport?: ModelTransport;
  timestamp: string;
}

export interface EvidenceRecord {
  mediaType: "application/vnd.ckodex.decision-trace+json";
  digest: `sha256:${string}`;
  trace: DecisionTrace;
}
