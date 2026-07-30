import type {
  EvidenceRecord,
  GateDecision,
  ModelCapabilities,
  ModelExecutionEvent,
  ModelExecutionRequest,
} from "./contracts.js";
import type {
  DecisionTraceObserverPort,
  EvidenceRecorderPort,
  ModelExecutionPort,
  PreparedModelExecution,
} from "./ports.js";

export interface ModelAdmissionInput {
  capabilities: ModelCapabilities;
  request: ModelExecutionRequest;
}

export type ModelAdmission = (
  input: ModelAdmissionInput,
) => GateDecision | Promise<GateDecision>;

export interface ModelDecisionEvidenceInput {
  traceId: string;
  actionId: string;
  decision: GateDecision;
  timestamp: string;
  model: ModelCapabilities;
}

export type ModelDecisionEvidenceFactory = (
  input: ModelDecisionEvidenceInput,
) => EvidenceRecord;

export interface ModelExecutionApplicationDependencies {
  model: ModelExecutionPort;
  evidence: EvidenceRecorderPort;
  observer: DecisionTraceObserverPort;
  admit: ModelAdmission;
  createEvidence: ModelDecisionEvidenceFactory;
  now(): string;
  nextTraceId(): string;
}

export class ModelAdmissionDeniedError extends Error {
  public constructor(
    public readonly decision: Extract<GateDecision, { verdict: "deny" }>,
    public readonly evidenceDigest: EvidenceRecord["digest"],
  ) {
    super(`Model execution denied by policy ${decision.policyId}.`);
    this.name = "ModelAdmissionDeniedError";
  }
}

export class ModelEventSequenceError extends Error {
  public constructor(
    public readonly previousSequence: number,
    public readonly receivedSequence: number,
  ) {
    super(
      `Model event sequence must increase monotonically; received ${receivedSequence} after ${previousSequence}.`,
    );
    this.name = "ModelEventSequenceError";
  }
}

export class ModelEventAfterTerminalError extends Error {
  public constructor(
    public readonly terminalSequence: number,
    public readonly receivedSequence: number,
  ) {
    super(
      `Model event ${receivedSequence} followed terminal event ${terminalSequence}.`,
    );
    this.name = "ModelEventAfterTerminalError";
  }
}

export class ModelEventStreamIncompleteError extends Error {
  public constructor(public readonly lastSequence: number) {
    super("Model event stream ended without a completed or canceled event.");
    this.name = "ModelEventStreamIncompleteError";
  }
}

async function recordDecision(
  dependencies: ModelExecutionApplicationDependencies,
  request: ModelExecutionRequest,
  capabilities: ModelCapabilities,
  decision: GateDecision,
): Promise<EvidenceRecord> {
  const evidence = dependencies.createEvidence({
    traceId: dependencies.nextTraceId(),
    actionId: request.requestId,
    decision,
    timestamp: dependencies.now(),
    model: capabilities,
  });
  await dependencies.evidence.record(evidence);
  await dependencies.observer.emit(evidence.trace);
  return evidence;
}

function requireNextSequence(
  previousSequence: number,
  event: ModelExecutionEvent,
): number {
  if (
    !Number.isSafeInteger(event.sequence) ||
    event.sequence < 0 ||
    event.sequence <= previousSequence
  ) {
    throw new ModelEventSequenceError(previousSequence, event.sequence);
  }
  return event.sequence;
}

export async function* executeModelApplication(
  dependencies: ModelExecutionApplicationDependencies,
  request: ModelExecutionRequest,
  signal: AbortSignal,
): AsyncGenerator<ModelExecutionEvent> {
  signal.throwIfAborted();
  const prepared = await prepareExecution(dependencies.model, request, signal);
  await admitExecution(dependencies, request, signal, prepared);
  yield* forwardExecution(dependencies.model, request, signal, prepared);
}

async function prepareExecution(
  model: ModelExecutionPort,
  request: ModelExecutionRequest,
  signal: AbortSignal,
): Promise<PreparedModelExecution | undefined> {
  return model.prepare === undefined
    ? undefined
    : await model.prepare(request, signal);
}

async function admitExecution(
  dependencies: ModelExecutionApplicationDependencies,
  request: ModelExecutionRequest,
  signal: AbortSignal,
  prepared: PreparedModelExecution | undefined,
): Promise<void> {
  try {
    const capabilities =
      prepared?.capabilities ?? (await dependencies.model.capabilities());
    signal.throwIfAborted();
    const decision = await dependencies.admit({ capabilities, request });
    const evidence = await recordDecision(
      dependencies,
      request,
      capabilities,
      decision,
    );
    if (decision.verdict === "deny") {
      throw new ModelAdmissionDeniedError(decision, evidence.digest);
    }
    signal.throwIfAborted();
  } catch (error) {
    await prepared?.cancel();
    throw error;
  }
}

async function* forwardExecution(
  model: ModelExecutionPort,
  request: ModelExecutionRequest,
  signal: AbortSignal,
  prepared: PreparedModelExecution | undefined,
): AsyncGenerator<ModelExecutionEvent> {
  let previousSequence = -1;
  let terminal = false;
  let executionFailure: unknown;
  try {
    const execution =
      prepared === undefined
        ? model.execute(request, signal)
        : prepared.execute();
    for await (const event of execution) {
      if (terminal) {
        throw new ModelEventAfterTerminalError(
          previousSequence,
          event.sequence,
        );
      }
      previousSequence = requireNextSequence(previousSequence, event);
      terminal = event.kind === "completed" || event.kind === "canceled";
      yield event;
    }
    if (!terminal) {
      throw new ModelEventStreamIncompleteError(previousSequence);
    }
  } catch (error) {
    executionFailure = error;
    throw error;
  } finally {
    if (!terminal)
      await cancelIncomplete(model, request, prepared, executionFailure);
  }
}

async function cancelIncomplete(
  model: ModelExecutionPort,
  request: ModelExecutionRequest,
  prepared: PreparedModelExecution | undefined,
  executionFailure: unknown,
): Promise<void> {
  try {
    if (prepared === undefined) await model.cancel(request.requestId);
    else await prepared.cancel();
  } catch (cancelError) {
    if (executionFailure === undefined) throw cancelError;
  }
}
