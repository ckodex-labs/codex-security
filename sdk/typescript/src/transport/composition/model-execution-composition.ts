import { randomUUID } from "node:crypto";
import {
  executeModelApplication,
  type ModelExecutionApplicationDependencies,
} from "../../kernel/model-execution-application.js";
import type {
  ModelExecutionEvent,
  ModelExecutionRequest,
} from "../../kernel/contracts.js";
import type {
  DecisionTraceObserverPort,
  EvidenceRecorderPort,
} from "../../kernel/ports.js";
import { createDecisionEvidence } from "../../proof/decision-trace.js";
import {
  validateModelCapabilities,
  type ModelCapabilityPolicy,
} from "../../validation/model-capabilities.js";
import {
  requireModelProviderDescriptor,
  resolveModelProvider,
  type ModelProviderAdapterRegistration,
} from "./provider-selection.js";

export interface ModelExecutionComposition {
  descriptor: unknown;
  registrations: readonly ModelProviderAdapterRegistration[];
  policy: ModelCapabilityPolicy;
  evidence: EvidenceRecorderPort;
  observer: DecisionTraceObserverPort;
  now?: () => string;
  nextTraceId?: () => string;
}

export function executeComposedModel(
  composition: ModelExecutionComposition,
  request: ModelExecutionRequest,
  signal: AbortSignal,
): AsyncIterable<ModelExecutionEvent> {
  const descriptor = requireModelProviderDescriptor(composition.descriptor);
  const model = resolveModelProvider(descriptor, composition.registrations);
  const allowedTransports =
    descriptor.kind === "codex_native"
      ? composition.policy.allowedTransports
      : composition.policy.allowedTransports.filter(
          (transport) => transport === descriptor.kind,
        );
  const dependencies: ModelExecutionApplicationDependencies = {
    model,
    evidence: composition.evidence,
    observer: composition.observer,
    admit: ({ capabilities, request: admittedRequest }) =>
      validateModelCapabilities(capabilities, {
        ...composition.policy,
        allowedTransports,
        requiredCapabilities: [
          ...new Set([
            ...composition.policy.requiredCapabilities,
            ...admittedRequest.requiredCapabilities,
          ]),
        ],
      }),
    createEvidence: createDecisionEvidence,
    now: composition.now ?? (() => new Date().toISOString()),
    nextTraceId: composition.nextTraceId ?? randomUUID,
  };
  return executeModelApplication(dependencies, request, signal);
}
