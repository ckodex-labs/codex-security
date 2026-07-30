import { createHash } from "node:crypto";
import type {
  DecisionTrace,
  EvidenceRecord,
  GateDecision,
  ModelCapabilities,
} from "../kernel/contracts.js";

export interface DecisionTraceInput {
  traceId: string;
  actionId: string;
  decision: GateDecision;
  timestamp: string;
  model?: ModelCapabilities;
}

export function createDecisionEvidence(
  input: DecisionTraceInput,
): EvidenceRecord {
  const trace: DecisionTrace = {
    traceId: input.traceId,
    actionId: input.actionId,
    policyId: input.decision.policyId,
    verdict: input.decision.verdict,
    reasons: [...input.decision.reasons],
    ...(input.model === undefined
      ? {}
      : {
          providerId: input.model.providerId,
          modelId: input.model.modelId,
          transport: input.model.transport,
        }),
    timestamp: input.timestamp,
  };
  const digest = createHash("sha256")
    .update(JSON.stringify(trace))
    .digest("hex");
  return {
    mediaType: "application/vnd.ckodex.decision-trace+json",
    digest: `sha256:${digest}`,
    trace,
  };
}
