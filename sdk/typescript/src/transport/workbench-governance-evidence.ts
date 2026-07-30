import type { EvidenceRecord, KernelJsonValue } from "../kernel/contracts.js";
import type {
  ActionEnvelope,
  BackPropagationLineage,
  DurableGovernanceEvidence,
  PersistedGovernanceEvidence,
} from "../kernel/governance-contracts.js";
import type { SignedEvidenceEnvelope } from "../kernel/supply-chain-contracts.js";
import type { EvidenceRecorderPort } from "../kernel/ports.js";
import type {
  SandboxEvidenceObserver,
  SandboxEvidenceRecord,
} from "./sandbox/types.js";

export interface GovernanceWorkbenchWriter {
  (args: readonly string[]): Promise<Record<string, unknown>>;
}

export interface WorkbenchGovernanceEvidenceOptions {
  scanId: string;
  action: ActionEnvelope;
  append: GovernanceWorkbenchWriter;
  bpl?: BackPropagationLineage;
  signedEnvelope?: SignedEvidenceEnvelope;
}

function jsonValue(value: unknown): KernelJsonValue {
  return JSON.parse(JSON.stringify(value)) as KernelJsonValue;
}

function persistedEvidence(value: unknown): PersistedGovernanceEvidence {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !("governanceEvidence" in value)
  ) {
    throw new Error("workbench returned invalid governance evidence");
  }
  return value["governanceEvidence"] as PersistedGovernanceEvidence;
}

export class WorkbenchGovernanceEvidenceAdapter
  implements EvidenceRecorderPort, SandboxEvidenceObserver
{
  readonly #options: WorkbenchGovernanceEvidenceOptions;

  constructor(options: WorkbenchGovernanceEvidenceOptions) {
    this.#options = options;
  }

  async record(record: EvidenceRecord): Promise<void> {
    await this.#append({
      schemaVersion: 1,
      recordId: `model:${record.trace.traceId}`,
      kind: "model_decision",
      action: this.#options.action,
      receipt: jsonValue(record),
      ...(this.#options.bpl === undefined ? {} : { bpl: this.#options.bpl }),
      ...(this.#options.signedEnvelope === undefined
        ? {}
        : { signedEnvelope: this.#options.signedEnvelope }),
    });
  }

  async emit(record: SandboxEvidenceRecord): Promise<void> {
    await this.#append({
      schemaVersion: 1,
      recordId: `sandbox:${record.execution.executionId}`,
      kind: "sandbox_execution",
      action: this.#options.action,
      receipt: jsonValue(record),
      ...(this.#options.bpl === undefined ? {} : { bpl: this.#options.bpl }),
      ...(this.#options.signedEnvelope === undefined
        ? {}
        : { signedEnvelope: this.#options.signedEnvelope }),
    });
  }

  async #append(evidence: DurableGovernanceEvidence): Promise<void> {
    const result = await this.#options.append([
      "append-governance-evidence",
      "--scan-id",
      this.#options.scanId,
      "--record-json",
      JSON.stringify(evidence),
    ]);
    const persisted = persistedEvidence(result);
    if (
      persisted.recordId !== evidence.recordId ||
      persisted.scanId !== this.#options.scanId ||
      persisted.actionId !== this.#options.action.id
    ) {
      throw new Error("workbench governance evidence correlation mismatch");
    }
  }
}
