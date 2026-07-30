import type { ScanLifecycleState } from "../kernel/contracts.js";

export interface LegacyWorkbenchScan {
  status: "running" | "complete" | "failed";
  completed_at?: string | null;
  canceled_at?: string | null;
  error?: string | null;
}

export interface LegacyWorkbenchPatch {
  status: LegacyWorkbenchScan["status"];
  completed_at: string | null;
  canceled_at: string | null;
  error: string | null;
}

export function fromLegacyWorkbenchScan(
  record: LegacyWorkbenchScan,
): ScanLifecycleState {
  return {
    status: record.status,
    ...(record.completed_at == null
      ? {}
      : { completedAt: record.completed_at }),
    ...(record.canceled_at == null ? {} : { canceledAt: record.canceled_at }),
    ...(record.error == null ? {} : { failureMessage: record.error }),
  };
}

export function toLegacyWorkbenchPatch(
  state: ScanLifecycleState,
): LegacyWorkbenchPatch {
  return {
    status: state.status,
    completed_at: state.completedAt ?? null,
    canceled_at: state.canceledAt ?? null,
    error: state.failureMessage ?? null,
  };
}
