import type {
  ScanLifecycleCommand,
  ScanLifecycleEvent,
  ScanLifecycleState,
  ScanTransition,
} from "./contracts.js";

function accepted(
  state: ScanLifecycleState,
  event?: ScanLifecycleEvent,
): ScanTransition {
  return {
    ok: true,
    changed: event !== undefined,
    state,
    ...(event === undefined ? {} : { event }),
  };
}

function rejected(command: string, state: ScanLifecycleState): ScanTransition {
  return {
    ok: false,
    reason: `cannot ${command} a scan in ${state.status} state`,
  };
}

function completeScan(
  state: ScanLifecycleState,
  command: Extract<ScanLifecycleCommand, { kind: "complete" }>,
): ScanTransition {
  if (state.status === "complete") return accepted(state);
  if (state.status !== "running") return rejected("complete", state);
  return accepted(
    { ...state, status: "complete", completedAt: command.at },
    { kind: "scan_completed", at: command.at },
  );
}

function failScan(
  state: ScanLifecycleState,
  command: Extract<ScanLifecycleCommand, { kind: "fail" }>,
): ScanTransition {
  if (state.status === "failed" && state.canceledAt === undefined) {
    return accepted(state);
  }
  if (state.status !== "running") return rejected("fail", state);
  const event = {
    kind: "scan_failed",
    at: command.at,
    ...(command.message === undefined ? {} : { message: command.message }),
  } as const;
  return accepted(
    {
      ...state,
      status: "failed",
      ...(command.message === undefined
        ? {}
        : { failureMessage: command.message }),
    },
    event,
  );
}

function cancelScan(
  state: ScanLifecycleState,
  command: Extract<ScanLifecycleCommand, { kind: "cancel" }>,
): ScanTransition {
  if (state.status === "failed" && state.canceledAt !== undefined) {
    return accepted(state);
  }
  if (state.status !== "running") return rejected("cancel", state);
  return accepted(
    { ...state, status: "failed", canceledAt: command.at },
    { kind: "scan_canceled", at: command.at },
  );
}

export function transitionScan(
  state: ScanLifecycleState,
  command: ScanLifecycleCommand,
): ScanTransition {
  if (command.kind === "complete") return completeScan(state, command);
  if (command.kind === "fail") return failScan(state, command);
  return cancelScan(state, command);
}
