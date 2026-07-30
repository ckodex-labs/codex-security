import type { ScanWorkerPhase, ScanWorkerStatus } from "../worker-progress.js";

export interface ScanTargetSelection {
  paths: string[];
  diff?: string;
  workingTree: boolean;
  head?: string;
  base?: string;
}

export type ScanTargetDecision =
  | { kind: "paths"; paths: string[] }
  | { kind: "refs"; base: string; head: string }
  | { kind: "working_tree"; base: string }
  | { kind: "repository" };

export function targetDecision(
  arguments_: ScanTargetSelection,
): ScanTargetDecision {
  if (arguments_.paths.length > 0) {
    return { kind: "paths", paths: arguments_.paths };
  }
  if (arguments_.diff !== undefined) {
    return {
      kind: "refs",
      base: arguments_.diff,
      head: arguments_.head ?? "HEAD",
    };
  }
  return arguments_.workingTree
    ? { kind: "working_tree", base: arguments_.base ?? "HEAD" }
    : { kind: "repository" };
}

export function scanPhase(value: ScanWorkerPhase): string {
  return {
    ranking: "ranking scan targets",
    file_review: "reviewing files",
    validation: "validating findings",
    attack_path: "analyzing attack paths",
  }[value];
}

export function workerStatusMessage(status: ScanWorkerStatus): string | null {
  if (status.kind === "preflight") {
    if (status.delegation === "unavailable") {
      return "Preflight: worker delegation unavailable; continuing without delegated workers.";
    }
    if (status.delegation === "unknown") {
      return "Preflight: worker delegation could not be confirmed; continuing scan.";
    }
    return status.configuredSlots === null
      ? "Preflight: worker delegation supported."
      : `Preflight: worker delegation supported (up to ${status.configuredSlots} worker slots).`;
  }
  if (status.started === status.planned) {
    const count = `${status.started} ${status.started === 1 ? "worker" : "workers"}`;
    return `Scan phase: ${scanPhase(status.phase)} (${count}).`;
  }
  const phase = status.phase.replaceAll("_", " ");
  if (status.started === 0) {
    return `Worker delegation unavailable during ${phase}; continuing without delegated workers.`;
  }
  return `Worker capacity changed during ${phase}; started ${status.started} of ${status.planned} planned workers. Continuing scan.`;
}
