const MAX_WORKER_STATUS_BYTES = 64 * 1024;
const MAX_WORKER_COUNT = 1024;
const WORKER_STATUS_PREFIX = "CODEX_SECURITY_WORKER_STATUS ";
const PREFLIGHT_COMMAND = /(?:^|[\\/])config_preflight\.py(?=$|["'\s])/u;
const WORKER_PHASES = new Set([
  "ranking",
  "file_review",
  "validation",
  "attack_path",
]);

export type ScanWorkerPhase =
  | "ranking"
  | "file_review"
  | "validation"
  | "attack_path";

export type ScanWorkerStatus =
  | {
      kind: "preflight";
      delegation: "available" | "unavailable" | "unknown";
      configuredSlots: number | null;
    }
  | {
      kind: "dispatch";
      phase: ScanWorkerPhase;
      planned: number;
      started: number;
    };

export function workerStatusFromEvent(
  event: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  if (event["type"] !== "item.completed" || !isRecord(event["item"])) {
    return null;
  }
  const item = event["item"];
  if (item["type"] === "command_execution") return preflightStatus(item);
  if (item["type"] === "agent_message") return dispatchStatus(item);
  return null;
}

function preflightStatus(
  item: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  const results = preflightResults(item);
  if (results === null) return null;
  const delegation = delegationStatus(results);
  if (delegation === null) return null;
  return {
    kind: "preflight",
    delegation,
    configuredSlots: configuredWorkerSlots(results),
  };
}

function preflightResults(
  item: Readonly<Record<string, unknown>>,
): readonly unknown[] | null {
  const command = item["command"];
  const output = item["aggregated_output"];
  if (typeof command !== "string" || !PREFLIGHT_COMMAND.test(command)) {
    return null;
  }
  if (typeof output !== "string" || !withinStatusLimit(output)) return null;
  const payload = parseJson(output);
  if (!isRecord(payload) || !Array.isArray(payload["results"])) return null;
  if (
    payload["profile"] !== "security_scan" &&
    payload["profile"] !== "security_diff_scan"
  ) {
    return null;
  }
  return payload["results"];
}

function delegationStatus(
  results: readonly unknown[],
): "available" | "unavailable" | "unknown" | null {
  const delegated = results.filter(
    (result): result is Record<string, unknown> =>
      isRecord(result) && result["capability"] === "delegated_workers",
  );
  const delegatedResult = delegated[0];
  if (delegated.length !== 1 || delegatedResult === undefined) return null;
  return delegatedResult["status"] === "pass"
    ? "available"
    : delegatedResult["status"] === "fail"
      ? "unavailable"
      : delegatedResult["status"] === "unknown"
        ? "unknown"
        : null;
}

function configuredWorkerSlots(results: readonly unknown[]): number | null {
  const capacity = results.filter(
    (result): result is Record<string, unknown> =>
      isRecord(result) &&
      typeof result["capability"] === "string" &&
      result["capability"].startsWith("usable_worker_slots_"),
  );
  if (capacity.length > 1) return null;
  const capacityResult = capacity[0];
  return capacity.length === 1 &&
    capacityResult !== undefined &&
    isWorkerCount(capacityResult["actual"])
    ? capacityResult["actual"]
    : null;
}

function dispatchStatus(
  item: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  if (typeof item["text"] !== "string" || !withinStatusLimit(item["text"])) {
    return null;
  }
  const markers = item["text"]
    .split(/\r?\n/u)
    .filter((line) => line.startsWith(WORKER_STATUS_PREFIX));
  const marker = markers[0];
  if (markers.length !== 1 || marker === undefined) return null;
  const payload = parseJson(marker.slice(WORKER_STATUS_PREFIX.length));
  if (
    !isRecord(payload) ||
    Object.keys(payload).length !== 3 ||
    typeof payload["phase"] !== "string" ||
    !WORKER_PHASES.has(payload["phase"]) ||
    !isWorkerCount(payload["planned"]) ||
    !isWorkerCount(payload["started"]) ||
    payload["started"] > payload["planned"]
  ) {
    return null;
  }
  return {
    kind: "dispatch",
    phase: payload["phase"] as ScanWorkerPhase,
    planned: payload["planned"],
    started: payload["started"],
  };
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function withinStatusLimit(value: string): boolean {
  return new TextEncoder().encode(value).byteLength <= MAX_WORKER_STATUS_BYTES;
}

function isWorkerCount(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= MAX_WORKER_COUNT
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
