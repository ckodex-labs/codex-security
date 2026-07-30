import { targetDecision } from "./kernel/cli/scan-state.js";
import { DiffTarget, type ScanTarget } from "./targets.js";

export function targetFromArguments(
  arguments_: Parameters<typeof targetDecision>[0],
): ScanTarget {
  const decision = targetDecision(arguments_);
  switch (decision.kind) {
    case "paths":
      return decision.paths;
    case "refs":
      return DiffTarget.refs({
        base: decision.base,
        head: decision.head,
      });
    case "working_tree":
      return DiffTarget.workingTree({ base: decision.base });
    case "repository":
      return "repository";
  }
}
