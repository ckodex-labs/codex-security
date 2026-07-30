import type { JsonObject } from "./config.js";
import { CodexSecurityError } from "./errors.js";
import { parseCliCodexOverrides } from "./transport/cli/codex-overrides.js";
import { CodexOverrideValidationError } from "./validation/cli/codex-overrides.js";

export function parseCodexOverrides(
  values: readonly string[],
  model?: string,
): JsonObject {
  try {
    return parseCliCodexOverrides(values, model) as JsonObject;
  } catch (error) {
    if (error instanceof CodexOverrideValidationError) {
      throw new CodexSecurityError(error.message);
    }
    throw error;
  }
}
