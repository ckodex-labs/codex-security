import { parse as parseToml } from "smol-toml";
import {
  buildCodexOverrides,
  CodexOverrideValidationError,
  type CliJsonObject,
  type CliJsonValue,
} from "../../validation/cli/codex-overrides.js";

function parseValue(literal: string): CliJsonValue {
  try {
    return parseToml(`value = ${literal}`)["value"] as CliJsonValue;
  } catch {
    throw new CodexOverrideValidationError("Invalid --codex TOML value");
  }
}

export function parseCliCodexOverrides(
  values: readonly string[],
  model?: string,
): CliJsonObject {
  return buildCodexOverrides(values, model, parseValue);
}
