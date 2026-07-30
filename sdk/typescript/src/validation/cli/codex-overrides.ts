const MAX_KEY_BYTES = 1_024;
const MAX_VALUE_BYTES = 64 * 1_024;
const MAX_DEPTH = 64;
const FORBIDDEN_PARTS = new Set(["__proto__", "prototype", "constructor"]);

export type CliJsonPrimitive = string | number | boolean | null;
export type CliJsonValue = CliJsonPrimitive | CliJsonObject | CliJsonValue[];
export interface CliJsonObject {
  [key: string]: CliJsonValue;
}

export class CodexOverrideValidationError extends Error {}

interface OverrideEntry {
  key: string;
  parts: string[];
  value: CliJsonValue;
}

function isJsonObject(value: CliJsonValue): value is CliJsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateParts(key: string): string[] {
  const parts = key.split(".");
  if (
    parts.length > MAX_DEPTH ||
    parts.some((part) => part.length === 0 || FORBIDDEN_PARTS.has(part))
  ) {
    throw new CodexOverrideValidationError("Invalid --codex key");
  }
  return parts;
}

function parseEntry(
  value: string,
  parseValue: (literal: string) => CliJsonValue,
): OverrideEntry {
  const separator = value.indexOf("=");
  const key = separator < 0 ? "" : value.slice(0, separator);
  const literal = separator < 0 ? "" : value.slice(separator + 1);
  if (key.length === 0 || literal.length === 0) {
    throw new CodexOverrideValidationError("--codex expects KEY=VALUE");
  }
  if (
    Buffer.byteLength(key, "utf8") > MAX_KEY_BYTES ||
    Buffer.byteLength(literal, "utf8") > MAX_VALUE_BYTES
  ) {
    throw new CodexOverrideValidationError(
      "--codex key or value exceeds the limit",
    );
  }
  return { key, parts: validateParts(key), value: parseValue(literal) };
}

function parentObject(
  result: CliJsonObject,
  parts: readonly string[],
): CliJsonObject {
  let cursor = result;
  for (const part of parts) {
    const existing = Object.hasOwn(cursor, part) ? cursor[part] : undefined;
    if (existing === undefined) {
      const nested = Object.create(null) as CliJsonObject;
      cursor[part] = nested;
      cursor = nested;
    } else if (isJsonObject(existing)) {
      cursor = existing;
    } else {
      throw new CodexOverrideValidationError("Conflicting --codex key");
    }
  }
  return cursor;
}

function assignEntry(
  result: CliJsonObject,
  entry: OverrideEntry,
  model: string | undefined,
): void {
  const final = entry.parts.at(-1);
  if (final === undefined) {
    throw new CodexOverrideValidationError("Invalid --codex key");
  }
  const cursor = parentObject(result, entry.parts.slice(0, -1));
  if (Object.hasOwn(cursor, final)) {
    throw new CodexOverrideValidationError(
      model !== undefined && entry.key === "model"
        ? "--model conflicts with --codex model"
        : "Duplicate --codex key",
    );
  }
  cursor[final] = entry.value;
}

export function buildCodexOverrides(
  values: readonly string[],
  model: string | undefined,
  parseValue: (literal: string) => CliJsonValue,
): CliJsonObject {
  const result = Object.create(null) as CliJsonObject;
  if (model !== undefined) result["model"] = model;
  for (const value of values) {
    assignEntry(result, parseEntry(value, parseValue), model);
  }
  return result;
}
