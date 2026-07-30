import type { ScanModelProvider } from "../../kernel/contracts.js";

type ScanAuthMode = "auto" | "chatgpt" | "api-key";
type ScanMode = "standard" | "deep";
type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
interface JsonObject {
  [key: string]: JsonValue;
}
export type FailureSeverity = "critical" | "high" | "medium" | "low";

export const REPORTABLE_SEVERITIES: readonly FailureSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
];

const COMMANDS = new Set([
  "scan",
  "install-hook",
  "bulk-scan",
  "scans",
  "findings",
  "export",
  "validate",
  "patch",
  "login",
  "logout",
  "info",
]);
const VALUE_OPTIONS = new Set([
  "--auth",
  "--path",
  "--knowledge-base",
  "--diff",
  "--head",
  "--base",
  "--mode",
  "--model",
  "--provider-kind",
  "--provider-id",
  "--provider-base-url",
  "--provider-bridge-base-url",
  "--provider-credential-env",
  "--output-dir",
  "--plugin-path",
  "--python",
  "--codex",
  "--fail-on-severity",
  "--max-cost",
  "--workers",
  "--max-attempts",
  "--export-format",
  "--output",
  "--source-root",
  "--format",
  "--filter-output",
  "--token-limit",
  "--token-offset",
  "--scan-root",
  "--reason",
]);

export interface ScanArguments {
  auth?: ScanAuthMode;
  repository?: string;
  paths: string[];
  knowledgeBasePaths: string[];
  diff?: string;
  workingTree: boolean;
  head?: string;
  base?: string;
  mode: ScanMode;
  model?: string;
  modelProvider?: ScanModelProvider;
  outputDir?: string;
  archiveExisting: boolean;
  pluginPath?: string;
  pythonPath?: string;
  codex: string[];
  codexOverrides?: JsonObject;
  failOnSeverity?: FailureSeverity;
  maxCostUsd?: number;
  dryRun: boolean;
  parentScanId?: string;
  expectedPluginVersion?: string;
}

function isJsonObject(value: JsonValue): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringArray(value: JsonValue | undefined, message: string): string[] {
  if (
    !Array.isArray(value) ||
    !value.every(
      (entry): entry is string => typeof entry === "string" && entry.length > 0,
    )
  ) {
    throw new Error(message);
  }
  return value;
}

function recipeTarget(value: JsonValue | undefined): JsonObject {
  if (value === undefined || !isJsonObject(value)) {
    throw new Error("The saved scan recipe contains no target.");
  }
  return value;
}

function targetKind(
  target: JsonObject,
): "repository" | "paths" | "refs" | "working_tree" {
  const kind = target["kind"];
  if (
    kind !== "repository" &&
    kind !== "paths" &&
    kind !== "refs" &&
    kind !== "working_tree"
  ) {
    throw new Error("The saved scan recipe contains an invalid target.");
  }
  return kind;
}

function targetReference(
  target: JsonObject,
  kind: "repository" | "paths" | "refs" | "working_tree",
): string | undefined {
  const reference = target["baseRef"] ?? target["base"];
  if (
    (reference !== undefined && typeof reference !== "string") ||
    (kind === "refs" && !reference)
  ) {
    throw new Error("The saved scan recipe has an invalid Git base.");
  }
  return reference;
}

function targetHead(target: JsonObject): string | undefined {
  const head = target["headRef"];
  if (head !== undefined && (typeof head !== "string" || head.length === 0)) {
    throw new Error("The saved scan recipe has an invalid Git head.");
  }
  return head;
}

function recipeMode(value: JsonValue | undefined): ScanMode {
  if (value !== "standard" && value !== "deep") {
    throw new Error("The saved scan recipe contains an invalid mode.");
  }
  return value;
}

function failureSeverity(
  value: JsonValue | undefined,
): FailureSeverity | undefined {
  if (value === undefined) return undefined;
  if (
    value === "critical" ||
    value === "high" ||
    value === "medium" ||
    value === "low"
  ) {
    return value;
  }
  throw new Error("The saved scan recipe contains an invalid severity policy.");
}

function positiveCost(value: JsonValue | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new Error("The saved scan recipe contains an invalid cost limit.");
  }
  return value;
}

function recipeObject(recipe: JsonValue | undefined): JsonObject {
  if (recipe === undefined || !isJsonObject(recipe)) {
    throw new Error("This scan does not have a saved launch recipe.");
  }
  return recipe;
}

function requiredRepository(recipe: JsonObject): string {
  const repository = recipe["repository"];
  if (typeof repository !== "string" || repository.length === 0) {
    throw new Error("The saved scan recipe does not contain a repository.");
  }
  return repository;
}

function recipeConfig(recipe: JsonObject): JsonObject {
  const config = recipe["config"];
  if (config === undefined || !isJsonObject(config)) {
    throw new Error("The saved scan recipe contains invalid configuration.");
  }
  return config;
}

export function scanArgumentsFromRecipe(
  value: JsonValue | undefined,
  parentScanId: string,
): ScanArguments {
  const recipe = recipeObject(value);
  const repository = requiredRepository(recipe);
  const target = recipeTarget(recipe["target"]);
  const paths = stringArray(
    target["paths"],
    "The saved scan recipe contains invalid paths.",
  );
  const knowledgeBasePaths = stringArray(
    recipe["knowledgeBasePaths"] ?? [],
    "The saved scan recipe contains invalid knowledge base paths.",
  );
  const kind = targetKind(target);
  const mode = recipeMode(recipe["mode"]);
  const config = recipeConfig(recipe);
  const reference = targetReference(target, kind);
  const head = targetHead(target);
  const failOnSeverity = failureSeverity(recipe["failOnSeverity"]);
  const maxCostUsd = positiveCost(recipe["maxCostUsd"]);
  return {
    repository,
    paths,
    knowledgeBasePaths,
    diff: kind === "refs" ? reference : undefined,
    workingTree: kind === "working_tree",
    head: kind === "refs" ? head ?? "HEAD" : undefined,
    base: kind === "working_tree" ? reference : undefined,
    mode,
    archiveExisting: false,
    codex: [],
    codexOverrides: config,
    failOnSeverity,
    maxCostUsd,
    dryRun: false,
    parentScanId,
    expectedPluginVersion:
      typeof recipe["pluginVersion"] === "string"
        ? recipe["pluginVersion"]
        : undefined,
  };
}

export function defaultScansList(argv: readonly string[]): readonly string[] {
  const commandIndex = argv.findIndex((value, index) => {
    if (value.startsWith("-")) return false;
    const previous = index === 0 ? undefined : argv[index - 1];
    return (
      index === 0 || previous === undefined || !VALUE_OPTIONS.has(previous)
    );
  });
  if (
    commandIndex < 0 ||
    argv[commandIndex] !== "scans" ||
    argv.includes("--help") ||
    argv.includes("-h")
  ) {
    return argv;
  }
  const following = argv[commandIndex + 1];
  if (following !== undefined && !following.startsWith("-")) return argv;
  return [
    ...argv.slice(0, commandIndex + 1),
    "list",
    ...argv.slice(commandIndex + 1),
  ];
}

function structuredOutput(argv: readonly string[]): boolean {
  return argv.some((value, index) => {
    if (value === "--json") return true;
    if (value === "--format=json" || value === "--format=jsonl") return true;
    return (
      value === "--format" &&
      (argv[index + 1] === "json" || argv[index + 1] === "jsonl")
    );
  });
}

function structuredOutputError(
  argv: readonly string[],
  command: string,
): string | undefined {
  if (!structuredOutput(argv)) return undefined;
  if (["validate", "patch", "login", "logout"].includes(command)) {
    return `${command} does not support noninteractive JSON output; run it without --json or --format json.`;
  }
  const stdout = argv.some(
    (value, index) =>
      value === "--output=-" ||
      (value === "--output" && argv[index + 1] === "-"),
  );
  const csv = argv.some(
    (value, index) =>
      value === "--export-format=csv" ||
      (value === "--export-format" && argv[index + 1] === "csv"),
  );
  return command === "export" && stdout && csv
    ? "CSV stdout cannot be combined with JSON output; write CSV to a file or omit --json."
    : undefined;
}

function scanOutputError(
  argv: readonly string[],
  command: string,
): string | undefined {
  if (command !== "scan" || argv.includes("--schema")) return undefined;
  if (
    argv.some(
      (value) =>
        value === "--filter-output" || value.startsWith("--filter-output="),
    )
  ) {
    return "--filter-output is not supported for scan results.";
  }
  const markdown = argv.some(
    (value, index) =>
      value === "--format=md" ||
      (value === "--format" && argv[index + 1] === "md"),
  );
  return markdown
    ? "Markdown output is not supported for scan results."
    : undefined;
}

function infoOutputError(
  argv: readonly string[],
  command: string,
): string | undefined {
  if (command !== "info") return undefined;
  const fields = new Set([
    "sdkVersion",
    "bundledPluginVersion",
    "scanMcp",
    "cancellationNote",
    "cliVersion",
    "codexVersion",
    "codexSdkVersion",
    "model",
    "reasoningEffort",
    "nextStep",
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (
      argument === undefined ||
      (argument !== "--filter-output" &&
        !argument.startsWith("--filter-output="))
    ) {
      continue;
    }
    const selector = argument.includes("=")
      ? argument.slice(argument.indexOf("=") + 1)
      : argv[index + 1];
    if (
      selector !== undefined &&
      !selector.split(",").every((field) => fields.has(field))
    ) {
      return "--filter-output must select an info metadata field.";
    }
  }
  return undefined;
}

function collectPositionals(
  argv: readonly string[],
  start: number,
  positionals: string[],
): string | undefined {
  for (let index = start; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === undefined) continue;
    if (!value.startsWith("-")) {
      positionals.push(value);
      continue;
    }
    const equals = value.indexOf("=");
    const option = equals < 0 ? value : value.slice(0, equals);
    if (equals >= 0 || !VALUE_OPTIONS.has(option)) continue;
    const next = argv[index + 1];
    if (next === undefined || next.startsWith("--") || next === "-h") {
      return `Missing value for flag: ${option}`;
    }
    index += 1;
  }
  return undefined;
}

function matchPositionalsError(
  argv: readonly string[],
  subcommand: string | undefined,
  positionals: readonly string[],
): string | undefined {
  const docs = argv.some((value) =>
    ["--schema", "--llms", "--llms-full"].includes(value),
  );
  if (subcommand !== "match" || docs) return undefined;
  if (argv.includes("--all") && positionals.length > 0) {
    return "scans match --all does not accept scan identifiers.";
  }
  return !argv.includes("--all") && positionals.length !== 2
    ? "scans match requires two scan identifiers or --all."
    : undefined;
}

function positionalLimit(
  command: string,
  subcommand: string | undefined,
): number | undefined {
  if (command === "validate" || command === "patch") return undefined;
  if (command === "logout" || command === "info") return 0;
  return subcommand === "compare" || subcommand === "match" ? 2 : 1;
}

function positionalError(
  command: string,
  subcommand: string | undefined,
  positionals: readonly string[],
): string | undefined {
  const maximum = positionalLimit(command, subcommand);
  if (maximum === undefined) return undefined;
  return positionals.length > maximum
    ? `Unexpected positional argument for ${command}${subcommand === undefined ? "" : ` ${subcommand}`}.`
    : undefined;
}

export function validateCliArguments(
  argv: readonly string[],
  positionals: string[],
): string | undefined {
  if (argv.includes("--help") || argv.includes("-h")) return undefined;
  const commandIndex = argv.findIndex((value) => COMMANDS.has(value));
  if (commandIndex < 0) return undefined;
  const command = argv[commandIndex];
  if (command === undefined) return undefined;
  const nested = command === "scans" || command === "findings";
  const subcommand = nested ? argv[commandIndex + 1] : undefined;
  return (
    structuredOutputError(argv, command) ??
    scanOutputError(argv, command) ??
    infoOutputError(argv, command) ??
    collectPositionals(argv, commandIndex + (nested ? 2 : 1), positionals) ??
    matchPositionalsError(argv, subcommand, positionals) ??
    positionalError(command, subcommand, positionals)
  );
}
