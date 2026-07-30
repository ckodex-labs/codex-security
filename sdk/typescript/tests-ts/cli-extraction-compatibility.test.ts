import { describe, expect, test } from "bun:test";
import {
  parseCodexOverrides as facadeParseCodexOverrides,
  Progress as FacadeProgress,
} from "../src/cli.js";
import { parseCodexOverrides } from "../src/cli-codex-overrides.js";
import { targetFromArguments } from "../src/cli-scan-target.js";
import { CodexSecurityError } from "../src/errors.js";
import {
  scanPhase,
  workerStatusMessage,
} from "../src/kernel/cli/scan-state.js";
import { Progress as TransportProgress } from "../src/transport/cli/progress.js";
import {
  modelProviderFromCli,
  privateHttpCredentialPresent,
  providerOptionsComplete,
} from "../src/validation/cli/provider-options.js";
import {
  defaultScansList,
  scanArgumentsFromRecipe,
  validateCliArguments,
} from "../src/validation/cli/scan-input.js";

describe("CLI extraction compatibility", () => {
  test("preserves legacy exported symbol identity", () => {
    expect(FacadeProgress).toBe(TransportProgress);
    expect(facadeParseCodexOverrides).toBe(parseCodexOverrides);
  });

  test("preserves provider validation and mapping", () => {
    const options = {
      providerKind: "private" as const,
      providerId: "ckodex-private",
      providerBaseUrl: "https://10.0.0.8/v1",
      providerCredentialEnv: "PRIVATE_MODEL_TOKEN",
      model: "private-model",
    };
    expect(providerOptionsComplete(options)).toBe(true);
    expect(privateHttpCredentialPresent(options)).toBe(true);
    expect(modelProviderFromCli(options)).toEqual({
      kind: "private",
      id: "ckodex-private",
      baseUrl: "https://10.0.0.8/v1",
      credentialEnv: "PRIVATE_MODEL_TOKEN",
      model: "private-model",
    });
    expect(() =>
      modelProviderFromCli({
        providerKind: "local",
      }),
    ).toThrow("provider id is required");
    expect(() =>
      modelProviderFromCli({
        providerKind: "private",
        providerId: "ckodex-private",
        providerBaseUrl: "https://10.0.0.8/v1",
        model: "private-model",
      }),
    ).toThrow("provider credential environment is required");
  });

  test("preserves override parsing and prototype rejection", () => {
    expect(
      parseCodexOverrides(
        ["agents.max_threads=4", 'model_reasoning_effort="high"'],
        "model-a",
      ),
    ).toEqual({
      agents: { max_threads: 4 },
      model: "model-a",
      model_reasoning_effort: "high",
    });
    try {
      parseCodexOverrides(["agents.__proto__.enabled=true"]);
      throw new Error("expected override validation to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(CodexSecurityError);
      expect((error as Error).message).toBe("Invalid --codex key");
    }
  });

  test("preserves saved recipe decoding and implicit scans list", () => {
    expect(
      scanArgumentsFromRecipe(
        {
          repository: "/repo",
          target: {
            kind: "refs",
            paths: [],
            baseRef: "main",
            headRef: "feature",
          },
          knowledgeBasePaths: ["security.md"],
          mode: "deep",
          config: { model: "model-a" },
          failOnSeverity: "high",
          maxCostUsd: 3,
          pluginVersion: "1.2.3",
        },
        "parent",
      ),
    ).toEqual({
      repository: "/repo",
      paths: [],
      knowledgeBasePaths: ["security.md"],
      diff: "main",
      workingTree: false,
      head: "feature",
      base: undefined,
      mode: "deep",
      archiveExisting: false,
      codex: [],
      codexOverrides: { model: "model-a" },
      failOnSeverity: "high",
      maxCostUsd: 3,
      dryRun: false,
      parentScanId: "parent",
      expectedPluginVersion: "1.2.3",
    });
    expect(defaultScansList(["scans", "--format", "json"])).toEqual([
      "scans",
      "list",
      "--format",
      "json",
    ]);
  });

  test("preserves validation positionals and pure scan state", () => {
    const positionals: string[] = [];
    expect(
      validateCliArguments(["scans", "match", "before", "after"], positionals),
    ).toBeUndefined();
    expect(positionals).toEqual(["before", "after"]);
    expect(
      targetFromArguments({
        paths: [],
        diff: "main",
        workingTree: false,
        head: "feature",
      }),
    ).toMatchObject({ kind: "refs", base: "main", head: "feature" });
    expect(scanPhase("validation")).toBe("validating findings");
    expect(
      workerStatusMessage({
        kind: "dispatch",
        phase: "ranking",
        planned: 2,
        started: 1,
      }),
    ).toContain("started 1 of 2");
  });

  test("preserves recipe validation error precedence", () => {
    const base = {
      repository: "/repo",
      target: { kind: "repository", paths: [] },
      mode: "standard",
      config: {},
    };
    expect(() =>
      scanArgumentsFromRecipe(
        {
          ...base,
          target: { kind: "invalid", paths: null },
        },
        "parent",
      ),
    ).toThrow("invalid paths");
    expect(() =>
      scanArgumentsFromRecipe(
        {
          ...base,
          target: {
            kind: "refs",
            paths: [],
            baseRef: null,
            headRef: null,
          },
          mode: "invalid",
        },
        "parent",
      ),
    ).toThrow("invalid mode");
    expect(() =>
      scanArgumentsFromRecipe(
        {
          ...base,
          target: { kind: "refs", paths: [], baseRef: null },
          config: null,
        },
        "parent",
      ),
    ).toThrow("invalid configuration");
  });

  test("preserves validation ordering before missing option values", () => {
    const positionals: string[] = [];
    expect(
      validateCliArguments(["validate", "--json", "--codex"], positionals),
    ).toBe(
      "validate does not support noninteractive JSON output; run it without --json or --format json.",
    );
    expect(positionals).toEqual([]);
  });

  test("restores an interactive cursor and clears its timer exactly once", () => {
    let now = 0;
    let render: (() => void) | undefined;
    let clears = 0;
    let output = "";
    const progress = new TransportProgress(
      {
        isTTY: true,
        write(value) {
          output += value;
        },
      },
      {
        now: () => now,
        setInterval(callback) {
          render = callback;
          return { id: "timer" } as unknown as NodeJS.Timeout;
        },
        clearInterval() {
          clears += 1;
        },
      },
    );

    progress.startTimer("Running scan");
    now = 1_000;
    render?.();
    progress.stopTimer();
    progress.stopTimer();

    expect(output).toBe(
      "\u001B[?25l[00:00] Running scan\r[00:01] Running scan\n\u001B[?25h",
    );
    expect(clears).toBe(1);
  });
});
