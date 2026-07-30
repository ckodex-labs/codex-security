import { spawnSync } from "node:child_process";
import { lstat, readdir, readFile, realpath } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const MAX_FILE_LINES = 500;
const MAX_FUNCTION_LINES = 50;
const MAX_COGNITIVE_COMPLEXITY = 15;
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pythonChecker = join(packageRoot, "scripts", "check-python-quality.py");
const defaultRoots = [
  "src/kernel",
  "src/validation",
  "src/proof",
  "src/transport",
  "_bundled_plugin/scripts/workbench_governance.py",
  "_bundled_plugin/scripts/workbench_governance_action_validation.py",
  "_bundled_plugin/scripts/workbench_governance_validation.py",
];

function lineCount(source) {
  return source.split(/\r?\n/u).length - (source.endsWith("\n") ? 1 : 0);
}

async function collect(path, files, seen) {
  const canonical = await realpath(path);
  if (seen.has(canonical)) return;
  seen.add(canonical);
  const metadata = await lstat(canonical);
  if (metadata.isFile()) {
    if ([".ts", ".tsx", ".py"].includes(extname(canonical))) {
      files.push(canonical);
    }
    return;
  }
  if (!metadata.isDirectory()) return;
  for (const entry of await readdir(canonical, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue;
    await collect(join(canonical, entry.name), files, seen);
  }
}

function location(sourceFile, node) {
  return (
    sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1
  );
}

function functionName(sourceFile, node) {
  if (node.name !== undefined) return node.name.getText(sourceFile);
  if (ts.isMethodDeclaration(node) || ts.isFunctionDeclaration(node)) {
    return "<anonymous>";
  }
  const parent = node.parent;
  if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  return "<callback>";
}

function isFunction(node) {
  return ts.isFunctionLike(node) && node.body !== undefined;
}

function logicalOperator(kind) {
  return (
    kind === ts.SyntaxKind.AmpersandAmpersandToken ||
    kind === ts.SyntaxKind.BarBarToken ||
    kind === ts.SyntaxKind.QuestionQuestionToken
  );
}

function thrownStub(node) {
  if (!ts.isThrowStatement(node) || node.expression === undefined) return false;
  const expression = node.expression;
  if (!ts.isNewExpression(expression) || expression.arguments === undefined) {
    return false;
  }
  const first = expression.arguments[0];
  return (
    first !== undefined &&
    ts.isStringLiteralLike(first) &&
    /\b(TODO|not implemented|not yet implemented)\b/iu.test(first.text)
  );
}

function commentTokens(source) {
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    false,
    ts.LanguageVariant.Standard,
    source,
  );
  const comments = [];
  for (
    let token = scanner.scan();
    token !== ts.SyntaxKind.EndOfFileToken;
    token = scanner.scan()
  ) {
    if (
      token === ts.SyntaxKind.SingleLineCommentTrivia ||
      token === ts.SyntaxKind.MultiLineCommentTrivia
    ) {
      comments.push({
        position: scanner.getTokenPos(),
        text: scanner.getTokenText(),
      });
    }
  }
  return comments;
}

function cognitiveComplexity(root) {
  let score = 1;
  function visit(node, nesting) {
    for (const child of node.getChildren()) {
      if (child !== root && isFunction(child)) continue;
      if (
        ts.isIfStatement(child) ||
        ts.isForStatement(child) ||
        ts.isForInStatement(child) ||
        ts.isForOfStatement(child) ||
        ts.isWhileStatement(child) ||
        ts.isDoStatement(child) ||
        ts.isCatchClause(child) ||
        ts.isConditionalExpression(child)
      ) {
        score += 1 + nesting;
        visit(child, nesting + 1);
        continue;
      }
      if (ts.isCaseClause(child) && child.statements.length > 0) {
        score += 1 + nesting;
      } else if (
        ts.isBinaryExpression(child) &&
        logicalOperator(child.operatorToken.kind)
      ) {
        score += 1;
      }
      visit(child, nesting);
    }
  }
  visit(root, 0);
  return score;
}

function pushViolation(violations, path, line, rule, message, actual, limit) {
  violations.push({
    path: relative(packageRoot, path),
    line,
    rule,
    message,
    ...(actual === undefined ? {} : { actual }),
    ...(limit === undefined ? {} : { limit }),
  });
}

function inspectTypeScript(path, source) {
  const violations = [];
  const sourceFile = ts.createSourceFile(
    path,
    source,
    ts.ScriptTarget.Latest,
    true,
    path.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  for (const diagnostic of sourceFile.parseDiagnostics) {
    const position = diagnostic.start ?? 0;
    const line = sourceFile.getLineAndCharacterOfPosition(position).line + 1;
    pushViolation(
      violations,
      path,
      line,
      "parse-error",
      ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"),
    );
  }
  const lines = lineCount(source);
  if (lines > MAX_FILE_LINES) {
    pushViolation(
      violations,
      path,
      1,
      "max-file-lines",
      `file has ${lines} lines; limit is ${MAX_FILE_LINES}`,
      lines,
      MAX_FILE_LINES,
    );
  }
  for (const comment of commentTokens(source)) {
    const marker = /\b(TODO|FIXME|XXX|HACK)\b/iu.exec(comment.text);
    if (marker === null) continue;
    const line =
      sourceFile.getLineAndCharacterOfPosition(comment.position).line + 1;
    pushViolation(
      violations,
      path,
      line,
      "stub",
      `stub marker ${marker[1].toUpperCase()} is forbidden`,
    );
  }
  function visit(node) {
    if (isFunction(node)) {
      const start = location(sourceFile, node);
      const end = sourceFile.getLineAndCharacterOfPosition(node.end).line + 1;
      const linesInFunction = end - start + 1;
      const name = functionName(sourceFile, node);
      if (linesInFunction > MAX_FUNCTION_LINES) {
        pushViolation(
          violations,
          path,
          start,
          "max-function-lines",
          `function ${name} has ${linesInFunction} lines; limit is ${MAX_FUNCTION_LINES}`,
          linesInFunction,
          MAX_FUNCTION_LINES,
        );
      }
      const complexity = cognitiveComplexity(node.body);
      if (complexity > MAX_COGNITIVE_COMPLEXITY) {
        pushViolation(
          violations,
          path,
          start,
          "cognitive-complexity",
          `function ${name} has cognitive complexity ${complexity}; limit is ${MAX_COGNITIVE_COMPLEXITY}`,
          complexity,
          MAX_COGNITIVE_COMPLEXITY,
        );
      }
    }
    if (ts.isNonNullExpression(node)) {
      pushViolation(
        violations,
        path,
        location(sourceFile, node),
        "unwrap-analogue",
        "TypeScript non-null assertion is forbidden",
      );
    }
    if (
      (ts.isPropertyDeclaration(node) || ts.isPropertySignature(node)) &&
      node.exclamationToken !== undefined
    ) {
      pushViolation(
        violations,
        path,
        location(sourceFile, node),
        "unwrap-analogue",
        "TypeScript definite-assignment assertion is forbidden",
      );
    }
    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "NotImplementedError"
    ) {
      pushViolation(
        violations,
        path,
        location(sourceFile, node),
        "stub",
        "NotImplementedError stub is forbidden",
      );
    }
    if (thrownStub(node)) {
      pushViolation(
        violations,
        path,
        location(sourceFile, node),
        "stub",
        "placeholder throw is forbidden",
      );
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return violations;
}

function inspectPython(paths) {
  if (paths.length === 0) return [];
  const configured = process.env["PYTHON"];
  const candidates =
    configured === undefined
      ? process.platform === "win32"
        ? [
            { command: "py", prefix: ["-3"] },
            { command: "python", prefix: [] },
            { command: "python3", prefix: [] },
          ]
        : [
            { command: "python3", prefix: [] },
            { command: "python", prefix: [] },
          ]
      : [{ command: configured, prefix: [] }];
  let result;
  for (const candidate of candidates) {
    result = spawnSync(
      candidate.command,
      [...candidate.prefix, "-I", pythonChecker, ...paths],
      {
        cwd: packageRoot,
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    if (result.error?.code !== "ENOENT") break;
  }
  if (result === undefined || result.error?.code === "ENOENT") {
    throw new Error("Python 3 is required for the quality gate");
  }
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `Python quality checker failed with exit ${result.status}: ${result.stderr.trim()}`,
    );
  }
  return JSON.parse(result.stdout);
}

async function main() {
  const requested = process.argv.slice(2);
  const roots = (requested.length === 0 ? defaultRoots : requested).map(
    (path) => resolve(packageRoot, path),
  );
  const files = [];
  const seen = new Set();
  for (const root of roots) await collect(root, files, seen);
  files.sort();
  const violations = [];
  const pythonFiles = [];
  for (const path of files) {
    if (path.endsWith(".py")) {
      pythonFiles.push(path);
      continue;
    }
    violations.push(...inspectTypeScript(path, await readFile(path, "utf8")));
  }
  for (const violation of inspectPython(pythonFiles)) {
    violations.push({
      ...violation,
      path: relative(packageRoot, violation.path),
    });
  }
  violations.sort(
    (left, right) =>
      left.path.localeCompare(right.path) ||
      left.line - right.line ||
      left.rule.localeCompare(right.rule),
  );
  if (violations.length === 0) {
    process.stdout.write(
      `quality limits: pass (${files.length} files, ${MAX_FILE_LINES}/${MAX_FUNCTION_LINES}/${MAX_COGNITIVE_COMPLEXITY})\n`,
    );
    return;
  }
  for (const violation of violations) {
    process.stderr.write(
      `${violation.path}:${violation.line} [${violation.rule}] ${violation.message}\n`,
    );
  }
  process.stderr.write(`${violations.length} quality violation(s)\n`);
  process.exitCode = 1;
}

await main();
