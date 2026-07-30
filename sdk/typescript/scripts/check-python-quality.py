from __future__ import annotations

import ast
import json
import pathlib
import re
import sys
import tokenize
from typing import Any, Iterable


MAX_FILE_LINES = 500
MAX_FUNCTION_LINES = 50
MAX_COGNITIVE_COMPLEXITY = 15
CONTROL_NODES = tuple(
    node
    for node in (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.IfExp,
        getattr(ast, "Match", None),
        ast.comprehension,
    )
    if node is not None
)
STUB_MARKERS = ("TODO", "FIXME", "XXX", "HACK")


def _line_count(source: str) -> int:
    return len(source.splitlines())


def _function_name(node: ast.AST) -> str:
    return getattr(node, "name", "<lambda>")


def _complexity(node: ast.AST) -> int:
    score = 1

    def visit(current: ast.AST, nesting: int, root: ast.AST) -> None:
        nonlocal score
        for child in ast.iter_child_nodes(current):
            if child is not root and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                continue
            if isinstance(child, CONTROL_NODES):
                score += 1 + nesting
                visit(child, nesting + 1, root)
                continue
            if isinstance(child, ast.BoolOp):
                score += max(1, len(child.values) - 1)
            visit(child, nesting, root)

    visit(node, 0, node)
    return score


def _stub_violations(tree: ast.AST) -> Iterable[tuple[int, str]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Pass):
            yield node.lineno, "stub statement 'pass' is forbidden"
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            if node.value.value is Ellipsis:
                yield node.lineno, "stub expression '...' is forbidden"
        elif isinstance(node, ast.Raise):
            exception = node.exc
            if isinstance(exception, ast.Call):
                exception = exception.func
            if isinstance(exception, ast.Name) and exception.id == "NotImplementedError":
                yield node.lineno, "NotImplementedError stub is forbidden"


def _comment_violations(path: pathlib.Path) -> Iterable[tuple[int, str]]:
    with path.open("rb") as stream:
        for token in tokenize.tokenize(stream.readline):
            if token.type != tokenize.COMMENT:
                continue
            upper = token.string.upper()
            for marker in STUB_MARKERS:
                if re.search(rf"\b{marker}\b", upper):
                    yield token.start[0], f"stub marker {marker} is forbidden"


def inspect_file(path: pathlib.Path) -> list[dict[str, Any]]:
    source = path.read_text(encoding="utf-8")
    violations: list[dict[str, Any]] = []
    lines = _line_count(source)
    if lines > MAX_FILE_LINES:
        violations.append(
            {
                "path": str(path),
                "line": 1,
                "rule": "max-file-lines",
                "actual": lines,
                "limit": MAX_FILE_LINES,
                "message": f"file has {lines} lines; limit is {MAX_FILE_LINES}",
            }
        )
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as error:
        violations.append(
            {
                "path": str(path),
                "line": error.lineno or 1,
                "rule": "parse-error",
                "message": error.msg,
            }
        )
        return violations
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        end_line = getattr(node, "end_lineno", node.lineno)
        function_lines = end_line - node.lineno + 1
        name = _function_name(node)
        if function_lines > MAX_FUNCTION_LINES:
            violations.append(
                {
                    "path": str(path),
                    "line": node.lineno,
                    "rule": "max-function-lines",
                    "actual": function_lines,
                    "limit": MAX_FUNCTION_LINES,
                    "message": (
                        f"function {name} has {function_lines} lines; "
                        f"limit is {MAX_FUNCTION_LINES}"
                    ),
                }
            )
        complexity = _complexity(node)
        if complexity > MAX_COGNITIVE_COMPLEXITY:
            violations.append(
                {
                    "path": str(path),
                    "line": node.lineno,
                    "rule": "cognitive-complexity",
                    "actual": complexity,
                    "limit": MAX_COGNITIVE_COMPLEXITY,
                    "message": (
                        f"function {name} has cognitive complexity {complexity}; "
                        f"limit is {MAX_COGNITIVE_COMPLEXITY}"
                    ),
                }
            )
    for line, message in _stub_violations(tree):
        violations.append(
            {"path": str(path), "line": line, "rule": "stub", "message": message}
        )
    for line, message in _comment_violations(path):
        violations.append(
            {"path": str(path), "line": line, "rule": "stub", "message": message}
        )
    return violations


def main() -> None:
    paths = [pathlib.Path(value) for value in sys.argv[1:]]
    violations: list[dict[str, Any]] = []
    for path in paths:
        violations.extend(inspect_file(path))
    print(json.dumps(violations, separators=(",", ":")))


if __name__ == "__main__":
    main()
