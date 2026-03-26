import ast
from pathlib import Path
from typing import Any

import esprima


NETWORK_MODULE_PREFIXES = ("requests", "socket", "urllib")


def _init_feature_counts() -> dict[str, int]:
    return {
        "eval_count": 0,
        "exec_count": 0,
        "base64_count": 0,
        "network_imports": 0,
        "settimeout_string_count": 0,
        "child_process_count": 0,
        "buffer_count": 0,
    }


class _PythonDangerVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.counts = _init_feature_counts()

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            imported = alias.name
            if imported.startswith(NETWORK_MODULE_PREFIXES):
                self.counts["network_imports"] += 1
        return self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        module = node.module or ""
        if module.startswith(NETWORK_MODULE_PREFIXES):
            self.counts["network_imports"] += 1
        return self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        func = node.func
        if isinstance(func, ast.Name):
            if func.id == "eval":
                self.counts["eval_count"] += 1
            elif func.id == "exec":
                self.counts["exec_count"] += 1
            elif func.id == "__import__":
                self.counts["network_imports"] += 1
        elif isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                if func.value.id == "base64" and func.attr == "b64decode":
                    self.counts["base64_count"] += 1

        return self.generic_visit(node)


def _merge_counts(target: dict[str, int], source: dict[str, int]) -> None:
    for key, value in source.items():
        target[key] = target.get(key, 0) + value


def _is_js_string_literal(node: Any) -> bool:
    if node is None:
        return False

    node_type = getattr(node, "type", "")
    if node_type == "Literal":
        value = getattr(node, "value", None)
        return isinstance(value, str)
    if node_type == "TemplateLiteral":
        expressions = getattr(node, "expressions", []) or []
        return len(expressions) == 0
    return False


def _walk_js(node: Any, counts: dict[str, int]) -> None:
    if node is None:
        return

    if isinstance(node, list):
        for item in node:
            _walk_js(item, counts)
        return

    node_type = getattr(node, "type", None)
    if not node_type:
        return

    if node_type == "CallExpression":
        callee = getattr(node, "callee", None)
        args = getattr(node, "arguments", []) or []

        if getattr(callee, "type", "") == "Identifier":
            name = getattr(callee, "name", "")
            if name == "eval":
                counts["eval_count"] += 1
            elif name == "setTimeout" and args and _is_js_string_literal(args[0]):
                counts["settimeout_string_count"] += 1
                counts["exec_count"] += 1
            elif name == "require" and args:
                first_arg = args[0]
                if getattr(first_arg, "type", "") == "Literal" and getattr(first_arg, "value", None) == "child_process":
                    counts["child_process_count"] += 1
                    counts["exec_count"] += 1

    if node_type == "Identifier" and getattr(node, "name", "") == "Buffer":
        counts["buffer_count"] += 1

    for value in vars(node).values():
        if isinstance(value, list):
            for item in value:
                _walk_js(item, counts)
        elif hasattr(value, "type"):
            _walk_js(value, counts)


def analyze_python_file(file_path: Path) -> dict[str, int]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source)
    except Exception:
        return _init_feature_counts()

    visitor = _PythonDangerVisitor()
    visitor.visit(tree)
    return visitor.counts


def analyze_javascript_file(file_path: Path) -> dict[str, int]:
    counts = _init_feature_counts()
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return counts

    parsed = None
    try:
        parsed = esprima.parseScript(source, tolerant=True)
    except Exception:
        try:
            parsed = esprima.parseModule(source, tolerant=True)
        except Exception:
            return counts

    _walk_js(parsed, counts)
    return counts


def analyze_code_files(file_paths: list[Path]) -> dict[str, int]:
    totals = _init_feature_counts()

    for file_path in file_paths:
        suffix = file_path.suffix.lower()
        if suffix == ".py":
            counts = analyze_python_file(file_path)
            _merge_counts(totals, counts)
        elif suffix == ".js":
            counts = analyze_javascript_file(file_path)
            _merge_counts(totals, counts)

    return totals
