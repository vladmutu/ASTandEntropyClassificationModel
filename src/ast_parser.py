import ast
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import esprima

from entropy import calculate_shannon_entropy


MAX_AST_FILE_SIZE = 1_000_000
HIGH_ENTROPY_THRESHOLD = 4.5
IDENTIFIER_MIN_LENGTH = 4

NETWORK_MODULE_PREFIXES = (
    "requests",
    "urllib",
    "socket",
)

JS_NETWORK_CALL_MARKERS = (
    "fetch",
    "http.request",
    "https.request",
    "net.connect",
    "dns.resolve",
    "axios.get",
    "axios.post",
    "axios.request",
    "xmlhttprequest.open",
)

PY_NETWORK_CALL_MARKERS = (
    "requests.",
    "urllib.",
    "socket.",
    "http.client.",
)

SENSITIVE_PATH_RE = re.compile(
    r"(?:~[\\/](?:\.ssh|\.npmrc)|/etc/(?:passwd|shadow)|AppData[\\/]Roaming|pip\.conf)",
    re.IGNORECASE,
)
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{32,}$")
HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{32,}$")


def _init_feature_counts() -> dict[str, float]:
    return {
        "eval_count": 0,
        "high_entropy_eval_count": 0,
        "exec_count": 0,
        "new_function_count": 0,
        "base64_count": 0,
        "base64_in_code_count": 0,
        "hex_literal_count": 0,
        "network_imports": 0,
        "network_call_count": 0,
        "unique_domains": 0,
        "suspicious_tlds_count": 0,
        "high_entropy_url_in_network_count": 0,
        "child_process_count": 0,
        "child_process_exec_count": 0,
        "buffer_count": 0,
        "os_env_count": 0,
        "file_read_count": 0,
        "file_write_count": 0,
        "sensitive_path_access_count": 0,
        "high_entropy_literal_count": 0,
        "high_entropy_identifier_count": 0,
        "string_literal_count": 0,
        "string_literal_entropy_sum": 0.0,
        "identifier_count": 0,
        "identifier_entropy_sum": 0.0,
        "max_ast_depth": 0,
        "function_count": 0,
        "function_node_total": 0,
        "dead_code_indicators": 0,
        "encoded_payload_chain_count": 0,
        "max_string_entropy": 0.0,
        "max_identifier_entropy": 0.0,
        "settimeout_string_count": 0,
        "dynamic_require_count": 0,
        "dynamic_import_count": 0,
        "eval_string_literal_count": 0,
    }


def _merge_counts(target: dict[str, float], source: dict[str, float]) -> None:
    for key, value in source.items():
        target[key] = target.get(key, 0) + value


def _safe_read_text(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _literal_text_from_node(node: Any) -> str | None:
    if node is None:
        return None

    node_type = getattr(node, "type", "")
    if node_type == "Literal":
        value = getattr(node, "value", None)
        return value if isinstance(value, str) else None
    if node_type == "TemplateLiteral":
        expressions = getattr(node, "expressions", []) or []
        quasis = getattr(node, "quasis", []) or []
        if expressions:
            return None
        parts = []
        for quasi in quasis:
            raw = getattr(getattr(quasi, "value", None), "cooked", None)
            if raw is None:
                raw = getattr(getattr(quasi, "value", None), "raw", None)
            if isinstance(raw, str):
                parts.append(raw)
        return "".join(parts) if parts else None
    return None


def _extract_js_callee_name(node: Any) -> str:
    if node is None:
        return ""

    node_type = getattr(node, "type", "")
    if node_type == "Identifier":
        return getattr(node, "name", "")
    if node_type == "ThisExpression":
        return "this"
    if node_type == "MemberExpression":
        object_name = _extract_js_callee_name(getattr(node, "object", None))
        property_node = getattr(node, "property", None)
        property_name = getattr(property_node, "name", None) or getattr(property_node, "value", "")
        if object_name and property_name:
            return f"{object_name}.{property_name}"
        return property_name or object_name
    return ""


def _extract_python_callee_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _extract_python_callee_name(node.value)
        if prefix:
            return f"{prefix}.{node.attr}"
        return node.attr
    return ""


@lru_cache(maxsize=4096)
def _entropy_for_text(text: str) -> float:
    if not text:
        return 0.0
    return calculate_shannon_entropy(text.encode("utf-8", errors="ignore"))


def _record_string_context(counts: dict[str, float], text: str, context: str = "") -> float:
    entropy = _entropy_for_text(text)
    if not text:
        return 0.0

    counts["string_literal_count"] += 1
    counts["string_literal_entropy_sum"] += entropy
    counts["max_string_entropy"] = max(counts["max_string_entropy"], entropy)

    if len(text) >= IDENTIFIER_MIN_LENGTH and entropy >= HIGH_ENTROPY_THRESHOLD:
        counts["high_entropy_literal_count"] += 1

    if BASE64_RE.match(text):
        counts["base64_count"] += 1

    if HEX_RE.match(text):
        counts["hex_literal_count"] += 1

    if SENSITIVE_PATH_RE.search(text):
        counts["sensitive_path_access_count"] += 1

    if context == "eval":
        counts["eval_string_literal_count"] += 1
        if entropy >= HIGH_ENTROPY_THRESHOLD:
            counts["high_entropy_eval_count"] += 1
    elif context == "network":
        if entropy >= HIGH_ENTROPY_THRESHOLD:
            counts["high_entropy_url_in_network_count"] += 1
    elif context == "decode":
        counts["base64_in_code_count"] += 1

    return entropy


def _record_identifier_context(counts: dict[str, float], identifier: str) -> None:
    if len(identifier) < IDENTIFIER_MIN_LENGTH:
        return

    entropy = _entropy_for_text(identifier)
    counts["identifier_count"] += 1
    counts["identifier_entropy_sum"] += entropy
    counts["max_identifier_entropy"] = max(counts["max_identifier_entropy"], entropy)
    if entropy >= HIGH_ENTROPY_THRESHOLD:
        counts["high_entropy_identifier_count"] += 1


def _is_fs_read_call(name: str) -> bool:
    lowered = name.lower()
    return any(
        marker in lowered
        for marker in (
            "readfile",
            "readtext",
            "readbytes",
            "open",
            "getdata",
            "readstream",
        )
    )


def _is_fs_write_call(name: str) -> bool:
    lowered = name.lower()
    return any(
        marker in lowered
        for marker in (
            "writefile",
            "writetext",
            "writebytes",
            "append",
            "unlink",
            "remove",
            "rm",
        )
    )


def _is_network_call(name: str) -> bool:
    lowered = name.lower()
    if lowered == "fetch" or lowered.endswith("xmlhttprequest.open"):
        return True
    return any(marker in lowered for marker in JS_NETWORK_CALL_MARKERS + PY_NETWORK_CALL_MARKERS)


def _extract_domain(text: str) -> str | None:
    match = re.search(r"https?://([^/\s'\"]+)", text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def _should_treat_as_shell_command(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in ("sh -c", "bash -c", "cmd.exe /c", "powershell", "curl ", "wget ", "python -c", "node -e"))


def _fast_scan_python_text(source: str) -> dict[str, float]:
    counts = _init_feature_counts()
    if not source:
        return counts

    counts["eval_count"] = source.count("eval(")
    counts["exec_count"] = source.count("exec(")
    counts["base64_count"] = source.count("base64.b64decode(")
    counts["network_imports"] = sum(
        source.count(pattern)
        for pattern in (
            "import requests",
            "from requests",
            "import socket",
            "from socket",
            "import urllib",
            "from urllib",
        )
    )
    counts["network_call_count"] = sum(source.count(marker) for marker in ("requests.", "urllib.", "socket.", "http.client."))
    counts["os_env_count"] = sum(source.count(pattern) for pattern in ("os.environ", "os.getenv", "os.getlogin", "pwd.getpwuid"))
    counts["file_read_count"] = sum(source.count(pattern) for pattern in ("open(", ".read_text(", ".read_bytes(", ".read()"))
    counts["file_write_count"] = sum(source.count(pattern) for pattern in ("write(", ".write_text(", ".write_bytes(", ".unlink(", "os.remove("))
    return counts


def _fast_scan_javascript_text(source: str) -> dict[str, float]:
    counts = _init_feature_counts()
    if not source:
        return counts

    counts["eval_count"] = source.count("eval(")
    counts["settimeout_string_count"] = source.count("setTimeout(")
    counts["new_function_count"] = source.count("new Function(")
    counts["buffer_count"] = source.count("Buffer")
    counts["child_process_count"] = source.count("child_process")
    counts["exec_count"] = counts["settimeout_string_count"] + counts["child_process_count"]
    counts["network_call_count"] = sum(source.count(marker) for marker in ("fetch(", "http.request", "https.request", "XMLHttpRequest", "axios."))
    counts["os_env_count"] = source.count("process.env")
    counts["file_read_count"] = sum(source.count(pattern) for pattern in ("readFile", "readFileSync", "readStream", "createReadStream"))
    counts["file_write_count"] = sum(source.count(pattern) for pattern in ("writeFile", "writeFileSync", "appendFile", "unlink", "rmSync"))
    return counts


@dataclass
class _PythonVisitorState:
    counts: dict[str, float]
    current_function_depth: int = 0
    current_ast_depth: int = 0


class _PythonDangerVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.state = _PythonVisitorState(counts=_init_feature_counts())

    @property
    def counts(self) -> dict[str, float]:
        return self.state.counts

    def _bump_depth(self, node: ast.AST) -> None:
        depth = 0
        current: ast.AST | None = node
        while current is not None:
            depth += 1
            current = getattr(current, "parent", None)
        self.state.counts["max_ast_depth"] = max(self.state.counts["max_ast_depth"], depth)

    def generic_visit(self, node: ast.AST) -> Any:
        for child in ast.iter_child_nodes(node):
            setattr(child, "parent", node)
        self._bump_depth(node)
        super().generic_visit(node)

    def visit_Import(self, node: ast.Import) -> Any:
        self._bump_depth(node)
        for alias in node.names:
            imported = alias.name
            if imported.startswith(NETWORK_MODULE_PREFIXES):
                self.counts["network_imports"] += 1
        return self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        self._bump_depth(node)
        module = node.module or ""
        if module.startswith(NETWORK_MODULE_PREFIXES):
            self.counts["network_imports"] += 1
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self.counts["function_count"] += 1
        self.state.current_function_depth += 1
        self.counts["function_node_total"] += 1
        _record_identifier_context(self.counts, node.name)
        result = self.generic_visit(node)
        self.state.current_function_depth -= 1
        return result

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        return self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        _record_identifier_context(self.counts, node.name)
        return self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> Any:
        _record_identifier_context(self.counts, node.id)
        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> Any:
        if isinstance(node.value, str):
            _record_string_context(self.counts, node.value)
        return self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        func_name = _extract_python_callee_name(node.func)
        lowered = func_name.lower()
        args = list(node.args)

        if func_name == "eval":
            self.counts["eval_count"] += 1
            if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
                _record_string_context(self.counts, args[0].value, context="eval")
        elif func_name == "exec":
            self.counts["exec_count"] += 1
            if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
                _record_string_context(self.counts, args[0].value, context="eval")
        elif func_name == "__import__" or lowered.endswith("importlib.import_module"):
            self.counts["dynamic_import_count"] += 1

        if lowered.startswith("base64.b64decode") or lowered.endswith("codecs.decode"):
            self.counts["base64_count"] += 1
            if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
                _record_string_context(self.counts, args[0].value, context="decode")

        if lowered.startswith("subprocess.") or lowered == "os.system":
            self.counts["child_process_count"] += 1
            self.counts["child_process_exec_count"] += 1

        if lowered.startswith("requests.") or lowered.startswith("urllib.") or lowered.startswith("socket.") or lowered.startswith("http.client."):
            self.counts["network_call_count"] += 1
            if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
                _record_string_context(self.counts, args[0].value, context="network")
                domain = _extract_domain(args[0].value)
                if domain:
                    self.counts["unique_domains"] += 1

        if lowered in {"open", "path.read_text", "path.read_bytes", "path.read"}:
            self.counts["file_read_count"] += 1
        if lowered in {"path.write_text", "path.write_bytes", "open.write", "os.remove", "os.unlink"}:
            self.counts["file_write_count"] += 1

        if args:
            first_arg = args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                if _should_treat_as_shell_command(first_arg.value):
                    self.counts["dead_code_indicators"] += 1
                if SENSITIVE_PATH_RE.search(first_arg.value):
                    self.counts["sensitive_path_access_count"] += 1

        if lowered == "eval" and args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
            if _entropy_for_text(args[0].value) >= HIGH_ENTROPY_THRESHOLD:
                self.counts["high_entropy_eval_count"] += 1

        return self.generic_visit(node)


def _walk_js(node: Any, counts: dict[str, float], depth: int = 0) -> None:
    if node is None:
        return

    if isinstance(node, list):
        for item in node:
            _walk_js(item, counts, depth)
        return

    node_type = getattr(node, "type", None)
    if not node_type:
        return

    counts["max_ast_depth"] = max(counts["max_ast_depth"], depth)

    if node_type == "Identifier":
        name = getattr(node, "name", "")
        _record_identifier_context(counts, name)
        if name == "Buffer":
            counts["buffer_count"] += 1

    elif node_type in {"Literal", "TemplateLiteral"}:
        text = _literal_text_from_node(node)
        if text is not None:
            _record_string_context(counts, text)

    elif node_type == "ImportDeclaration":
        source = getattr(getattr(node, "source", None), "value", "")
        if isinstance(source, str) and source.startswith(NETWORK_MODULE_PREFIXES):
            counts["network_imports"] += 1

    elif node_type == "CallExpression":
        callee = getattr(node, "callee", None)
        args = getattr(node, "arguments", []) or []
        callee_name = _extract_js_callee_name(callee)
        lowered = callee_name.lower()

        if lowered == "eval":
            counts["eval_count"] += 1
            if args and (text := _literal_text_from_node(args[0])) is not None:
                _record_string_context(counts, text, context="eval")
                if _entropy_for_text(text) >= HIGH_ENTROPY_THRESHOLD:
                    counts["high_entropy_eval_count"] += 1

        if lowered == "settimeout" and args and (text := _literal_text_from_node(args[0])) is not None:
            counts["settimeout_string_count"] += 1
            counts["exec_count"] += 1
            _record_string_context(counts, text, context="eval")

        if lowered == "require":
            if args:
                first_arg = args[0]
                text = _literal_text_from_node(first_arg)
                if text is None:
                    counts["dynamic_require_count"] += 1
                else:
                    if text == "child_process":
                        counts["child_process_count"] += 1
                    if text.startswith(NETWORK_MODULE_PREFIXES):
                        counts["network_imports"] += 1

        if "child_process" in lowered:
            counts["child_process_count"] += 1
            counts["child_process_exec_count"] += 1
            if "exec" in lowered:
                counts["exec_count"] += 1

        if _is_network_call(lowered):
            counts["network_call_count"] += 1
            for arg in args:
                text = _literal_text_from_node(arg)
                if text is not None:
                    _record_string_context(counts, text, context="network")
                    domain = _extract_domain(text)
                    if domain:
                        counts["unique_domains"] += 1

        if lowered.startswith("buffer.from"):
            for arg in args:
                text = _literal_text_from_node(arg)
                if text is not None and "base64" in text.lower():
                    counts["base64_in_code_count"] += 1
                    _record_string_context(counts, text, context="decode")

    elif node_type == "NewExpression":
        callee = getattr(node, "callee", None)
        callee_name = _extract_js_callee_name(callee).lower()
        if callee_name == "function":
            counts["new_function_count"] += 1
            counts["exec_count"] += 1

    for value in vars(node).values():
        if isinstance(value, list):
            for item in value:
                _walk_js(item, counts, depth + 1)
        elif hasattr(value, "type"):
            _walk_js(value, counts, depth + 1)


def _finalize_counts(counts: dict[str, float]) -> dict[str, float]:
    string_count = counts.get("string_literal_count", 0) or 0
    identifier_count = counts.get("identifier_count", 0) or 0
    function_count = counts.get("function_count", 0) or 0
    function_total = counts.get("function_node_total", 0) or 0

    counts["string_literal_entropy_mean"] = (
        counts.get("string_literal_entropy_sum", 0.0) / string_count if string_count else 0.0
    )
    counts["identifier_entropy_mean"] = (
        counts.get("identifier_entropy_sum", 0.0) / identifier_count if identifier_count else 0.0
    )
    counts["avg_function_length"] = function_total / function_count if function_count else 0.0
    counts["obfuscated_execution_flag"] = 1 if (
        counts.get("encoded_payload_chain_count", 0) > 0
        or (
            counts.get("base64_in_code_count", 0) > 0
            and counts.get("eval_count", 0) > 0
            and counts.get("high_entropy_eval_count", 0) > 0
        )
    ) else 0
    counts["install_time_attack_flag"] = 0
    counts["exfiltration_score"] = min(
        1.0,
        0.45 * min(1.0, (counts.get("os_env_count", 0) + counts.get("sensitive_path_access_count", 0)) / 5.0)
        + 0.45 * min(1.0, counts.get("network_call_count", 0) / 5.0)
        + 0.10 * min(1.0, counts.get("unique_domains", 0) / 5.0),
    )
    return counts


def analyze_python_file(file_path: Path) -> dict[str, float]:
    try:
        if file_path.stat().st_size > MAX_AST_FILE_SIZE:
            source = _safe_read_text(file_path)
            return _finalize_counts(_fast_scan_python_text(source))
    except OSError:
        return _finalize_counts(_init_feature_counts())

    try:
        source = _safe_read_text(file_path)
        if not source:
            return _finalize_counts(_init_feature_counts())
        tree = ast.parse(source)
    except Exception:
        return _finalize_counts(_init_feature_counts())

    visitor = _PythonDangerVisitor()
    visitor.visit(tree)
    return _finalize_counts(visitor.counts)


def analyze_javascript_file(file_path: Path) -> dict[str, float]:
    counts = _init_feature_counts()
    try:
        if file_path.stat().st_size > MAX_AST_FILE_SIZE:
            source = _safe_read_text(file_path)
            return _finalize_counts(_fast_scan_javascript_text(source))
    except OSError:
        return _finalize_counts(counts)

    try:
        source = _safe_read_text(file_path)
        if not source:
            return _finalize_counts(counts)
    except Exception:
        return _finalize_counts(counts)

    parsed = None
    try:
        parsed = esprima.parseScript(source, tolerant=True)
    except Exception:
        try:
            parsed = esprima.parseModule(source, tolerant=True)
        except Exception:
            return _finalize_counts(counts)

    _walk_js(parsed, counts)
    return _finalize_counts(counts)


def analyze_code_files(file_paths: list[Path]) -> dict[str, float]:
    totals = _init_feature_counts()

    for file_path in file_paths:
        suffix = file_path.suffix.lower()
        if suffix == ".py":
            counts = analyze_python_file(file_path)
            _merge_counts(totals, counts)
        elif suffix == ".js":
            counts = analyze_javascript_file(file_path)
            _merge_counts(totals, counts)

    return _finalize_counts(totals)
