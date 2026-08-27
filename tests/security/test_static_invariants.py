from __future__ import annotations

import ast
from pathlib import Path

FORBIDDEN_AGENT_MODULES = frozenset(
    {"openai", "anthropic", "google.generativeai", "langchain", "litellm"}
)


def _get_python_files(root: Path) -> list[Path]:
    return list(root.rglob("*.py"))


def test_no_shell_true_in_codebase() -> None:
    src_root = Path("src/acip")
    assert src_root.exists(), "src/acip directory not found"

    violations: list[str] = []
    for file_path in _get_python_files(src_root):
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        violations.append(f"{file_path}:{node.lineno} uses shell=True")

    assert not violations, f"Forbidden shell=True found in: {violations}"


def test_no_direct_llm_sdk_imports_in_agents() -> None:
    agents_root = Path("src/acip/agents")
    assert agents_root.exists(), "src/acip/agents directory not found"

    violations: list[str] = []
    for file_path in _get_python_files(agents_root):
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_name = alias.name.split(".")[0]
                    if root_name in FORBIDDEN_AGENT_MODULES:
                        violations.append(f"{file_path}:{node.lineno} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_name = node.module.split(".")[0]
                    if root_name in FORBIDDEN_AGENT_MODULES:
                        violations.append(f"{file_path}:{node.lineno} imports from {node.module}")

    assert not violations, f"Direct LLM SDK imports in agents found: {violations}"


#: Attributes ``logging.Logger.makeRecord`` refuses to let ``extra`` overwrite.
#: ``message`` and ``asctime`` are rejected outright; the rest collide with
#: attributes already present on the record.
_RESERVED_LOGRECORD_KEYS = frozenset(
    """args asctime created exc_info exc_text filename funcName levelname levelno
    lineno message module msecs msg name pathname process processName
    relativeCreated stack_info taskName thread threadName""".split()
)

_LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)


def test_no_reserved_logrecord_keys_in_log_extra() -> None:
    """A reserved key in ``extra`` raises KeyError only when the record is emitted.

    That makes it invisible to any test running at a level which suppresses the
    call, and fatal in production at the level that does not. It cost this project
    a 5xx error handler that crashed instead of returning the documented envelope
    for every GroundingError, so the class is blocked statically rather than
    left to be rediscovered.
    """
    src_root = Path("src/acip")
    assert src_root.exists(), "src/acip directory not found"

    violations: list[str] = []
    for file_path in _get_python_files(src_root):
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in _LOG_METHODS):
                continue
            for keyword in node.keywords:
                if keyword.arg != "extra" or not isinstance(keyword.value, ast.Dict):
                    continue
                for key in keyword.value.keys:
                    if (
                        isinstance(key, ast.Constant)
                        and isinstance(key.value, str)
                        and key.value in _RESERVED_LOGRECORD_KEYS
                    ):
                        violations.append(
                            f"{file_path}:{node.lineno} logs extra={{{key.value!r}: ...}}"
                        )

    assert not violations, f"Reserved LogRecord keys passed to extra: {violations}"
