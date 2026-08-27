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
