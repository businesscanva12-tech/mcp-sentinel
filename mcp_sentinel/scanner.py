"""
Scanner engine for credentials, high-entropy tokens, and dangerous AST structures.
"""

from typing import List, Optional, Set
from pydantic import BaseModel
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import math
import re
import ast
import os

from .rules import PATTERNS, DANGEROUS_AST_CALLS

DEFAULT_IGNORED_DIRS: Set[str] = {
    ".git", "__pycache__", ".venv", "venv", "env", "node_modules",
    "dist", "build", ".pytest_cache", ".ruff_cache", ".idea", ".vscode"
}


class Finding(BaseModel):
    rule_id: str
    severity: str
    description: str
    line_number: int
    matched_snippet: str
    file_path: Optional[str] = None


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string to identify generated keys/tokens."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1

    for count in char_counts.values():
        p_x = count / length
        entropy += -p_x * math.log2(p_x)

    return entropy


def scan_secrets(content: str, file_path: Optional[str] = None) -> List[Finding]:
    """Scans plain text or source code for hardcoded secrets, API keys, and private keys."""
    findings: List[Finding] = []
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        # Ignore comments or docs that explicitly state mock/test/dummy
        if any(marker in line.lower() for marker in ["mock", "dummy", "example_key", "placeholder"]):
            continue

        for rule_id, rule_data in PATTERNS.items():
            pattern = re.compile(rule_data["regex"])
            match = pattern.search(line)
            if match:
                # Obfuscate snippet for safety
                full_val = match.group(0)
                if len(full_val) > 8:
                    masked = full_val[:4] + "*" * (len(full_val) - 8) + full_val[-4:]
                else:
                    masked = "*" * len(full_val)

                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=rule_data["severity"],
                        description=rule_data["description"],
                        line_number=line_idx,
                        matched_snippet=masked,
                        file_path=file_path,
                    )
                )

    return findings


class SecurityAstVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Optional[str] = None):
        self.findings: List[Finding] = []
        self.file_path = file_path

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
            else:
                func_name = node.func.attr

        if func_name in DANGEROUS_AST_CALLS:
            self.findings.append(
                Finding(
                    rule_id=f"DANGEROUS_CALL_{func_name.upper().replace('.', '_')}",
                    severity="WARNING",
                    description=DANGEROUS_AST_CALLS[func_name],
                    line_number=node.lineno,
                    matched_snippet=f"{func_name}(...)",
                    file_path=self.file_path,
                )
            )

        self.generic_visit(node)


def audit_python_ast(content: str, file_path: Optional[str] = None) -> List[Finding]:
    """Audits Python source code AST for unsafe constructs like eval, exec, and unsanitized shell execution."""
    try:
        tree = ast.parse(content)
        visitor = SecurityAstVisitor(file_path=file_path)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError:
        return []


def scan_file(file_path: Path) -> List[Finding]:
    """Scans an individual file for secrets and unsafe AST calls."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    findings = scan_secrets(content, file_path=str(file_path))
    if file_path.suffix == ".py":
        findings += audit_python_ast(content, file_path=str(file_path))
    return findings


def scan_directory_parallel(directory_path: str, max_workers: int = 8) -> List[Finding]:
    """Scans an entire directory tree concurrently using ThreadPoolExecutor."""
    path = Path(directory_path)
    if not path.exists():
        return []

    files_to_scan: List[Path] = []
    if path.is_file():
        files_to_scan.append(path)
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORED_DIRS]
            for file in files:
                files_to_scan.append(Path(root) / file)

    all_findings: List[Finding] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(scan_file, files_to_scan)
        for res in results:
            all_findings.extend(res)

    return all_findings
