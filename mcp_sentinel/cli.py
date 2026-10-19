"""
Command line interface for MCP Sentinel.
"""

import argparse
import sys
import os
from pathlib import Path

from .scanner import scan_secrets, audit_python_ast
from .server import run_stdio_server


def scan_path(target_path: str):
    path = Path(target_path)
    if not path.exists():
        print(f"Error: Path '{target_path}' does not exist.")
        sys.exit(1)

    files_to_scan = []
    if path.is_file():
        files_to_scan.append(path)
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in [".git", "__pycache__", ".venv", "node_modules", "dist", "build"]]
            for file in files:
                files_to_scan.append(Path(root) / file)

    print(f"Scanning {len(files_to_scan)} files with MCP Sentinel...")
    total_findings = 0

    for file in files_to_scan:
        try:
            content = file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        secrets = scan_secrets(content, file_path=str(file))
        ast_calls = []
        if file.suffix == ".py":
            ast_calls = audit_python_ast(content, file_path=str(file))

        findings = secrets + ast_calls
        if findings:
            for f in findings:
                total_findings += 1
                print(f"[{f.severity}] {f.file_path}:{f.line_number} - {f.rule_id}: {f.description}")
                print(f"       Snippet: {f.matched_snippet}")

    if total_findings > 0:
        print(f"\nScan completed: {total_findings} security finding(s) detected.")
        sys.exit(1)
    else:
        print("\nScan passed: No security issues or hardcoded secrets found! ✨")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="MCP Sentinel: Security Scanner and MCP Server")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or file for security issues")
    scan_parser.add_argument("path", default=".", nargs="?", help="Path to scan")

    # serve subcommand
    serve_parser = subparsers.add_parser("serve", help="Run as a Model Context Protocol stdio server")

    args = parser.parse_args()

    if args.command == "serve":
        run_stdio_server()
    elif args.command == "scan":
        scan_path(args.path)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
