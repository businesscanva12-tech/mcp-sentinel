"""
Command line interface for MCP Sentinel.
"""

import argparse
import sys
import os
import json
from pathlib import Path

from .scanner import scan_directory_parallel
from .sarif import generate_sarif_report
from .server import run_stdio_server


def scan_path(target_path: str, output_format: str = "text", output_file: str = None, workers: int = 8):
    path = Path(target_path)
    if not path.exists():
        print(f"Error: Path '{target_path}' does not exist.")
        sys.exit(1)

    print(f"🔍 Running MCP Sentinel security scan on '{target_path}' (parallel workers: {workers})...")
    findings = scan_directory_parallel(target_path, max_workers=workers)

    if output_format == "sarif":
        sarif_data = generate_sarif_report(findings, tool_version="0.2.0")
        output_str = json.dumps(sarif_data, indent=2)
        if output_file:
            Path(output_file).write_text(output_str, encoding="utf-8")
            print(f"📄 SARIF report written to {output_file}")
        else:
            print(output_str)
        sys.exit(1 if findings else 0)

    # Standard human-readable console output
    for f in findings:
        color_prefix = "🚨" if f.severity in ["CRITICAL", "HIGH"] else "⚠️"
        print(f"{color_prefix} [{f.severity}] {f.file_path}:{f.line_number} - {f.rule_id}")
        print(f"   Description: {f.description}")
        print(f"   Snippet:     {f.matched_snippet}\n")

    if findings:
        print(f"❌ Scan failed: {len(findings)} security issue(s) detected.")
        if output_file:
            report_data = [f.model_dump() for f in findings]
            Path(output_file).write_text(json.dumps(report_data, indent=2), encoding="utf-8")
            print(f"Report saved to {output_file}")
        sys.exit(1)
    else:
        print("✅ Scan passed: No credentials or dangerous execution constructs found! ✨")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="MCP Sentinel: High-Performance Security Scanner & MCP Server")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or file for security issues")
    scan_parser.add_argument("path", default=".", nargs="?", help="Path to scan")
    scan_parser.add_argument("--format", choices=["text", "sarif", "json"], default="text", help="Output format")
    scan_parser.add_argument("-o", "--output", help="Write scan results to a file")
    scan_parser.add_argument("-w", "--workers", type=int, default=8, help="Number of concurrent worker threads")

    # serve subcommand
    subparsers.add_parser("serve", help="Run as a Model Context Protocol stdio server")

    args = parser.parse_args()

    if args.command == "serve":
        run_stdio_server()
    elif args.command == "scan":
        scan_path(args.path, output_format=args.format, output_file=args.output, workers=args.workers)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
