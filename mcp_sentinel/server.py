"""
MCP Server implementation exposing tools for AI assistants like Claude Code.
"""

from typing import Any, Dict, List
import sys
import json
import os
from pathlib import Path

from .scanner import scan_secrets, audit_python_ast, calculate_shannon_entropy, scan_directory_parallel
from .sarif import generate_sarif_report


def run_stdio_server():
    """Runs a Model Context Protocol compatible JSON-RPC stdio loop."""
    sys.stderr.write("Starting MCP Sentinel Security Server v0.2.0...\n")
    sys.stderr.flush()

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            request = json.loads(line)
            msg_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})

            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "mcp-sentinel",
                            "version": "0.2.0"
                        }
                    }
                }
            elif method == "tools/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": [
                            {
                                "name": "scan_code_security",
                                "description": "Scan source code or configuration for leaked secrets, API keys, and insecure AST calls before saving.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "code": {"type": "string", "description": "The file content or patch to scan"},
                                        "filename": {"type": "string", "description": "Optional file path or name"}
                                    },
                                    "required": ["code"]
                                }
                            },
                            {
                                "name": "check_token_entropy",
                                "description": "Compute Shannon entropy of a string to verify if it represents a cryptographic secret or high-entropy key.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "token": {"type": "string", "description": "The candidate token to inspect"}
                                    },
                                    "required": ["token"]
                                }
                            },
                            {
                                "name": "audit_repository_security",
                                "description": "High-speed parallel scan across the entire workspace/repository to detect hardcoded credentials and dangerous AST calls.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "directory": {"type": "string", "description": "Directory path to audit (defaults to current dir)"}
                                    }
                                }
                            },
                            {
                                "name": "generate_sarif_report",
                                "description": "Generate an OASIS SARIF v2.1.0 security report for the workspace, compatible with GitHub Code Scanning.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "directory": {"type": "string", "description": "Directory path to audit (defaults to current dir)"}
                                    }
                                }
                            }
                        ]
                    }
                }
            elif method == "tools/call":
                tool_name = params.get("name")
                args = params.get("arguments", {})

                if tool_name == "scan_code_security":
                    code = args.get("code", "")
                    filename = args.get("filename", "unknown.py")
                    secret_findings = scan_secrets(code, file_path=filename)
                    ast_findings = []
                    if filename.endswith(".py"):
                        ast_findings = audit_python_ast(code, file_path=filename)

                    all_findings = [f.model_dump() for f in (secret_findings + ast_findings)]
                    is_safe = len(all_findings) == 0

                    result_text = json.dumps({
                        "status": "passed" if is_safe else "vulnerabilities_detected",
                        "findings_count": len(all_findings),
                        "findings": all_findings
                    }, indent=2)

                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": result_text
                                }
                            ]
                        }
                    }
                elif tool_name == "check_token_entropy":
                    token = args.get("token", "")
                    entropy = calculate_shannon_entropy(token)
                    is_suspicious = entropy > 3.8 and len(token) >= 16

                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps({
                                        "token_length": len(token),
                                        "entropy_score": round(entropy, 3),
                                        "is_high_entropy": is_suspicious,
                                        "recommendation": "Potential secret key" if is_suspicious else "Normal text"
                                    }, indent=2)
                                }
                            ]
                        }
                    }
                elif tool_name == "audit_repository_security":
                    directory = args.get("directory", ".")
                    findings = scan_directory_parallel(directory)
                    findings_data = [f.model_dump() for f in findings]
                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps({
                                        "directory": directory,
                                        "status": "clean" if not findings_data else "findings_detected",
                                        "total_findings": len(findings_data),
                                        "findings": findings_data
                                    }, indent=2)
                                }
                            ]
                        }
                    }
                elif tool_name == "generate_sarif_report":
                    directory = args.get("directory", ".")
                    findings = scan_directory_parallel(directory)
                    sarif_json = generate_sarif_report(findings, tool_version="0.2.0")
                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(sarif_json, indent=2)
                                }
                            ]
                        }
                    }
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method not found: {tool_name}"
                        }
                    }
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {}
                }

            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

        except Exception as e:
            sys.stderr.write(f"Error handling request: {e}\n")
            sys.stderr.flush()
