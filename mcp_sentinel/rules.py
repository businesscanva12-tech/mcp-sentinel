"""
Security rules and signature patterns for detection.
"""

from typing import Dict, List, Pattern
import re

PATTERNS: Dict[str, Dict[str, str]] = {
    "ANTHROPIC_API_KEY": {
        "regex": r"sk-ant-api[a-zA-Z0-9_\-]{20,}",
        "severity": "CRITICAL",
        "description": "Anthropic Claude API key detected",
    },
    "OPENAI_API_KEY": {
        "regex": r"sk-[a-zA-Z0-9]{20,}",
        "severity": "CRITICAL",
        "description": "OpenAI API key detected",
    },
    "GITHUB_TOKEN": {
        "regex": r"(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}",
        "severity": "CRITICAL",
        "description": "GitHub Personal Access Token or OAuth key detected",
    },
    "AWS_ACCESS_KEY": {
        "regex": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": "HIGH",
        "description": "AWS Access Key ID detected",
    },
    "GENERIC_SECRET_ASSIGNMENT": {
        "regex": r"""(?i)(?:api_key|secret_key|auth_token|access_token|password|passwd|private_key)\s*[:=]\s*['"][a-zA-Z0-9@#$%^&*()_+=\-]{12,}['"]""",
        "severity": "MEDIUM",
        "description": "Hardcoded secret or credential assignment detected",
    },
    "PRIVATE_KEY_BLOCK": {
        "regex": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Unencrypted Private Key header block detected",
    },
}

DANGEROUS_AST_CALLS: Dict[str, str] = {
    "eval": "Dynamic code evaluation using eval() presents severe arbitrary execution risk",
    "exec": "Dynamic code execution using exec() presents arbitrary code execution risk",
    "os.system": "Executing shell commands directly with os.system() is vulnerable to injection",
    "subprocess.Popen": "Review subprocess usage with shell=True for command injection vulnerabilities",
}
