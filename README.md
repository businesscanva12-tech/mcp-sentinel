# MCP Sentinel 🛡️

[![CI](https://github.com/businesscanva12-tech/mcp-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/businesscanva12-tech/mcp-sentinel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version: v0.2.0](https://img.shields.io/badge/version-0.2.0-brightgreen.svg)](https://github.com/businesscanva12-tech/mcp-sentinel/releases)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP-orange.svg)](https://modelcontextprotocol.io/)
[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0-blueviolet.svg)](https://docs.github.com/en/code-security/code-scanning)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**MCP Sentinel** is a high-performance [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) security server and CLI tool designed as an automated safety & secret guardrail for **Claude Code**, **Claude Desktop**, and autonomous AI coding agents.

As autonomous AI agents read, refactor, and commit large codebases, they risk accidentally persisting sensitive environment variables, hardcoded API keys (Anthropic, OpenAI, HuggingFace, Stripe, AWS, GitHub), or generating dangerous dynamic execution patterns (`eval`, `exec`, unescaped `os.system`). **MCP Sentinel** verifies every patch and workspace in real time before changes hit disk or production.

---

## 🌟 What's New in v0.2.0

- 🌐 **25+ Secret & Cloud Providers**: Full detection coverage for Anthropic, OpenAI, Hugging Face, GitHub Fine-Grained PATs, GitLab, AWS, Google Cloud, Azure Storage, Stripe, Slack, Discord, SendGrid, Supabase, and private key blocks.
- 📊 **OASIS SARIF v2.1.0 Export**: Direct integration with GitHub Code Scanning, allowing automated vulnerability tabs on GitHub Pull Requests.
- ⚡ **High-Speed Concurrent Scanner**: Multi-threaded parallel file auditing capable of scanning thousands of files in milliseconds.
- 🪝 **Pre-Commit Hook Integration**: Ready-to-use `.pre-commit-hooks.yaml` for pre-commit and pre-push stages.
- 🛠️ **4 Native MCP Tools**: Extended agent toolkit with `scan_code_security`, `check_token_entropy`, `audit_repository_security`, and `generate_sarif_report`.

---

## 🚀 Quick Start

### Installation

Clone the repository and install in editable mode:

```bash
git clone https://github.com/businesscanva12-tech/mcp-sentinel.git
cd mcp-sentinel
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
```

---

## 🤖 Integration with Claude

### 1. Claude Desktop Setup

Add **mcp-sentinel** to your `claude_desktop_config.json`:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "python",
      "args": ["-m", "mcp_sentinel.cli", "serve"]
    }
  }
}
```

### 2. Claude Code CLI Setup

Register Sentinel directly into your Claude Code workspace:

```bash
claude mcp add sentinel python -m mcp_sentinel.cli serve
```

---

## 💻 CLI Usage

Sentinel can be used directly from your terminal or CI/CD pipelines:

### Standard Scan
```bash
# Scan current repository
mcp-sentinel scan .

# Scan with 16 parallel threads
mcp-sentinel scan . --workers 16
```

### Export to SARIF for GitHub Code Scanning
```bash
# Generate SARIF report for GitHub Actions
mcp-sentinel scan . --format sarif -o report.sarif
```

### Run as an MCP Server
```bash
mcp-sentinel serve
```

---

## 🪝 Pre-Commit Hook Configuration

Add MCP Sentinel to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/businesscanva12-tech/mcp-sentinel
    rev: v0.2.0
    hooks:
      - id: mcp-sentinel
```

---

## 🧪 Running Tests

Sentinel includes a comprehensive test suite covering pattern recognition, Shannon entropy calculations, and AST node visitors:

```bash
python -m unittest discover -s tests
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Check out the [Contributing Guidelines](CONTRIBUTING.md) to get started.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
