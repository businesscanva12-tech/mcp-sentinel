# MCP Sentinel 🛡️

[![CI](https://github.com/username/mcp-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/username/mcp-sentinel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP-orange.svg)](https://modelcontextprotocol.io/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**MCP Sentinel** is a lightweight, high-performance [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server and CLI tool designed to act as an automated security and secret guardrail for AI coding assistants like **Claude Code**, **Claude Desktop**, and agentic IDEs.

As autonomous AI agents read, refactor, and commit large codebases, they risk accidentally persisting sensitive environment variables, hardcoded API keys (Anthropic, OpenAI, AWS, GitHub), or generating insecure dynamic evaluation constructs (`eval`, `exec`, unescaped `os.system`). **MCP Sentinel** provides real-time verification before changes are finalized.

---

## 🌟 Key Features

- 🔑 **Real-time Secret Detection**: Instant regex-based & entropy-based identification of exposed API keys, private keys, and OAuth tokens.
- 🔬 **Python AST Safety Audit**: Inspects abstract syntax trees to flag dangerous dynamic execution patterns (`eval`, `exec`, insecure `subprocess` calls) before writing to disk.
- 📐 **Shannon Entropy Analysis**: Distinguishes between plain text and high-entropy cryptographically generated secrets to reduce false positives.
- 🔌 **Native MCP Integration**: Implements the Model Context Protocol stdio transport for frictionless plug-and-play setup with Claude Code and Claude Desktop.
- ⚡ **Zero-Friction CLI**: Can also be executed directly as a terminal utility (`mcp-sentinel scan .`) or integrated into CI/CD pipelines and pre-commit hooks.

---

## 🚀 Quick Start

### Installation

Clone the repository and install in editable mode:

```bash
git clone https://github.com/<your-username>/mcp-sentinel.git
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

You can register Sentinel directly within your Claude Code environment:

```bash
claude mcp add sentinel python -m mcp_sentinel.cli serve
```

Once registered, Claude can call `scan_code_security` and `check_token_entropy` tools during code generation and file edits.

---

## 💻 CLI Usage

You can also use Sentinel independently from the terminal:

### Scan a file or project directory
```bash
# Scan current directory
mcp-sentinel scan .

# Scan a specific file
mcp-sentinel scan src/config.py
```

### Run as an MCP Server
```bash
mcp-sentinel serve
```

---

## 🧪 Running Tests

Sentinel includes a comprehensive test suite covering pattern recognition, Shannon entropy calculations, and AST node visitors:

```bash
python -m unittest discover -s tests
```

---

## 🗺️ Roadmap

- [ ] Support for SARIF (Static Analysis Results Interchange Format) export.
- [ ] Integration with Gitleaks rulesets for custom corporate patterns.
- [ ] Pre-commit hook template (`.pre-commit-hooks.yaml`).
- [ ] Semantic AST taint analysis for JavaScript/TypeScript targets.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Check out the [Contributing Guidelines](CONTRIBUTING.md) to get started.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
