# Contributing to MCP Sentinel

Thank you for your interest in contributing to **MCP Sentinel**! As an open-source security tool for AI coding assistants and the Model Context Protocol ecosystem, we welcome community contributions, bug reports, and rule additions.

## How to Contribute

1. **Fork the Repository**: Create a personal fork on GitHub.
2. **Clone and Install**:
   ```bash
   git clone https://github.com/<your-username>/mcp-sentinel.git
   cd mcp-sentinel
   python -m venv .venv
   source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   ```
3. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/new-security-rule
   ```
4. **Run Tests**:
   ```bash
   pytest
   ```
5. **Submit a Pull Request**: Provide a descriptive title and explanation of your changes.

## Adding New Secret Detection Rules

To add a new secret or credential pattern, inspect `mcp_sentinel/rules.py` and submit a PR with corresponding test cases in `tests/test_scanner.py`.

## Code of Conduct

Please be respectful and constructive in all community interactions.
