<p align="center">
  <img src="https://img.shields.io/badge/OWASP-Top%2010%20Agentic%20AI-blue?style=for-the-badge&logo=owasp" alt="OWASP Top 10 Agentic AI">
</p>

<h1 align="center">🛡️ OWASP Agentic AI Scanner</h1>

<p align="center">
  <strong>Static analysis tool for detecting security risks from the OWASP Top 10 for Agentic AI Applications</strong>
</p>

<p align="center">
  <a href="https://github.com/NP-compete/owasp-agentic-scanner/actions/workflows/lint.yml"><img src="https://github.com/NP-compete/owasp-agentic-scanner/actions/workflows/lint.yml/badge.svg" alt="Lint"></a>
  <a href="https://github.com/NP-compete/owasp-agentic-scanner/actions/workflows/test.yml"><img src="https://github.com/NP-compete/owasp-agentic-scanner/actions/workflows/test.yml/badge.svg" alt="Test"></a>
  <a href="https://github.com/NP-compete/owasp-agentic-scanner/actions/workflows/security.yml"><img src="https://github.com/NP-compete/owasp-agentic-scanner/actions/workflows/security.yml/badge.svg" alt="Security"></a>
  <br>
  <a href="https://pypi.org/project/owasp-agentic-scanner/"><img src="https://img.shields.io/pypi/v/owasp-agentic-scanner?color=blue" alt="PyPI"></a>
  <a href="https://pypi.org/project/owasp-agentic-scanner/"><img src="https://img.shields.io/pypi/pyversions/owasp-agentic-scanner" alt="Python Versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
  <a href="https://github.com/NP-compete/owasp-agentic-scanner/stargazers"><img src="https://img.shields.io/github/stars/NP-compete/owasp-agentic-scanner?style=social" alt="Stars"></a>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-owasp-top-10-coverage">OWASP Coverage</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-cicd-integration">CI/CD</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## ✨ Features

- 🔍 **All 10 OWASP Agentic AI risks** covered with 100+ detection patterns
- 🌳 **AST-based analysis** for accurate Python code scanning
- 🔄 **Taint tracking** for data flow analysis
- 📊 **Multiple output formats**: Console, JSON, SARIF
- ⚡ **Parallel scanning** for large codebases
- 💾 **Incremental scanning** with smart caching
- 🎯 **Baseline management** for tracking known issues
- 🔗 **Git integration** for scanning only changed files
- 🪝 **Pre-commit hook** for shift-left security

## 🚀 Quick Start

```bash
# Install from PyPI
pip install owasp-agentic-scanner

# Or install from source
git clone https://github.com/NP-compete/owasp-agentic-scanner.git
cd owasp-agentic-scanner
uv sync

# Scan your AI agent code
owasp-scan scan /path/to/your/agent

# Generate SARIF report for CI/CD
owasp-scan scan src --format sarif --output results.sarif
```

## 🎯 OWASP Top 10 Coverage

| ID | Risk | Description |
|----|------|-------------|
| **AA01** | Agent Goal Hijack | Prompt injection, system prompt manipulation |
| **AA02** | Tool Misuse & Exploitation | Unsafe shell commands, SQL injection |
| **AA03** | Identity & Privilege Abuse | Hardcoded credentials, privilege escalation |
| **AA04** | Agentic Supply Chain | Unsafe model loading, trust_remote_code |
| **AA05** | Unexpected Code Execution | eval(), exec(), dynamic code execution |
| **AA06** | Memory Poisoning | Vector store injection, RAG poisoning |
| **AA07** | Excessive Agency | Missing human-in-the-loop, auto-approval |
| **AA08** | Insecure Plugin Design | CORS misconfiguration, unsafe plugins |
| **AA09** | Overreliance on Outputs | Disabled validation, unchecked outputs |
| **AA10** | Model Theft | Missing rate limits, debug mode exposure |

## 📖 Usage

### Basic Scanning

```bash
# Scan a directory
owasp-scan scan src/

# Scan with specific rules
owasp-scan scan src --rules goal_hijack,code_execution

# Filter by severity
owasp-scan scan src --min-severity high

# List all available rules
owasp-scan list-rules
```

### Output Formats

```bash
# Console output (default)
owasp-scan scan src

# JSON output
owasp-scan scan src --format json --output results.json

# SARIF output (for GitHub Code Scanning)
owasp-scan scan src --format sarif --output results.sarif
```

### Advanced Features

```bash
# Parallel scanning (faster for large codebases)
owasp-scan scan src --parallel --workers 8

# Incremental scanning with cache
owasp-scan scan src --cache --cache-dir .owasp-cache

# Scan only git-changed files
owasp-scan scan src --git-diff main

# Use baseline to track known issues
owasp-scan scan src --baseline .owasp-baseline.json
```

### Inline Suppression

Suppress specific findings in your code:

```python
# Suppress a specific rule
eval(expression)  # noqa: AA05

# Suppress all rules on a line
exec(code)  # noqa: owasp-scan

# Suppress multiple rules
dangerous_call()  # noqa: AA02,AA05
```

## 🔗 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install scanner
        run: pip install owasp-agentic-scanner

      - name: Run OWASP scan
        run: owasp-scan scan src --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: python:3.12
  script:
    - pip install owasp-agentic-scanner
    - owasp-scan scan src --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/NP-compete/owasp-agentic-scanner
    rev: v0.1.0
    hooks:
      - id: owasp-agentic-scan
        args: [--min-severity, high]
```

## ⚙️ Configuration

Create `.owasp-scan.toml` in your project root:

```toml
[rules]
enabled = ["goal_hijack", "code_execution", "privilege_abuse"]
disabled = []

[scanning]
parallel = true
max_workers = 4
max_file_size = 1048576  # 1MB

[output]
format = "console"
verbose = true
min_severity = "medium"

[paths]
exclude = ["tests/", "docs/", "*.test.py"]
```

## 🧪 Test Coverage

| Component | Coverage | Tests |
|-----------|----------|-------|
| OWASP Rules | 100% | 21 |
| Baseline System | 96% | 20 |
| Config System | 90% | 22 |
| Scanner Engine | 89% | 37 |
| Cache System | 83% | 38 |
| **Total** | **80%** | **294** |

## 🛠️ Development

```bash
# Clone the repository
git clone https://github.com/NP-compete/owasp-agentic-scanner.git
cd owasp-agentic-scanner

# Install development dependencies
make install-dev

# Run all checks
make pre-commit

# Run tests only
make test

# Run linting only
make lint
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run checks (`make pre-commit`)
5. Commit (`git commit -m 'feat: Add amazing feature'`)
6. Push (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📚 Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Detection Rules](docs/RULES.md)
- [Extending the Scanner](docs/EXTENDING.md)
- [Pre-commit Integration](docs/PRE_COMMIT.md)
- [Changelog](CHANGELOG.md)

## 🔒 Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) or use GitHub's private vulnerability reporting.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP GenAI Security Project](https://genai.owasp.org/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

---

<p align="center">
  Made with ❤️ for the AI security community
</p>
