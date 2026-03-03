# OWASP Agentic AI Scanner

[![Lint](https://github.com/NP-compete/owasp-agentic-scanner/actions/workflows/lint.yml/badge.svg)](https://github.com/NP-compete/owasp-agentic-scanner/actions/workflows/lint.yml)
[![Test](https://github.com/NP-compete/owasp-agentic-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/NP-compete/owasp-agentic-scanner/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Static analysis tool for detecting security risks from the [OWASP Top 10 for Agentic AI Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

## Installation

```bash
pip install owasp-agentic-scanner
```

## Usage

```bash
# Scan a directory
owasp-scan scan src/

# Filter by severity
owasp-scan scan src --min-severity high

# Output as SARIF (for CI/CD)
owasp-scan scan src --format sarif --output results.sarif

# List available rules
owasp-scan list-rules
```

## OWASP Top 10 Coverage

| ID | Risk |
|----|------|
| AA01 | Agent Goal Hijack |
| AA02 | Tool Misuse & Exploitation |
| AA03 | Identity & Privilege Abuse |
| AA04 | Agentic Supply Chain |
| AA05 | Unexpected Code Execution |
| AA06 | Memory Poisoning |
| AA07 | Excessive Agency |
| AA08 | Insecure Plugin Design |
| AA09 | Overreliance on Outputs |
| AA10 | Model Theft |

## Inline Suppression

```python
eval(expression)  # noqa: AA05
```

## Documentation

- [Usage Guide](docs/USAGE.md)
- [CI/CD Integration](docs/CICD.md)
- [Configuration](docs/CONFIG.md)
- [Detection Rules](docs/RULES.md)
- [Architecture](docs/ARCHITECTURE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT - see [LICENSE](LICENSE).
