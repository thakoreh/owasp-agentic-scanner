# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Repository excellence improvements (labels, templates, automation)

## [0.1.0] - 2025-01-06

### Added
- Initial release of OWASP Agentic AI Scanner
- All 10 OWASP Agentic AI Top 10 detection rules:
  - AA01: Agent Goal Hijack
  - AA02: Tool Misuse & Exploitation
  - AA03: Identity & Privilege Abuse
  - AA04: Agentic Supply Chain
  - AA05: Unexpected Code Execution
  - AA06: Memory Poisoning
  - AA07: Excessive Agency
  - AA08: Insecure Plugin Design
  - AA09: Overreliance on Outputs
  - AA10: Model Theft
- AST-based analysis for Python code
- Taint tracking for data flow analysis
- Multiple output formats: console, JSON, SARIF
- CLI with `owasp-scan` command
- Pre-commit hook integration
- Inline suppression with `# noqa: AA01` comments
- Baseline system for managing known issues
- Incremental scanning with caching
- Git-aware scanning (scan only changed files)
- Configuration via TOML files or environment variables
- Parallel scanning support
- 294 comprehensive tests with 80% coverage

### Security
- Secure cache directory validation
- Protection against directory traversal attacks

[Unreleased]: https://github.com/NP-compete/owasp-agentic-scanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/NP-compete/owasp-agentic-scanner/releases/tag/v0.1.0
