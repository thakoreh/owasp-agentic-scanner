# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in the OWASP Agentic AI Scanner, please report it responsibly.

### For Vulnerabilities in the Scanner Itself

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use one of these methods:

1. **GitHub Private Vulnerability Reporting** (Preferred)
   - Go to the [Security tab](https://github.com/NP-compete/owasp-agentic-scanner/security)
   - Click "Report a vulnerability"
   - Fill out the form with details

2. **Email**
   - Contact the maintainers directly via GitHub

### What to Include

Please include the following in your report:

- **Type of vulnerability** (RCE, path traversal, information disclosure, etc.)
- **Steps to reproduce** the vulnerability
- **Affected versions**
- **Potential impact**
- **Suggested fix** (if you have one)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### What to Expect

1. **Acknowledgment**: We'll confirm receipt of your report
2. **Assessment**: We'll evaluate the vulnerability
3. **Fix Development**: We'll develop and test a fix
4. **Coordinated Disclosure**: We'll work with you on disclosure timing
5. **Credit**: We'll credit you in the release notes (unless you prefer anonymity)

### For Vulnerabilities Detected BY the Scanner

If the scanner detects a vulnerability in your code, that's the scanner working as intended! 🎉

- Check the [documentation](docs/RULES.md) for remediation guidance
- Use inline suppression (`# noqa: AA01`) for false positives
- Open a [bug report](https://github.com/NP-compete/owasp-agentic-scanner/issues/new?template=bug_report.md) if you believe it's a false positive

## Security Best Practices

When using this scanner:

1. **Keep it updated**: Always use the latest version
2. **Review findings**: Don't blindly suppress warnings
3. **Integrate in CI/CD**: Catch issues early
4. **Use baselines carefully**: Don't baseline real vulnerabilities

## Scope

This security policy covers:

- The `owasp-agentic-scanner` Python package
- The CLI tool (`owasp-scan`)
- Official GitHub Actions and integrations

It does NOT cover:

- Third-party integrations
- Forks of this repository
- User-created rules or plugins

## Recognition

We appreciate security researchers who help keep this project safe. Contributors who report valid vulnerabilities will be:

- Credited in the release notes
- Added to our Security Hall of Fame (coming soon)

Thank you for helping secure the AI security community! 🛡️
