# Contributing

## Development Setup

```bash
git clone https://github.com/NP-compete/owasp-agentic-scanner.git
cd owasp-agentic-scanner
make install-dev
```

## Running Checks

```bash
make pre-commit  # Run all checks (lint, format, test)
make test        # Run tests only
make lint        # Run linting only
```

## Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make changes and add tests
4. Run checks: `make pre-commit`
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation
   - `test:` - Tests
   - `refactor:` - Refactoring
6. Push and open a Pull Request

## Code Standards

- Python 3.11+
- Type hints required
- Ruff for linting/formatting
- 80% test coverage minimum

## Adding a New Rule

1. Create `src/owasp_agentic_scanner/rules/your_rule.py`
2. Inherit from `BaseRule`
3. Define patterns in `_get_patterns()`
4. Add tests in `tests/unit/test_rules.py`
5. Register in `rules/__init__.py`

```python
from owasp_agentic_scanner.rules.base import BaseRule, DetectionPattern, Severity, pattern

class YourRule(BaseRule):
    rule_id = "AA99"
    rule_name = "Your Rule Name"
    owasp_category = "Category"
    description = "What this rule detects"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"your_regex"),
                message="Finding message",
                recommendation="How to fix",
                severity=Severity.HIGH,
                confidence="high",
            ),
        ]
```

## PR Checklist

- [ ] `make pre-commit` passes
- [ ] Tests added for new features
- [ ] Documentation updated if needed

## Questions

Open an issue or start a discussion.
