# Contributing to OWASP Agentic AI Scanner

Thank you for your interest in contributing!

## Getting Started

### 1. Fork the Repository

1. Go to [https://github.com/NP-compete/owasp-agentic-scanner](https://github.com/NP-compete/owasp-agentic-scanner)
2. Click the "Fork" button in the top right
3. This creates a copy in your GitHub account

### 2. Clone Your Fork

```bash
git clone https://github.com/YOUR-USERNAME/owasp-agentic-scanner.git
cd owasp-agentic-scanner
```

### 3. Add Upstream Remote

```bash
git remote add upstream https://github.com/NP-compete/owasp-agentic-scanner.git
git remote -v  # Verify you have both origin (your fork) and upstream (original repo)
```

### 4. Install Development Dependencies

```bash
make install-dev
```

## Development Workflow

### 1. Sync Your Fork

Before creating a new branch, sync with the latest changes:

```bash
git checkout main
git fetch upstream
git merge upstream/main
git push origin main  # Update your fork
```

### 2. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 3. Make Your Changes

- Write code following our code standards (see below)
- Add tests for new features
- Update documentation if needed

### 4. Run Checks

```bash
make pre-commit  # Runs linting, formatting, and tests
```

### 5. Commit Your Changes

```bash
git add .
git commit -m "feat: Add your feature description"
```

We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test changes
- `refactor:` - Code refactoring

### 6. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

### 7. Submit a Pull Request

1. Go to your fork on GitHub
2. Click "Pull Request" button
3. Select your feature branch
4. Fill out the PR template
5. Submit the PR

## Code Standards

- Python 3.11+
- Type hints required
- Ruff for linting/formatting
- 85% test coverage minimum

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

## PR Requirements

- [ ] All checks pass (`make pre-commit`)
- [ ] Tests added for new features
- [ ] Documentation updated if needed

## Questions?

Open an issue or discussion.
