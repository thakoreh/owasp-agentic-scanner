# Configuration

## Configuration File

Create `.owasp-scan.toml` in your project root:

```toml
# Rules configuration
enabled_rules = ["goal_hijack", "code_execution", "privilege_abuse"]
disabled_rules = []

# Scanning behavior
parallel = true
max_workers = 0  # 0 = auto-detect based on CPU count
max_file_size = 10485760  # 10MB in bytes

# Minimum severity to report
min_severity = "info"  # Options: critical, high, medium, low, info

# File patterns to exclude
exclude_patterns = ["**/*_pb2.py", "**/migrations/**"]

# File patterns to include (empty = use default extensions)
include_patterns = []

# Output configuration
format = "console"  # Options: console, json, sarif
output_file = null  # null = stdout
verbose = false

# Caching for faster subsequent scans
use_cache = true
cache_dir = ".owasp-cache"

# Git integration (scan only changed files)
only_git_changed = false
git_base_ref = "origin/main"

# Baseline (suppress existing issues)
baseline_file = null  # Path to baseline file
create_baseline = false

# Directories to always exclude
exclude_dirs = [
    "__pycache__",
    ".git",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
]
```

## pyproject.toml Configuration

Alternatively, you can configure the scanner in your `pyproject.toml`:

```toml
[tool.owasp-scan]
enabled_rules = ["goal_hijack", "code_execution"]
parallel = true
min_severity = "medium"
exclude_patterns = ["tests/", "docs/"]
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OWASP_SCAN_PARALLEL` | Enable parallel scanning | `true` |
| `OWASP_SCAN_MAX_WORKERS` | Number of parallel workers (0 = auto) | `0` |
| `OWASP_SCAN_MIN_SEVERITY` | Minimum severity to report | `info` |
| `OWASP_SCAN_FORMAT` | Output format (console/json/sarif) | `console` |
| `OWASP_SCAN_USE_CACHE` | Enable caching for faster scans | `true` |
| `OWASP_SCAN_ONLY_GIT_CHANGED` | Scan only git-changed files | `false` |

## Configuration Priority

1. CLI arguments (highest)
2. Environment variables
3. `.owasp-scan.toml` in current directory
4. `pyproject.toml` `[tool.owasp-scan]` section
5. Default values (lowest)

## Severity Levels

- `critical` - Immediate security risk
- `high` - Significant security concern
- `medium` - Potential security issue
- `low` - Informational finding
- `info` - Debug/informational (default)
