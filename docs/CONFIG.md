# Configuration

## Configuration File

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

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OWASP_SCAN_PARALLEL` | Enable parallel scanning | `false` |
| `OWASP_SCAN_MAX_WORKERS` | Number of parallel workers | `4` |
| `OWASP_SCAN_MIN_SEVERITY` | Minimum severity to report | `low` |
| `OWASP_SCAN_FORMAT` | Output format | `console` |

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
