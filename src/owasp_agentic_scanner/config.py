"""Configuration file support for the scanner.

Allows users to configure scanner behavior via:
- .owasp-scan.toml in project root
- pyproject.toml [tool.owasp-scan] section
- Environment variables
"""

import contextlib
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScanConfig:
    """Scanner configuration.

    Can be loaded from:
    1. .owasp-scan.toml
    2. pyproject.toml [tool.owasp-scan]
    3. Environment variables
    4. CLI arguments (highest priority)
    """

    # Rules configuration
    enabled_rules: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)

    # Scanning behavior
    parallel: bool = True
    max_workers: int = 0  # 0 = auto-detect
    max_file_size: int = 10 * 1024 * 1024  # 10MB

    # Filtering
    min_severity: str = "info"
    exclude_patterns: list[str] = field(default_factory=list)
    include_patterns: list[str] = field(default_factory=list)

    # Output
    format: str = "console"
    output_file: str | None = None
    verbose: bool = False

    # Caching
    use_cache: bool = True
    cache_dir: str = ".owasp-cache"

    # Git integration
    only_git_changed: bool = False
    git_base_ref: str = "origin/main"

    # Baseline
    baseline_file: str | None = None
    create_baseline: bool = False

    # Paths
    exclude_dirs: list[str] = field(
        default_factory=lambda: [
            "__pycache__",
            ".git",
            "node_modules",
            ".venv",
            "venv",
            ".tox",
            "dist",
            "build",
        ]
    )

    @classmethod
    def load(cls, config_file: Path | None = None) -> "ScanConfig":
        """Load configuration from file and environment.

        Priority (highest to lowest):
        1. Explicit config_file argument
        2. .owasp-scan.toml in current directory
        3. pyproject.toml [tool.owasp-scan] section
        4. Environment variables
        5. Defaults

        Args:
            config_file: Explicit config file path

        Returns:
            Loaded configuration
        """
        config = cls()

        # Load from files
        if config_file and config_file.exists():
            config._load_from_file(config_file)
        elif (Path.cwd() / ".owasp-scan.toml").exists():
            config._load_from_file(Path.cwd() / ".owasp-scan.toml")
        elif (Path.cwd() / "pyproject.toml").exists():
            config._load_from_pyproject(Path.cwd() / "pyproject.toml")

        # Override with environment variables
        config._load_from_env()

        return config

    def _load_from_file(self, file_path: Path) -> None:
        """Load configuration from TOML file."""
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            self._apply_config(data)
        except Exception as e:
            import logging

            logger = logging.getLogger("owasp_scanner")
            logger.warning(f"Failed to load config from {file_path}: {e}")

    def _load_from_pyproject(self, file_path: Path) -> None:
        """Load configuration from pyproject.toml [tool.owasp-scan] section."""
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)

            if "tool" in data and "owasp-scan" in data["tool"]:
                self._apply_config(data["tool"]["owasp-scan"])
        except Exception as e:
            import logging

            logger = logging.getLogger("owasp_scanner")
            logger.warning(f"Failed to load config from {file_path}: {e}")

    def _apply_config(self, data: dict[str, Any]) -> None:
        """Apply configuration from dictionary."""
        # Rules
        if "enabled_rules" in data:
            self.enabled_rules = data["enabled_rules"]
        if "disabled_rules" in data:
            self.disabled_rules = data["disabled_rules"]

        # Scanning
        if "parallel" in data:
            self.parallel = data["parallel"]
        if "max_workers" in data:
            self.max_workers = data["max_workers"]
        if "max_file_size" in data:
            self.max_file_size = data["max_file_size"]

        # Filtering
        if "min_severity" in data:
            self.min_severity = data["min_severity"]
        if "exclude_patterns" in data:
            self.exclude_patterns = data["exclude_patterns"]
        if "include_patterns" in data:
            self.include_patterns = data["include_patterns"]

        # Output
        if "format" in data:
            self.format = data["format"]
        if "output_file" in data:
            self.output_file = data["output_file"]
        if "verbose" in data:
            self.verbose = data["verbose"]

        # Caching
        if "use_cache" in data:
            self.use_cache = data["use_cache"]
        if "cache_dir" in data:
            self.cache_dir = data["cache_dir"]

        # Git
        if "only_git_changed" in data:
            self.only_git_changed = data["only_git_changed"]
        if "git_base_ref" in data:
            self.git_base_ref = data["git_base_ref"]

        # Baseline
        if "baseline_file" in data:
            self.baseline_file = data["baseline_file"]
        if "create_baseline" in data:
            self.create_baseline = data["create_baseline"]

        # Paths
        if "exclude_dirs" in data:
            self.exclude_dirs = data["exclude_dirs"]

    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # OWASP_SCAN_PARALLEL=false
        if os.getenv("OWASP_SCAN_PARALLEL"):
            self.parallel = os.getenv("OWASP_SCAN_PARALLEL", "true").lower() == "true"

        # OWASP_SCAN_MAX_WORKERS=8
        if os.getenv("OWASP_SCAN_MAX_WORKERS"):
            with contextlib.suppress(ValueError):
                self.max_workers = int(os.getenv("OWASP_SCAN_MAX_WORKERS", "0"))

        # OWASP_SCAN_MIN_SEVERITY=high
        if os.getenv("OWASP_SCAN_MIN_SEVERITY"):
            self.min_severity = os.getenv("OWASP_SCAN_MIN_SEVERITY", "info")

        # OWASP_SCAN_FORMAT=sarif
        if os.getenv("OWASP_SCAN_FORMAT"):
            self.format = os.getenv("OWASP_SCAN_FORMAT", "console")

        # OWASP_SCAN_USE_CACHE=false
        if os.getenv("OWASP_SCAN_USE_CACHE"):
            self.use_cache = os.getenv("OWASP_SCAN_USE_CACHE", "true").lower() == "true"

        # OWASP_SCAN_ONLY_GIT_CHANGED=true
        if os.getenv("OWASP_SCAN_ONLY_GIT_CHANGED"):
            self.only_git_changed = (
                os.getenv("OWASP_SCAN_ONLY_GIT_CHANGED", "false").lower() == "true"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "enabled_rules": self.enabled_rules,
            "disabled_rules": self.disabled_rules,
            "parallel": self.parallel,
            "max_workers": self.max_workers,
            "max_file_size": self.max_file_size,
            "min_severity": self.min_severity,
            "exclude_patterns": self.exclude_patterns,
            "include_patterns": self.include_patterns,
            "format": self.format,
            "output_file": self.output_file,
            "verbose": self.verbose,
            "use_cache": self.use_cache,
            "cache_dir": self.cache_dir,
            "only_git_changed": self.only_git_changed,
            "git_base_ref": self.git_base_ref,
            "baseline_file": self.baseline_file,
            "create_baseline": self.create_baseline,
            "exclude_dirs": self.exclude_dirs,
        }

    def save(self, file_path: Path) -> None:
        """Save configuration to TOML file."""
        try:
            # We need tomli_w for writing
            import tomli_w  # type: ignore[import-not-found]

            with open(file_path, "wb") as f:
                tomli_w.dump(self.to_dict(), f)
        except ImportError:
            import logging

            logger = logging.getLogger("owasp_scanner")
            logger.warning("tomli_w not installed, cannot save config")
        except Exception as e:
            import logging

            logger = logging.getLogger("owasp_scanner")
            logger.error(f"Failed to save config: {e}")


def generate_sample_config() -> str:
    """Generate a sample configuration file."""
    return """# OWASP Agentic AI Scanner Configuration

# Rules to enable (empty = all rules)
enabled_rules = []

# Rules to disable
disabled_rules = []

# Scanning behavior
parallel = true
max_workers = 0  # 0 = auto-detect based on CPU count
max_file_size = 10485760  # 10MB in bytes

# Minimum severity to report
min_severity = "info"  # Options: critical, high, medium, low, info

# File patterns to exclude
exclude_patterns = [
    "**/*_pb2.py",  # Generated protobuf files
    "**/migrations/**",  # Database migrations
]

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
"""
