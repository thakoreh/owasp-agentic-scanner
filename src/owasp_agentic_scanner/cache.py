"""Caching system for incremental scanning.

This enables scanning only changed files, making the scanner much faster
for repeated runs and CI/CD usage.
"""

import contextlib
import fcntl
import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Any

from owasp_agentic_scanner.constants import CHUNK_SIZE_BYTES, MAX_GIT_REF_LENGTH

logger = logging.getLogger("owasp_scanner")


class FileLock:
    """Simple file locking for cache access."""

    def __init__(self, lock_file: Path) -> None:
        """Initialize file lock."""
        self.lock_file = lock_file
        self.lock_fd: Any = None  # TextIOWrapper type

    def __enter__(self) -> "FileLock":
        """Acquire lock."""
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.lock_fd = open(self.lock_file, "w")

        if sys.platform != "win32":
            # Use fcntl on Unix-like systems
            with contextlib.suppress(OSError, AttributeError):
                fcntl.flock(self.lock_fd.fileno(), fcntl.LOCK_EX)
        # Note: Windows locking would require msvcrt, skipping for now

        return self

    def __exit__(self, *args: Any) -> None:
        """Release lock."""
        if self.lock_fd:
            if sys.platform != "win32":
                with contextlib.suppress(OSError, AttributeError):
                    fcntl.flock(self.lock_fd.fileno(), fcntl.LOCK_UN)
            self.lock_fd.close()
            self.lock_fd = None


class ScanCache:
    """Cache system for storing scan results.

    Tracks file hashes and findings to enable incremental scanning.
    Only re-scans files that have changed since the last run.
    """

    def __init__(self, cache_dir: Path | None = None, project_root: Path | None = None) -> None:
        """Initialize cache.

        Args:
            cache_dir: Directory to store cache (defaults to .owasp-cache in cwd)
            project_root: Root directory of project (for relative path keys)
        """
        self.cache_dir = cache_dir or Path.cwd() / ".owasp-cache"
        self.cache_file = self.cache_dir / "scan_cache.json"
        self.lock_file = self.cache_dir / "cache.lock"
        self.project_root = (project_root or Path.cwd()).absolute()
        self.cache_data: dict[str, dict[str, Any]] = {}
        self._load_cache()

    def _get_relative_path_key(self, file_path: Path) -> str:
        """Get cache key using relative path from project root.

        This makes cache portable when project is moved.
        """
        try:
            abs_path = file_path.absolute()
            # Validate path is within project
            abs_path.relative_to(self.project_root)
            return str(abs_path.relative_to(self.project_root))
        except ValueError:
            # File is outside project root - use absolute path
            logger.warning(f"File {file_path} is outside project root, using absolute path")
            return str(file_path.absolute())

    def _load_cache(self) -> None:
        """Load cache from disk with file locking."""
        if not self.cache_file.exists():
            self.cache_data = {}
            return

        try:
            with FileLock(self.lock_file):
                with open(self.cache_file, encoding="utf-8") as f:
                    self.cache_data = json.load(f)
                logger.debug(f"Loaded cache with {len(self.cache_data)} entries")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load cache: {e}")
            self.cache_data = {}

    def load(self) -> None:
        """Public method to reload cache from disk.

        This is useful when you want to explicitly reload the cache
        after it has been modified by another process.
        """
        self._load_cache()

    def save(self) -> None:
        """Save cache to disk with file locking."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            with FileLock(self.lock_file), open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache_data, f, indent=2)
            logger.debug(f"Saved cache with {len(self.cache_data)} entries")
        except OSError as e:
            logger.warning(f"Failed to save cache: {e}")

    def get_file_hash(self, file_path: Path, chunk_size: int = CHUNK_SIZE_BYTES) -> str:
        """Compute hash of file contents using streaming.

        Uses chunked reading to efficiently handle large files without
        loading them entirely into memory.

        Args:
            file_path: Path to file
            chunk_size: Size of chunks to read (default from constants)

        Returns:
            SHA256 hash of file contents
        """
        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read in chunks for optimal I/O performance
                # This balances I/O efficiency with memory usage
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except OSError:
            return ""

    def has_changed(self, file_path: Path) -> bool:
        """Check if a file has changed since last scan.

        Args:
            file_path: Path to file

        Returns:
            True if file has changed or is new, False if unchanged
        """
        file_key = self._get_relative_path_key(file_path)
        current_hash = self.get_file_hash(file_path)

        if not current_hash:
            return True  # Could not read file, treat as changed

        cached_entry = self.cache_data.get(file_key)
        if not cached_entry:
            return True  # New file

        return cached_entry.get("hash") != current_hash

    def update(self, file_path: Path, findings: list[Any]) -> None:
        """Update cache with new scan results.

        Args:
            file_path: Path to file that was scanned
            findings: List of Finding objects from the scan
        """
        file_key = self._get_relative_path_key(file_path)
        file_hash = self.get_file_hash(file_path)

        # Convert Finding objects to dicts for JSON serialization
        findings_dicts = []
        for finding in findings:
            if hasattr(finding, "__dict__"):
                # Convert Finding object to dict (with all required fields)
                finding_dict = {
                    "rule_id": finding.rule_id,
                    "rule_name": finding.rule_name,
                    "severity": finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity),
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "line_content": finding.line_content,
                    "message": finding.message,
                    "recommendation": finding.recommendation,
                    "owasp_category": finding.owasp_category,
                    "confidence": finding.confidence,
                }
                findings_dicts.append(finding_dict)
            else:
                findings_dicts.append(finding)

        self.cache_data[file_key] = {
            "hash": file_hash,
            "findings": findings_dicts,
            "mtime": file_path.stat().st_mtime if file_path.exists() else 0,
        }

    def get_findings(self, file_path: Path) -> list[dict[str, Any]]:
        """Get cached findings for a file (empty list if not cached).

        Args:
            file_path: Path to file

        Returns:
            List of cached findings, or empty list if no cache
        """
        findings = self.get_cached_findings(file_path)
        return findings if findings is not None else []

    def get_cached_findings(self, file_path: Path) -> list[dict[str, Any]] | None:
        """Get cached findings for a file if it hasn't changed.

        Args:
            file_path: Path to file

        Returns:
            List of cached findings, or None if file has changed or no cache exists
        """
        if self.has_changed(file_path):
            return None

        file_key = self._get_relative_path_key(file_path)
        cached_entry = self.cache_data.get(file_key)
        if cached_entry:
            return cached_entry.get("findings")
        return None

    def clear(self) -> None:
        """Clear all cache data."""
        self.cache_data = {}
        if self.cache_file.exists():
            try:
                self.cache_file.unlink()
                logger.info("Cache cleared")
            except OSError as e:
                logger.warning(f"Failed to clear cache: {e}")

    def prune_deleted_files(self, project_root: Path) -> None:
        """Remove cache entries for files that no longer exist.

        Args:
            project_root: Root directory of the project
        """
        deleted_keys: list[str] = []
        for file_key in self.cache_data:
            file_path = Path(file_key)
            if not file_path.exists() or not file_path.is_relative_to(project_root):
                deleted_keys.append(file_key)

        for key in deleted_keys:
            del self.cache_data[key]

        if deleted_keys:
            logger.debug(f"Pruned {len(deleted_keys)} deleted files from cache")


class GitAwareCache(ScanCache):
    """Cache that integrates with git to only scan changed files.

    This is particularly useful for CI/CD where you only want to scan
    files that changed in a PR or commit.
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        project_root: Path | None = None,
        git_root: Path | None = None,
    ) -> None:
        """Initialize git-aware cache.

        Args:
            cache_dir: Directory to store cache
            project_root: Root directory of project (for relative path keys)
            git_root: Root of git repository (auto-detected if not provided)
        """
        super().__init__(cache_dir, project_root)
        self.git_root = git_root or self._find_git_root()

    def _find_git_root(self) -> Path | None:
        """Find the root of the git repository."""
        current = Path.cwd()
        while current != current.parent:
            if (current / ".git").exists():
                return current
            current = current.parent
        return None

    def _validate_git_ref(self, ref: str) -> bool:
        """Validate that a git reference is safe and valid using allowlist approach.

        Prevents command injection by strictly validating git reference format.

        Args:
            ref: Git reference to validate

        Returns:
            True if valid, False otherwise
        """
        import re

        # Strict allowlist: only alphanumeric, dash, underscore, slash, dot, caret
        # Matches: HEAD, main, feature/branch, v1.0.0, HEAD^, origin/main
        # Prevents: ref;whoami, ref\nwhoami, ref$(whoami), ref|whoami, etc.
        safe_pattern = re.compile(r"^[a-zA-Z0-9/_.\-^]+$")

        if not safe_pattern.match(ref):
            logger.warning(f"Invalid git ref rejected: {ref}")
            return False

        # Additional length limit to prevent DoS
        if len(ref) > MAX_GIT_REF_LENGTH:
            logger.warning(f"Git ref too long: {len(ref)} chars")
            return False

        # Prevent directory traversal attempts
        if ".." in ref:
            logger.warning(f"Git ref contains directory traversal: {ref}")
            return False

        return True

    def get_changed_files(self, base_ref: str = "origin/main") -> set[Path]:
        """Get list of files changed since base_ref.

        Args:
            base_ref: Git reference to compare against (default: origin/main)

        Returns:
            Set of paths to changed files
        """
        import subprocess

        if not self.git_root:
            logger.warning("Not in a git repository")
            return set()

        # Validate git reference to prevent command injection
        if not self._validate_git_ref(base_ref):
            logger.error(f"Refusing to use invalid git reference: {base_ref}")
            return set()

        try:
            # Use three-dot diff to compare against merge base
            # This gives correct diff for PRs/branches
            result = subprocess.run(
                ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
                cwd=self.git_root,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )

            changed_files = set()
            for line in result.stdout.splitlines():
                file_path = self.git_root / line.strip()
                if file_path.exists() and file_path.is_file():
                    changed_files.add(file_path)

            logger.info(f"Found {len(changed_files)} changed files since {base_ref}")
            return changed_files

        except subprocess.CalledProcessError as e:
            logger.warning(f"Git command failed: {e}")
            return set()
        except subprocess.TimeoutExpired:
            logger.warning("Git command timed out")
            return set()

    def should_scan_file(self, file_path: Path, only_changed: bool = False) -> bool:
        """Determine if a file should be scanned.

        Args:
            file_path: Path to file
            only_changed: If True, only scan files changed in git

        Returns:
            True if file should be scanned
        """
        if only_changed:
            changed_files = self.get_changed_files()
            return file_path in changed_files

        # Fall back to hash-based change detection
        return self.has_changed(file_path)
