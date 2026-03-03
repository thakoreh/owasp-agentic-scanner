"""Improved scanning engine with better performance and resource management."""

import logging
import os
from collections import deque
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from owasp_agentic_scanner.cache import ScanCache

from owasp_agentic_scanner.constants import (
    CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    CIRCUIT_BREAKER_TIMEOUT_SECONDS,
    DEFAULT_CPU_COUNT,
    DEFAULT_MAX_FILE_SIZE,
    FILE_SCAN_TIMEOUT_SECONDS,
    MAX_FINDINGS_PER_BATCH,
    MAX_WORKERS_LIMIT,
    SCAN_BATCH_SIZE,
    WORKER_CPU_MULTIPLIER,
)
from owasp_agentic_scanner.rules.base import BaseRule, Finding

logger = logging.getLogger("owasp_scanner")


class ScanTask:
    """Represents a single file scan task."""

    def __init__(self, rule: BaseRule, file_path: Path) -> None:
        """Initialize scan task."""
        self.rule = rule
        self.file_path = file_path

    def execute(self) -> tuple[Path, list[Finding]]:
        """Execute the scan task."""
        try:
            findings = self.rule.scan_file(self.file_path)
            return self.file_path, findings
        except Exception as e:
            logger.warning(
                f"Error scanning {self.file_path} with {self.rule.rule_id}: {e}",
                exc_info=True,
                extra={"file_path": str(self.file_path), "rule_id": self.rule.rule_id},
            )
            return self.file_path, []


@dataclass
class CircuitBreaker:
    """Circuit breaker to prevent cascading failures in parallel scanning.

    Implements the circuit breaker pattern to stop processing when too many
    failures occur, preventing resource exhaustion and cascading failures.
    """

    failure_threshold: int = CIRCUIT_BREAKER_FAILURE_THRESHOLD
    timeout_seconds: int = CIRCUIT_BREAKER_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        """Initialize circuit breaker state."""
        self.failures: deque[datetime] = deque(maxlen=self.failure_threshold)
        self.state = "closed"  # closed, open, half_open

    def record_failure(self) -> None:
        """Record a failure and update circuit state."""
        self.failures.append(datetime.now())

        # Count recent failures within timeout window
        recent_failures = sum(
            1
            for ts in self.failures
            if datetime.now() - ts < timedelta(seconds=self.timeout_seconds)
        )

        if recent_failures >= self.failure_threshold:
            self.state = "open"
            logger.warning(
                f"Circuit breaker opened: {recent_failures} failures in "
                f"{self.timeout_seconds} seconds"
            )

    def can_execute(self) -> bool:
        """Check if tasks can be executed."""
        if self.state == "closed":
            return True

        if self.state == "open":
            # Check if timeout has passed
            if self.failures and datetime.now() - self.failures[-1] > timedelta(
                seconds=self.timeout_seconds
            ):
                self.state = "half_open"
                logger.info("Circuit breaker half-open: trying execution")
                return True
            return False

        # half_open state - allow execution to test recovery
        return True


class OptimizedScanner:
    """Optimized scanner with better resource management.

    Improvements over original:
    - Lazy file discovery (generator-based)
    - Batched task submission (prevents memory explosion)
    - Better worker count defaults (CPU-aware)
    - Streaming results (don't hold all findings in memory)
    - File size limits (prevent DoS)
    - Better error handling and reporting
    """

    # Maximum file size to scan (from constants)
    MAX_FILE_SIZE = DEFAULT_MAX_FILE_SIZE

    # Batch size for task submission (from constants)
    BATCH_SIZE = SCAN_BATCH_SIZE

    def __init__(
        self,
        rules: list[BaseRule],
        max_workers: int | None = None,
        max_file_size: int | None = None,
    ) -> None:
        """Initialize scanner.

        Args:
            rules: List of rules to apply
            max_workers: Number of worker threads (defaults to CPU count)
            max_file_size: Maximum file size in bytes (defaults to 10MB)
        """
        self.rules = rules
        self.max_workers = max_workers or min(
            MAX_WORKERS_LIMIT, (os.cpu_count() or DEFAULT_CPU_COUNT) + WORKER_CPU_MULTIPLIER
        )
        self.max_file_size = max_file_size or self.MAX_FILE_SIZE

    def discover_files(self, path: Path) -> Iterator[Path]:
        """Lazily discover files to scan.

        Args:
            path: Root path to scan

        Yields:
            Paths to files that should be scanned
        """
        if path.is_file():
            if self._should_scan_file(path):
                yield path
            return

        # Get skip directories from rules
        skip_dirs = set()
        for rule in self.rules:
            skip_dirs.update(rule.skip_dirs)

        # Get file extensions from rules
        file_extensions = set()
        for rule in self.rules:
            file_extensions.update(rule.file_extensions)

        # Walk directory tree
        for item in path.rglob("*"):
            # Skip directories in skip list
            if any(skip_dir in item.parts for skip_dir in skip_dirs):
                continue

            if item.is_file() and item.suffix in file_extensions:
                # Check file size
                try:
                    if item.stat().st_size > self.max_file_size:
                        logger.debug(f"Skipping large file: {item} (> {self.max_file_size} bytes)")
                        continue
                except OSError:
                    continue

                yield item

    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if any rule should scan this file."""
        return any(rule.should_scan_file(file_path) for rule in self.rules)

    def scan(
        self,
        path: Path,
        parallel: bool = True,
        files_to_scan: list[Path] | None = None,
        cache: "ScanCache | None" = None,
    ) -> list[Finding]:
        """Scan a path and return all findings.

        Args:
            path: Path to scan (file or directory)
            parallel: Whether to use parallel scanning
            files_to_scan: Optional list of specific files to scan (for git-diff mode)
            cache: Optional cache to check for unchanged files

        Returns:
            List of all findings
        """
        findings: list[Finding] = []

        # Determine which files to scan
        files_iter: Iterator[Path] = (
            iter(files_to_scan) if files_to_scan is not None else self.discover_files(path)
        )

        if not parallel:
            # Sequential scanning
            for file_path in files_iter:
                # Skip if cache says file hasn't changed
                if cache and not cache.has_changed(file_path):
                    logger.debug(f"Skipping unchanged file: {file_path}")
                    continue

                for rule in self.rules:
                    if rule.should_scan_file(file_path):
                        try:
                            file_findings = rule.scan_file(file_path)
                            findings.extend(file_findings)

                            # Update cache with results
                            if cache:
                                cache.update(file_path, file_findings)
                        except Exception as e:
                            logger.warning(
                                f"Error scanning {file_path} with {rule.rule_id}: {e}",
                                exc_info=True,
                                extra={"file_path": str(file_path), "rule_id": rule.rule_id},
                            )
        else:
            # Parallel scanning with batching
            findings = self._scan_parallel_with_cache(files_iter, cache)

        return findings

    def _scan_parallel(self, path: Path) -> list[Finding]:
        """Scan in parallel with batched task submission (legacy method)."""
        return self._scan_parallel_with_cache(self.discover_files(path), cache=None)

    def _scan_parallel_with_cache(
        self, files_iter: Iterator[Path], cache: "ScanCache | None" = None
    ) -> list[Finding]:
        """Scan in parallel with batched task submission and cache support.

        Args:
            files_iter: Iterator of files to scan
            cache: Optional cache to check for unchanged files

        Returns:
            List of all findings
        """
        all_findings = []
        pending_tasks: list[ScanTask] = []

        # Create tasks lazily
        for file_path in files_iter:
            # Skip if cache says file hasn't changed
            if cache and not cache.has_changed(file_path):
                logger.debug(f"Skipping unchanged file (cached): {file_path}")
                # Retrieve cached findings if available
                cached_findings_dicts = cache.get_findings(file_path)
                if cached_findings_dicts:
                    # Convert dicts back to Finding objects
                    from owasp_agentic_scanner.rules.base import Finding, Severity

                    for finding_dict in cached_findings_dicts:
                        finding = Finding(
                            rule_id=finding_dict["rule_id"],
                            rule_name=finding_dict["rule_name"],
                            severity=Severity(finding_dict["severity"]),
                            file_path=finding_dict["file_path"],
                            line_number=finding_dict["line_number"],
                            line_content=finding_dict["line_content"],
                            message=finding_dict["message"],
                            recommendation=finding_dict.get("recommendation", ""),
                            owasp_category=finding_dict.get("owasp_category", ""),
                            confidence=finding_dict.get("confidence", "medium"),
                        )
                        all_findings.append(finding)
                continue

            for rule in self.rules:
                if rule.should_scan_file(file_path):
                    pending_tasks.append(ScanTask(rule, file_path))

                    # Process in batches
                    if len(pending_tasks) >= self.BATCH_SIZE:
                        batch_findings = self._process_batch(pending_tasks)
                        all_findings.extend(batch_findings)

                        # Update cache with batch results
                        if cache:
                            self._update_cache_batch(pending_tasks, batch_findings, cache)

                        pending_tasks = []

        # Process remaining tasks
        if pending_tasks:
            batch_findings = self._process_batch(pending_tasks)
            all_findings.extend(batch_findings)

            # Update cache with final batch
            if cache:
                self._update_cache_batch(pending_tasks, batch_findings, cache)

        return all_findings

    def _update_cache_batch(
        self, tasks: list[ScanTask], findings: list[Finding], cache: "ScanCache"
    ) -> None:
        """Update cache with findings from a batch of tasks.

        Uses file locking to prevent race conditions during parallel batch updates.

        Args:
            tasks: List of scan tasks in this batch
            findings: List of findings from the batch
            cache: Cache instance to update
        """
        from filelock import FileLock, Timeout  # type: ignore[import-not-found]

        from owasp_agentic_scanner.constants import CACHE_LOCK_TIMEOUT_SECONDS

        # Group findings by file
        findings_by_file: dict[Path, list[Finding]] = {}
        for finding in findings:
            file_path = Path(finding.file_path)
            if file_path not in findings_by_file:
                findings_by_file[file_path] = []
            findings_by_file[file_path].append(finding)

        # Use file locking for thread-safe batch updates
        lock_file = cache.cache_dir / ".owasp_cache_batch.lock"
        try:
            with FileLock(lock_file, timeout=CACHE_LOCK_TIMEOUT_SECONDS):
                # Update cache for each file while holding lock
                for file_path, file_findings in findings_by_file.items():
                    cache.update(file_path, file_findings)
        except Timeout:
            logger.warning(
                "Cache batch update timed out waiting for lock, skipping cache update",
                extra={"batch_size": len(tasks), "findings_count": len(findings)},
            )
        except Exception as e:
            logger.error(
                f"Error updating cache batch: {e}",
                exc_info=True,
                extra={"batch_size": len(tasks), "findings_count": len(findings)},
            )

    def _cancel_remaining_futures(
        self, future_to_task: dict["Future[tuple[Path, list[Finding]]]", ScanTask]
    ) -> None:
        """Cancel all remaining futures that haven't completed.

        Args:
            future_to_task: Dictionary mapping futures to tasks
        """
        for future in future_to_task:
            if not future.done():
                future.cancel()

    def _handle_task_result(
        self,
        future: "Future[tuple[Path, list[Finding]]]",
        future_to_task: dict["Future[tuple[Path, list[Finding]]]", ScanTask],
        findings: list[Finding],
        circuit_breaker: CircuitBreaker,
        max_findings: int,
    ) -> bool:
        """Handle the result of a completed task.

        Args:
            future: The completed future
            future_to_task: Dictionary mapping futures to tasks
            findings: List to append findings to
            circuit_breaker: Circuit breaker instance
            max_findings: Maximum findings allowed

        Returns:
            True if processing should continue, False if should stop
        """
        try:
            # Reduced timeout per file (from constants)
            _, file_findings = future.result(timeout=FILE_SCAN_TIMEOUT_SECONDS)

            # Memory limit check: prevent unbounded growth
            if len(findings) + len(file_findings) > max_findings:
                logger.warning(
                    f"Findings limit reached: {len(findings)} findings. "
                    "Stopping batch to prevent memory exhaustion."
                )
                return False

            findings.extend(file_findings)
            return True

        except TimeoutError:
            task = future_to_task[future]
            logger.warning(
                f"Task timeout (5s): {task.file_path} with {task.rule.rule_id}",
                extra={"file_path": str(task.file_path), "rule_id": task.rule.rule_id},
            )
            circuit_breaker.record_failure()
            return True

        except Exception as e:
            task = future_to_task[future]
            logger.error(
                f"Error processing {task.file_path} with {task.rule.rule_id}: {e}",
                exc_info=True,
                extra={"file_path": str(task.file_path), "rule_id": task.rule.rule_id},
            )
            circuit_breaker.record_failure()
            return True

    def _process_batch(self, tasks: list[ScanTask]) -> list[Finding]:
        """Process a batch of tasks in parallel with resource limits.

        Implements circuit breaker pattern and memory limits to prevent
        resource exhaustion during parallel scanning.
        """
        findings: list[Finding] = []
        circuit_breaker = CircuitBreaker(
            failure_threshold=CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            timeout_seconds=CIRCUIT_BREAKER_TIMEOUT_SECONDS,
        )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks in the batch
            future_to_task = {executor.submit(task.execute): task for task in tasks}

            # Collect results as they complete
            for future in as_completed(future_to_task):
                # Check circuit breaker before processing more results
                if not circuit_breaker.can_execute():
                    logger.error("Circuit breaker open, cancelling remaining tasks")
                    self._cancel_remaining_futures(future_to_task)
                    break

                # Handle task result
                should_continue = self._handle_task_result(
                    future, future_to_task, findings, circuit_breaker, MAX_FINDINGS_PER_BATCH
                )

                if not should_continue:
                    self._cancel_remaining_futures(future_to_task)
                    break

        return findings

    def scan_streaming(self, path: Path) -> Iterator[Finding]:
        """Scan and yield findings as they are discovered (streaming).

        This is useful for large codebases where you don't want to hold
        all findings in memory at once.

        Args:
            path: Path to scan

        Yields:
            Findings as they are discovered
        """
        pending_tasks: list[ScanTask] = []

        for file_path in self.discover_files(path):
            for rule in self.rules:
                if rule.should_scan_file(file_path):
                    pending_tasks.append(ScanTask(rule, file_path))

                    # Process in batches
                    if len(pending_tasks) >= self.BATCH_SIZE:
                        yield from self._process_batch(pending_tasks)
                        pending_tasks = []

        # Process remaining tasks
        if pending_tasks:
            yield from self._process_batch(pending_tasks)


class FileFilter:
    """Helper to filter files before scanning."""

    @staticmethod
    def is_binary(file_path: Path) -> bool:
        """Check if a file is binary (heuristic)."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
                # Check for null bytes
                return b"\x00" in chunk
        except OSError:
            return True

    @staticmethod
    def is_minified(file_path: Path) -> bool:
        """Check if a file is minified (heuristic for JS/CSS)."""
        if file_path.suffix not in {".js", ".css"}:
            return False

        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                first_line = f.readline()
                # Minified files often have very long first lines
                return len(first_line) > 500
        except OSError:
            return False

    @staticmethod
    def should_skip(file_path: Path) -> bool:
        """Check if file should be skipped entirely."""
        # Skip binaries
        if FileFilter.is_binary(file_path):
            return True

        # Skip minified files
        if FileFilter.is_minified(file_path):
            return True

        # Skip lockfiles
        lockfiles = {"package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock"}
        return file_path.name in lockfiles
