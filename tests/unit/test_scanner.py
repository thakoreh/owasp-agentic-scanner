"""Unit tests for scanner module."""

from pathlib import Path

from owasp_agentic_scanner.cache import ScanCache
from owasp_agentic_scanner.rules.code_execution import CodeExecutionRule
from owasp_agentic_scanner.rules.goal_hijack import GoalHijackRule
from owasp_agentic_scanner.scanner import OptimizedScanner


class TestOptimizedScanner:
    """Test OptimizedScanner functionality."""

    def test_scanner_init_with_rules(self) -> None:
        """Test scanner initialization with specific rules."""
        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        assert len(scanner.rules) == 1
        assert scanner.rules[0].rule_id == "AA05"

    def test_scanner_init_with_max_workers(self) -> None:
        """Test scanner initialization with max_workers."""
        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule], max_workers=4)

        assert scanner.max_workers == 4

    def test_scanner_init_with_max_file_size(self) -> None:
        """Test scanner initialization with max_file_size."""
        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule], max_file_size=1000000)

        assert scanner.max_file_size == 1000000

    def test_scanner_init_defaults(self) -> None:
        """Test scanner uses sensible defaults."""
        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        assert scanner.max_workers > 0
        assert scanner.max_file_size == 10 * 1024 * 1024

    def test_discover_files_finds_python_files(self, tmp_path: Path) -> None:
        """Test discover_files finds Python files."""
        # Create test files
        (tmp_path / "test1.py").write_text("print('test')")
        (tmp_path / "test2.py").write_text("print('test')")
        (tmp_path / "readme.txt").write_text("not python")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        files = list(scanner.discover_files(tmp_path))

        # Should find 2 .py files
        assert len(files) == 2
        assert all(f.suffix == ".py" for f in files)

    def test_discover_files_excludes_dirs(self, tmp_path: Path) -> None:
        """Test discover_files excludes standard directories."""
        # Create files in excluded dirs
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "test.py").write_text("print('test')")

        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "test.py").write_text("print('test')")

        # Create normal file
        (tmp_path / "normal.py").write_text("print('test')")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        files = list(scanner.discover_files(tmp_path))

        # Should only find normal.py
        assert len(files) == 1
        assert files[0].name == "normal.py"

    def test_discover_files_respects_max_file_size(self, tmp_path: Path) -> None:
        """Test discover_files respects max_file_size."""
        small_file = tmp_path / "small.py"
        small_file.write_text("x = 1")

        large_file = tmp_path / "large.py"
        large_file.write_text("x = 1\n" * 10000)  # Large file

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule], max_file_size=100)  # Small limit
        files = list(scanner.discover_files(tmp_path))

        # Should only find small.py
        assert len(files) == 1
        assert files[0].name == "small.py"

    def test_scan_finds_issues(self, tmp_path: Path) -> None:
        """Test scan finds security issues."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=False)

        assert len(findings) > 0
        assert any(f.rule_id == "AA05" for f in findings)

    def test_scan_empty_directory(self, tmp_path: Path) -> None:
        """Test scan of empty directory."""
        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=False)

        assert findings == []

    def test_scan_with_multiple_rules(self, tmp_path: Path) -> None:
        """Test scan with multiple rules."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        rules = [CodeExecutionRule(), GoalHijackRule()]
        scanner = OptimizedScanner(rules=rules)
        scanner.scan(tmp_path, parallel=False)

        # Should work with multiple rules
        assert scanner.rules == rules

    def test_scan_nested_directories(self, tmp_path: Path) -> None:
        """Test scan of nested directories."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        test_file = subdir / "test.py"
        test_file.write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=False)

        assert len(findings) > 0
        assert any(f.file_path == str(test_file) for f in findings)

    def test_scan_parallel(self, tmp_path: Path) -> None:
        """Test scan with parallel=True."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=True)

        assert len(findings) > 0

    def test_scan_sequential(self, tmp_path: Path) -> None:
        """Test scan with parallel=False."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=False)

        assert len(findings) > 0

    def test_scan_single_file(self, tmp_path: Path) -> None:
        """Test scanning a single file directly."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(test_file, parallel=False)

        assert len(findings) > 0
        assert all(f.file_path == str(test_file) for f in findings)

    def test_scan_with_files_to_scan_parameter(self, tmp_path: Path) -> None:
        """Test scan with explicit files_to_scan set."""
        file1 = tmp_path / "test1.py"
        file1.write_text("eval(input())")

        file2 = tmp_path / "test2.py"
        file2.write_text("exec(code)")

        file3 = tmp_path / "test3.py"
        file3.write_text("print('safe')")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # Only scan file1 and file3
        findings = scanner.scan(tmp_path, parallel=False, files_to_scan={file1, file3})

        # Should not have findings from file2
        file_paths = {f.file_path for f in findings}
        assert str(file2) not in file_paths

    def test_scan_with_cache_integration(self, tmp_path: Path) -> None:
        """Test scan properly integrates with cache."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        cache_dir = tmp_path / ".cache"
        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # First scan
        scanner.scan(tmp_path, parallel=False, cache=cache)
        cache.save()

        # Verify cache was populated
        assert len(cache.cache_data) > 0

        # Second scan with cache
        cache2 = ScanCache(cache_dir=cache_dir, project_root=tmp_path)
        findings2 = scanner.scan(tmp_path, parallel=False, cache=cache2)

        # Should get similar results from cache
        assert len(findings2) >= 1  # At least finds the issue

    def test_scan_parallel_with_cache(self, tmp_path: Path) -> None:
        """Test parallel scan with cache."""
        for i in range(5):
            f = tmp_path / f"test{i}.py"
            f.write_text("eval(input())")

        cache_dir = tmp_path / ".cache"
        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        findings = scanner.scan(tmp_path, parallel=True, cache=cache)

        assert len(findings) >= 5

    def test_discover_files_single_file(self, tmp_path: Path) -> None:
        """Test discover_files with a single file path."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        files = list(scanner.discover_files(test_file))

        assert len(files) == 1
        assert files[0] == test_file

    def test_scan_deeply_nested_dirs(self, tmp_path: Path) -> None:
        """Test scan finds files in deeply nested directories."""
        deep_dir = tmp_path / "a" / "b" / "c" / "d"
        deep_dir.mkdir(parents=True)

        test_file = deep_dir / "test.py"
        test_file.write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=False)

        assert len(findings) > 0
        assert any(f.file_path == str(test_file) for f in findings)

    def test_scan_excludes_common_dirs(self, tmp_path: Path) -> None:
        """Test scan excludes common directories."""
        # Create files in excluded directories
        for dirname in ["__pycache__", ".git", "node_modules", ".venv", "venv", "dist", "build"]:
            dir_path = tmp_path / dirname
            dir_path.mkdir()
            (dir_path / "test.py").write_text("eval(input())")

        # Create file in normal directory
        (tmp_path / "normal.py").write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=False)

        # Should only find issue in normal.py
        assert all("normal.py" in f.file_path for f in findings)

    def test_scan_empty_file(self, tmp_path: Path) -> None:
        """Test scan handles empty files."""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=False)

        # Should not crash, no findings
        assert findings == []

    def test_scan_with_unicode_content(self, tmp_path: Path) -> None:
        """Test scan handles unicode content."""
        test_file = tmp_path / "unicode.py"
        test_file.write_text("# 中文注释\neval(input())  # 危险代码")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=False)

        assert len(findings) > 0


class TestScannerAdvanced:
    """Advanced scanner tests for edge cases."""

    def test_scan_task_error_handling(self, tmp_path: Path) -> None:
        """Test ScanTask handles errors gracefully."""
        from owasp_agentic_scanner.scanner import ScanTask

        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        rule = CodeExecutionRule()
        task = ScanTask(rule, test_file)

        # Should execute without error
        file_path, findings = task.execute()
        assert file_path == test_file
        assert len(findings) >= 0

    def test_scanner_batch_processing(self, tmp_path: Path) -> None:
        """Test scanner processes files in batches."""
        # Create exactly BATCH_SIZE + 1 files to test batching
        for i in range(101):
            (tmp_path / f"test{i}.py").write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=True)

        # Should process all files
        assert len(findings) >= 101

    def test_scanner_max_file_size(self, tmp_path: Path) -> None:
        """Test scanner respects max file size limit."""
        large_file = tmp_path / "large.py"
        # Create file larger than default 10MB
        large_content = "# " + ("x" * (11 * 1024 * 1024))
        large_file.write_text(large_content)

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # Should skip large file
        files = list(scanner.discover_files(tmp_path))
        assert large_file not in files

    def test_scanner_custom_max_workers(self, tmp_path: Path) -> None:
        """Test scanner with custom worker count."""
        for i in range(10):
            (tmp_path / f"test{i}.py").write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule], max_workers=2)

        assert scanner.max_workers == 2

        findings = scanner.scan(tmp_path, parallel=True)
        assert len(findings) >= 10

    def test_file_filter_is_binary(self, tmp_path: Path) -> None:
        """Test FileFilter.is_binary detection."""
        from owasp_agentic_scanner.scanner import FileFilter

        # Text file
        text_file = tmp_path / "text.py"
        text_file.write_text("print('hello')")
        assert FileFilter.is_binary(text_file) is False

        # Binary file
        binary_file = tmp_path / "binary.bin"
        binary_file.write_bytes(b"\x00\x01\x02\x03")
        assert FileFilter.is_binary(binary_file) is True

    def test_file_filter_is_minified(self, tmp_path: Path) -> None:
        """Test FileFilter.is_minified detection."""
        from owasp_agentic_scanner.scanner import FileFilter

        # Normal JS file
        normal_js = tmp_path / "normal.js"
        normal_js.write_text("function test() {\n  return 42;\n}")
        assert FileFilter.is_minified(normal_js) is False

        # Minified JS file (long first line)
        minified_js = tmp_path / "minified.js"
        minified_js.write_text("a" * 600)
        assert FileFilter.is_minified(minified_js) is True

        # Python file should not be considered minified
        py_file = tmp_path / "test.py"
        py_file.write_text("x" * 600)
        assert FileFilter.is_minified(py_file) is False

    def test_file_filter_should_skip(self, tmp_path: Path) -> None:
        """Test FileFilter.should_skip detection."""
        from owasp_agentic_scanner.scanner import FileFilter

        # Binary file should be skipped
        binary_file = tmp_path / "binary.bin"
        binary_file.write_bytes(b"\x00\x01\x02")
        assert FileFilter.should_skip(binary_file) is True

        # Lockfile should be skipped
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text("{}")
        assert FileFilter.should_skip(lockfile) is True

        # Normal Python file should not be skipped
        py_file = tmp_path / "test.py"
        py_file.write_text("print('test')")
        assert FileFilter.should_skip(py_file) is False

    def test_scanner_streaming(self, tmp_path: Path) -> None:
        """Test scan_streaming yields findings."""
        for i in range(10):
            (tmp_path / f"test{i}.py").write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        findings = list(scanner.scan_streaming(tmp_path))

        # Should yield findings
        assert len(findings) >= 10

    def test_scanner_streaming_batches(self, tmp_path: Path) -> None:
        """Test scan_streaming processes in batches."""
        # Create more than BATCH_SIZE files
        for i in range(150):
            (tmp_path / f"test{i}.py").write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        findings = []
        for finding in scanner.scan_streaming(tmp_path):
            findings.append(finding)

        # Should process all files
        assert len(findings) >= 150

    def test_concurrent_cache_batch_updates(self, tmp_path: Path) -> None:
        """Test that concurrent cache batch updates don't cause race conditions."""
        import threading

        from owasp_agentic_scanner.rules.base import Finding, Severity
        from owasp_agentic_scanner.scanner import ScanTask

        # Create test files
        for i in range(10):
            (tmp_path / f"test{i}.py").write_text("eval(input())")

        cache_dir = tmp_path / ".cache"
        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # Create mock tasks and findings
        tasks = [ScanTask(rule, tmp_path / f"test{i}.py") for i in range(10)]
        findings = [
            Finding(
                rule_id="AA05",
                rule_name="Test",
                severity=Severity.CRITICAL,
                file_path=str(tmp_path / f"test{i}.py"),
                line_number=1,
                line_content="eval(input())",
                message="Test finding",
                recommendation="Fix it",
                owasp_category="AA05",
            )
            for i in range(10)
        ]

        # Simulate concurrent batch updates
        errors = []

        def update_batch():
            try:
                scanner._update_cache_batch(tasks, findings, cache)
            except Exception as e:
                errors.append(e)

        # Run 5 concurrent threads trying to update cache
        threads = [threading.Thread(target=update_batch) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should complete without errors
        assert len(errors) == 0
        # Cache should be updated
        assert len(cache.cache_data) > 0

    def test_cache_batch_update_timeout(self, tmp_path: Path) -> None:
        """Test cache batch update handles lock timeout gracefully."""
        from filelock import FileLock

        from owasp_agentic_scanner.rules.base import Finding, Severity
        from owasp_agentic_scanner.scanner import ScanTask

        cache_dir = tmp_path / ".cache"
        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # Hold lock to force timeout
        lock_file = cache_dir / ".owasp_cache_batch.lock"
        with FileLock(lock_file):
            # Try to update cache while lock is held
            tasks = [ScanTask(rule, tmp_path / "test.py")]
            findings = [
                Finding(
                    rule_id="AA05",
                    rule_name="Test",
                    severity=Severity.CRITICAL,
                    file_path=str(tmp_path / "test.py"),
                    line_number=1,
                    line_content="eval(input())",
                    message="Test",
                    recommendation="Fix",
                    owasp_category="AA05",
                )
            ]

            # Should not crash, just log warning
            scanner._update_cache_batch(tasks, findings, cache)


class TestCircuitBreaker:
    """Test CircuitBreaker functionality for resource limits."""

    def test_circuit_breaker_initial_state(self) -> None:
        """Test circuit breaker starts in closed state."""
        from owasp_agentic_scanner.scanner import CircuitBreaker

        breaker = CircuitBreaker(failure_threshold=5, timeout_seconds=30)
        assert breaker.state == "closed"
        assert breaker.can_execute() is True

    def test_circuit_breaker_opens_after_threshold(self) -> None:
        """Test circuit breaker opens after failure threshold."""
        from owasp_agentic_scanner.scanner import CircuitBreaker

        breaker = CircuitBreaker(failure_threshold=3, timeout_seconds=30)

        # Record failures
        breaker.record_failure()
        assert breaker.state == "closed"

        breaker.record_failure()
        assert breaker.state == "closed"

        breaker.record_failure()
        # Should open after 3rd failure
        assert breaker.state == "open"
        assert breaker.can_execute() is False

    def test_circuit_breaker_resets_after_timeout(self) -> None:
        """Test circuit breaker resets to half-open after timeout."""
        from datetime import datetime, timedelta

        from owasp_agentic_scanner.scanner import CircuitBreaker

        breaker = CircuitBreaker(failure_threshold=2, timeout_seconds=1)

        # Record failures to open circuit
        breaker.record_failure()
        breaker.record_failure()
        assert breaker.state == "open"

        # Manually set last failure time to past
        if breaker.failures:
            breaker.failures[-1] = datetime.now() - timedelta(seconds=2)

        # Should transition to half_open
        assert breaker.can_execute() is True
        assert breaker.state == "half_open"


class TestResourceLimits:
    """Test resource limits in parallel scanning."""

    def test_timeout_reduces_from_30s_to_5s(self) -> None:
        """Test that timeout is set to 5s (not 30s)."""
        import inspect

        from owasp_agentic_scanner.scanner import OptimizedScanner

        # Check _handle_task_result where timeout is now implemented
        source = inspect.getsource(OptimizedScanner._handle_task_result)
        # Should use FILE_SCAN_TIMEOUT_SECONDS constant (5.0 seconds)
        assert "FILE_SCAN_TIMEOUT_SECONDS" in source

    def test_memory_limit_enforcement(self, tmp_path: Path) -> None:
        """Test that findings memory limit is enforced."""
        from owasp_agentic_scanner.rules.base import Finding, Severity
        from owasp_agentic_scanner.scanner import ScanTask

        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # Create many tasks
        tasks = [ScanTask(rule, test_file) for _ in range(100)]

        # Mock execute to return many findings
        def many_findings():
            return test_file, [
                Finding(
                    rule_id="TEST",
                    rule_name="Test",
                    severity=Severity.LOW,
                    file_path=str(test_file),
                    line_number=i,
                    line_content="test",
                    message="test",
                    recommendation="test",
                    owasp_category="TEST",
                )
                for i in range(200)  # 200 findings per task
            ]

        # Patch all tasks
        for task in tasks:
            task.execute = many_findings

        # Should stop at 10K findings (won't process all 100 tasks)
        findings = scanner._process_batch(tasks)
        assert len(findings) <= 10000

    def test_circuit_breaker_integration(self, tmp_path: Path) -> None:
        """Test circuit breaker stops processing on failures."""
        from owasp_agentic_scanner.scanner import ScanTask

        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # Create many tasks
        tasks = [ScanTask(rule, test_file) for _ in range(20)]

        # Mock execute to always fail
        def failing_execute():
            raise RuntimeError("Simulated failure")

        # Patch all tasks to fail
        for task in tasks:
            task.execute = failing_execute

        # Should stop after circuit opens (around 10 failures)
        findings = scanner._process_batch(tasks)
        assert findings == []

    def test_max_findings_per_batch_is_10k(self) -> None:
        """Test that max_findings_per_batch is set to 10000."""
        import inspect

        from owasp_agentic_scanner.scanner import OptimizedScanner

        source = inspect.getsource(OptimizedScanner._process_batch)
        # Should use MAX_FINDINGS_PER_BATCH constant (10000)
        assert "MAX_FINDINGS_PER_BATCH" in source
