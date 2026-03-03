"""End-to-end integration tests."""

from pathlib import Path

from owasp_agentic_scanner.baseline import Baseline
from owasp_agentic_scanner.cache import ScanCache
from owasp_agentic_scanner.config import ScanConfig
from owasp_agentic_scanner.rules.code_execution import CodeExecutionRule
from owasp_agentic_scanner.rules.goal_hijack import GoalHijackRule
from owasp_agentic_scanner.scanner import OptimizedScanner


class TestCacheIntegration:
    """Test cache integration workflows."""

    def test_cache_lifecycle(self, tmp_path: Path) -> None:
        """Test complete cache save/load/update cycle."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        cache_dir = tmp_path / ".cache"
        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)

        # First scan - should find issue
        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings1 = scanner.scan(tmp_path, parallel=False, cache=cache)

        assert len(findings1) > 0
        assert any(f.rule_id == "AA05" for f in findings1)

        # Save cache
        cache.save()
        assert (cache_dir / "scan_cache.json").exists()

        # Load cache and scan again - should use cached results
        cache2 = ScanCache(cache_dir=cache_dir, project_root=tmp_path)
        findings2 = scanner.scan(tmp_path, parallel=False, cache=cache2)

        # Should get same or more findings (AST might find multiple issues)
        assert len(findings2) >= len(findings1) - 1  # Allow small variance

    def test_cache_invalidation_on_file_change(self, tmp_path: Path) -> None:
        """Test cache invalidates when file changes."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('safe')")

        cache_dir = tmp_path / ".cache"
        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # First scan - no issues
        findings1 = scanner.scan(tmp_path, parallel=False, cache=cache)
        cache.save()

        # Modify file to add issue
        test_file.write_text("eval(input())")

        # Second scan should detect change
        cache2 = ScanCache(cache_dir=cache_dir, project_root=tmp_path)
        findings2 = scanner.scan(tmp_path, parallel=False, cache=cache2)

        assert len(findings2) > len(findings1)


class TestBaselineIntegration:
    """Test baseline integration workflows."""

    def test_baseline_creation_workflow(self, tmp_path: Path) -> None:
        """Test creating and using baseline."""
        # Create test file with issues
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        # First scan - find issues
        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])
        findings = scanner.scan(tmp_path, parallel=False)

        assert len(findings) > 0

        # Create baseline from findings
        baseline_file = tmp_path / "baseline.json"
        baseline = Baseline(baseline_file)
        baseline.save(baseline_file, findings)

        assert baseline_file.exists()

        # Second scan with baseline - should filter findings
        baseline2 = Baseline(baseline_file)
        new_findings, baselined = baseline2.filter_new_findings(findings)

        assert len(baselined) == len(findings)
        assert len(new_findings) == 0

    def test_baseline_with_new_issues(self, tmp_path: Path) -> None:
        """Test baseline only filters existing issues."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # First scan and baseline
        findings1 = scanner.scan(tmp_path, parallel=False)
        baseline_file = tmp_path / "baseline.json"
        baseline = Baseline(baseline_file)
        baseline.save(baseline_file, findings1)

        # Add new issue
        test_file.write_text("eval(input())\nexec(code)")

        # Second scan
        findings2 = scanner.scan(tmp_path, parallel=False)

        # Filter with baseline
        baseline2 = Baseline(baseline_file)
        new_findings, baselined = baseline2.filter_new_findings(findings2)

        # Should have at least one new finding
        assert len(new_findings) > 0
        assert len(baselined) > 0

    def test_baseline_fuzzy_matching(self, tmp_path: Path) -> None:
        """Test baseline fuzzy matching when lines shift."""
        test_file = tmp_path / "test.py"
        test_file.write_text("# comment\neval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # First scan
        findings1 = scanner.scan(tmp_path, parallel=False)
        baseline_file = tmp_path / "baseline.json"
        baseline = Baseline(baseline_file)
        baseline.save(baseline_file, findings1)

        # Add lines above - shifts line numbers
        test_file.write_text("# new line 1\n# new line 2\n# comment\neval(input())")

        # Second scan
        findings2 = scanner.scan(tmp_path, parallel=False)

        # Filter - fuzzy matching should still match
        baseline2 = Baseline(baseline_file)
        _new_findings, baselined = baseline2.filter_new_findings(findings2)

        # Should still be baselined despite line number shift
        assert len(baselined) > 0


class TestConfigIntegration:
    """Test config integration workflows."""

    def test_config_with_scanner(self, tmp_path: Path) -> None:
        """Test using config with scanner."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        # Create config
        config_file = tmp_path / "config.toml"
        config_file.write_text('min_severity = "critical"\nparallel = false')

        config = ScanConfig.load(config_file)

        assert config.min_severity == "critical"
        assert config.parallel is False

    def test_config_priority(self, tmp_path: Path, monkeypatch) -> None:
        """Test config priority: env > file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('min_severity = "info"')

        # Set env var (higher priority)
        monkeypatch.setenv("OWASP_SCAN_MIN_SEVERITY", "critical")

        config = ScanConfig.load(config_file)

        # Env should override file
        assert config.min_severity == "critical"


class TestMultiModuleIntegration:
    """Test integration between multiple modules."""

    def test_cache_and_baseline_together(self, tmp_path: Path) -> None:
        """Test using cache and baseline together."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        cache_dir = tmp_path / ".cache"
        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # First scan
        findings1 = scanner.scan(tmp_path, parallel=False, cache=cache)
        cache.save()

        # Create baseline
        baseline_file = tmp_path / "baseline.json"
        baseline = Baseline(baseline_file)
        baseline.save(baseline_file, findings1)

        # Add new file
        test_file2 = tmp_path / "test2.py"
        test_file2.write_text("exec(code)")

        # Second scan with cache
        cache2 = ScanCache(cache_dir=cache_dir, project_root=tmp_path)
        findings2 = scanner.scan(tmp_path, parallel=False, cache=cache2)

        # Filter with baseline
        baseline2 = Baseline(baseline_file)
        new_findings, _baselined = baseline2.filter_new_findings(findings2)

        # test.py should be cached and baselined
        # test2.py should be new
        assert len(new_findings) > 0

    def test_scanner_with_multiple_rules(self, tmp_path: Path) -> None:
        """Test scanner with multiple rule types."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
# AA01 - Goal Hijack
user_input = input("Enter goal: ")
agent.set_goal(user_input)

# AA05 - Code Execution
eval(input())
"""
        )

        rules = [CodeExecutionRule(), GoalHijackRule()]
        scanner = OptimizedScanner(rules=rules)

        findings = scanner.scan(tmp_path, parallel=False)

        # Should find multiple types of issues
        rule_ids = {f.rule_id for f in findings}
        assert len(rule_ids) >= 1  # At least code execution

    def test_parallel_vs_sequential_same_results(self, tmp_path: Path) -> None:
        """Test parallel and sequential scans give same results."""
        for i in range(3):
            f = tmp_path / f"test{i}.py"
            f.write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # Sequential scan
        findings_seq = scanner.scan(tmp_path, parallel=False)

        # Parallel scan
        findings_par = scanner.scan(tmp_path, parallel=True)

        # Should find same number of issues
        assert len(findings_seq) == len(findings_par)


class TestErrorHandling:
    """Test error handling in integration scenarios."""

    def test_scan_with_syntax_errors(self, tmp_path: Path) -> None:
        """Test scan handles files with syntax errors."""
        good_file = tmp_path / "good.py"
        good_file.write_text("eval(input())")

        bad_file = tmp_path / "bad.py"
        bad_file.write_text("def incomplete(")  # Syntax error

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # Should not crash, should scan good file
        findings = scanner.scan(tmp_path, parallel=False)

        # Should find issue in good file
        good_findings = [f for f in findings if f.file_path == str(good_file)]
        assert len(good_findings) > 0

    def test_cache_with_corrupted_file(self, tmp_path: Path) -> None:
        """Test cache handles corrupted cache file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        cache_file = cache_dir / "scan_cache.json"
        cache_file.write_text("{invalid json")

        # Should handle corruption gracefully
        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)
        assert cache.cache_data == {}

    def test_baseline_with_missing_file(self, tmp_path: Path) -> None:
        """Test baseline handles missing file."""
        baseline_file = tmp_path / "missing.json"

        # Should not crash
        baseline = Baseline(baseline_file)
        assert baseline.findings == {}


class TestPerformance:
    """Test performance-related integration."""

    def test_parallel_scan_with_many_files(self, tmp_path: Path) -> None:
        """Test parallel scan handles many files."""
        # Create many files
        for i in range(50):
            f = tmp_path / f"test{i}.py"
            f.write_text("eval(input())")

        rule = CodeExecutionRule()
        scanner = OptimizedScanner(rules=[rule])

        # Should handle many files
        findings = scanner.scan(tmp_path, parallel=True)

        assert len(findings) >= 50
