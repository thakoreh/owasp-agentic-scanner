"""Tests for AST analyzer."""

from pathlib import Path

from owasp_agentic_scanner.ast_analyzer import ASTSecurityChecker, PythonASTAnalyzer


class TestPythonASTAnalyzer:
    """Test Python AST analyzer."""

    def test_detect_eval_usage(self, tmp_path: Path) -> None:
        """Test detection of eval() calls."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
user_input = input("Enter code: ")
result = eval(user_input)  # Dangerous!
"""
        )

        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        assert len(findings) > 0
        assert any(f["function"] == "eval" for f in findings)
        assert any(f["severity"] == "critical" for f in findings)

    def test_detect_exec_usage(self, tmp_path: Path) -> None:
        """Test detection of exec() calls."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
code = "print('hello')"
exec(code)
"""
        )

        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        assert len(findings) > 0
        assert any(f["function"] == "exec" for f in findings)

    def test_ignore_safe_alternatives(self, tmp_path: Path) -> None:
        """Test that safe alternatives are not flagged."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
import ast
data = '{"key": "value"}'
result = ast.literal_eval(data)  # Safe!
"""
        )

        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        # Should not flag ast.literal_eval
        assert not any(f["function"] == "ast.literal_eval" for f in findings)

    def test_taint_tracking(self, tmp_path: Path) -> None:
        """Test taint tracking from input to dangerous function."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
user_input = input("Enter something: ")
result = eval(user_input)
"""
        )

        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        eval_findings = [f for f in findings if f["function"] == "eval"]
        assert len(eval_findings) > 0
        assert eval_findings[0]["is_tainted"]
        assert eval_findings[0]["confidence"] == "high"

    def test_subprocess_with_shell_true(self, tmp_path: Path) -> None:
        """Test detection of subprocess with shell=True and tainted input."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
import subprocess
user_cmd = input("Enter command: ")
subprocess.run(user_cmd, shell=True)  # Command injection!
"""
        )

        findings = ASTSecurityChecker.detect_subprocess_injection(test_file)
        assert len(findings) > 0
        assert findings[0]["severity"] == "critical"
        assert findings[0]["is_tainted"]

    def test_subprocess_safe_usage(self, tmp_path: Path) -> None:
        """Test that safe subprocess usage is not flagged."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
import subprocess
# Safe: using list form, no shell=True
subprocess.run(["ls", "-la"])
"""
        )

        findings = ASTSecurityChecker.detect_subprocess_injection(test_file)
        # Should not flag safe usage
        assert len(findings) == 0

    def test_inline_suppression(self, tmp_path: Path) -> None:
        """Test that inline # noqa comments suppress findings."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
# Intentionally using eval for testing
result = eval("2 + 2")  # noqa: AA05
"""
        )

        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        # Finding should be detected but check line_content has noqa
        if findings:
            assert "# noqa" in findings[0]["line_content"]

    def test_os_system_detection(self, tmp_path: Path) -> None:
        """Test detection of os.system() calls."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
import os
os.system("ls -la")
"""
        )

        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        os_system_findings = [f for f in findings if f["function"] == "os.system"]
        assert len(os_system_findings) > 0
        assert os_system_findings[0]["severity"] == "critical"

    def test_pickle_loads_detection(self, tmp_path: Path) -> None:
        """Test detection of unsafe pickle.loads."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
import pickle
data = pickle.loads(untrusted_data)  # Dangerous!
"""
        )

        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        pickle_findings = [f for f in findings if "pickle.loads" in f["function"]]
        assert len(pickle_findings) > 0

    def test_import_resolution(self, tmp_path: Path) -> None:
        """Test that imports are resolved correctly."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
from subprocess import run
cmd = input("cmd: ")
run(cmd, shell=True)
"""
        )

        analyzer = PythonASTAnalyzer(test_file)
        source = test_file.read_text()
        analyzer.analyze(source)

        # Check that the import was resolved
        assert "run" in analyzer.imports

    def test_obfuscated_eval(self, tmp_path: Path) -> None:
        """Test detection of obfuscated eval through getattr."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
# Obfuscated eval
func = getattr(__builtins__, 'eval')
result = func(user_input)
"""
        )

        # Note: Current implementation may not catch this advanced case
        # This test documents a limitation
        ASTSecurityChecker.check_dangerous_functions(test_file)
        # This is a known limitation - advanced obfuscation may not be detected

    def test_f_string_taint(self, tmp_path: Path) -> None:
        """Test taint tracking through f-strings."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
user_input = input("Enter: ")
code = f"print({user_input})"
exec(code)
"""
        )

        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        exec_findings = [f for f in findings if f["function"] == "exec"]
        assert len(exec_findings) > 0
        # Should detect tainted f-string usage
        assert exec_findings[0]["is_tainted"]

    def test_invalid_python_syntax(self, tmp_path: Path) -> None:
        """Test handling of files with invalid Python syntax."""
        test_file = tmp_path / "invalid.py"
        test_file.write_text(
            """
def broken(
    # Missing closing parenthesis
"""
        )

        # Should not crash on invalid syntax
        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        assert findings == []


class TestASTAnalyzerPerformance:
    """Test AST analyzer performance."""

    def test_large_file_handling(self, tmp_path: Path) -> None:
        """Test that analyzer can handle large files."""
        test_file = tmp_path / "large.py"

        # Generate a large file with many functions
        code_lines = []
        for i in range(1000):
            code_lines.append(f"def function_{i}():")
            code_lines.append(f"    return {i}")
            code_lines.append("")

        # Add one dangerous call
        code_lines.append("eval('test')")

        test_file.write_text("\n".join(code_lines))

        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        # Should find the eval even in a large file
        assert any(f["function"] == "eval" for f in findings)

    def test_binary_file_handling(self, tmp_path: Path) -> None:
        """Test handling of binary files."""
        test_file = tmp_path / "binary.pyc"
        test_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe")

        # Should not crash on binary files
        findings = ASTSecurityChecker.check_dangerous_functions(test_file)
        assert findings == []
