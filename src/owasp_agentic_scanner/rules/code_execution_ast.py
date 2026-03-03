"""AA05: Unexpected Code Execution detection rule with AST analysis."""

import ast
from pathlib import Path

from owasp_agentic_scanner.ast_analyzer import ASTSecurityChecker
from owasp_agentic_scanner.rules.base import DetectionPattern, Finding, Severity
from owasp_agentic_scanner.rules.base_ast import HybridRule
from owasp_agentic_scanner.rules.code_execution import CodeExecutionRule


class CodeExecutionASTRule(HybridRule):
    """Detect patterns that could lead to unexpected code execution.

    This enhanced version uses AST analysis for Python files to provide:
    - Context-aware detection (excludes test files, comments, safe usage)
    - Taint tracking (detects when user input flows to dangerous functions)
    - Lower false positives (understands ast.literal_eval vs eval)
    - Detection of obfuscated calls (getattr(__builtins__, 'eval'))

    Falls back to pattern matching for JavaScript/TypeScript files.
    """

    rule_id = "AA05"
    rule_name = "Unexpected Code Execution (AST)"
    owasp_category = "AA05: Unexpected Code Execution"
    description = "Detects code execution vulnerabilities with context awareness"

    def __init__(self) -> None:
        """Initialize the rule."""
        # Initialize pattern rule BEFORE parent __init__ (which calls _get_patterns)
        self._pattern_rule = CodeExecutionRule()
        super().__init__()

    def _get_patterns(self) -> list[DetectionPattern]:
        """Get patterns for non-Python files."""
        if hasattr(self, "_pattern_rule"):
            return self._pattern_rule._get_patterns()
        return []

    def _scan_python_file(self, file_path: Path) -> list[Finding]:
        """Scan Python file using AST analysis."""
        findings: list[Finding] = []

        # Skip test files (different severity/context)
        if self._is_test_file(file_path):
            return findings

        # Use AST security checker
        dangerous_funcs = ASTSecurityChecker.check_dangerous_functions(file_path)
        subprocess_issues = ASTSecurityChecker.detect_subprocess_injection(file_path)

        # Process eval/exec findings
        for func_finding in dangerous_funcs:
            if func_finding["function"] in ("eval", "exec"):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.CRITICAL,
                        file_path=str(file_path),
                        line_number=func_finding["line_number"],
                        line_content=func_finding["line_content"],
                        message=f"{func_finding['function']}() function usage detected"
                        + (" with tainted input" if func_finding["is_tainted"] else ""),
                        recommendation=(
                            f"Never use {func_finding['function']}() with untrusted input. "
                            "Use ast.literal_eval() for safe data evaluation, or redesign to avoid dynamic code execution."
                        ),
                        owasp_category=self.owasp_category,
                        confidence=func_finding["confidence"],
                    )
                )

            elif func_finding["function"] == "compile":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.HIGH,
                        file_path=str(file_path),
                        line_number=func_finding["line_number"],
                        line_content=func_finding["line_content"],
                        message="Dynamic code compilation detected",
                        recommendation="Avoid compile() with untrusted input. Use static code patterns instead.",
                        owasp_category=self.owasp_category,
                        confidence=func_finding["confidence"],
                    )
                )

            elif func_finding["function"].startswith("subprocess."):
                # Basic subprocess detection
                if func_finding["is_tainted"]:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=Severity.HIGH,
                            file_path=str(file_path),
                            line_number=func_finding["line_number"],
                            line_content=func_finding["line_content"],
                            message="Subprocess call with tainted input detected",
                            recommendation="Use subprocess with explicit argument lists (list form). Never use shell=True with user input. Validate and sanitize all inputs.",
                            owasp_category=self.owasp_category,
                            confidence="high",
                        )
                    )

            elif func_finding["function"] == "os.system":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.CRITICAL,
                        file_path=str(file_path),
                        line_number=func_finding["line_number"],
                        line_content=func_finding["line_content"],
                        message="os.system() usage detected - high command injection risk",
                        recommendation="Replace os.system() with subprocess.run() using argument lists. Never interpolate user input into shell commands.",
                        owasp_category=self.owasp_category,
                        confidence="high",
                    )
                )

            elif func_finding["function"] in ("pickle.loads", "marshal.loads", "yaml.load"):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.HIGH,
                        file_path=str(file_path),
                        line_number=func_finding["line_number"],
                        line_content=func_finding["line_content"],
                        message=f"Unsafe deserialization: {func_finding['function']}()",
                        recommendation=(
                            "Use safe alternatives: yaml.safe_load() for YAML, "
                            "json.loads() for JSON. Never deserialize untrusted data with pickle/marshal."
                        ),
                        owasp_category=self.owasp_category,
                        confidence="high",
                    )
                )

        # Process subprocess injection findings (shell=True with tainted input)
        for issue in subprocess_issues:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    file_path=str(file_path),
                    line_number=issue["line_number"],
                    line_content=issue["line_content"],
                    message="Command injection vulnerability: subprocess with shell=True and tainted input",
                    recommendation="CRITICAL: Never use shell=True with user input. Use subprocess.run() with a list of arguments instead.",
                    owasp_category=self.owasp_category,
                    confidence="high",
                )
            )

        # Detect LLM code execution patterns
        findings.extend(self._detect_llm_code_execution(file_path))

        return findings

    def _detect_llm_code_execution(self, file_path: Path) -> list[Finding]:
        """Detect patterns where LLM-generated code is executed."""
        findings: list[Finding] = []

        try:
            source = file_path.read_text(encoding="utf-8", errors="strict")
            tree = ast.parse(source, filename=str(file_path))
            lines = source.splitlines()
        except (SyntaxError, OSError, UnicodeDecodeError):
            return findings

        # Look for patterns like: exec(llm_response) or eval(agent.generate_code())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)

                if func_name in ("eval", "exec"):
                    # Check if argument looks like LLM output
                    for arg in node.args:
                        if self._is_llm_output(arg):
                            line_num = node.lineno
                            line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    rule_name=self.rule_name,
                                    severity=Severity.CRITICAL,
                                    file_path=str(file_path),
                                    line_number=line_num,
                                    line_content=line_content,
                                    message="LLM-generated code execution detected - CRITICAL RISK",
                                    recommendation="NEVER execute LLM-generated code directly. Implement: 1) Human review workflow, 2) Sandboxed execution environment, 3) Strict capability limits, 4) Code signing/verification.",
                                    owasp_category=self.owasp_category,
                                    confidence="high",
                                )
                            )

        return findings

    def _get_func_name(self, node: ast.AST) -> str:
        """Extract function name from call node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts: list[str] = []
            current: ast.expr = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            return ".".join(parts)
        return ""

    def _is_llm_output(self, node: ast.AST) -> bool:
        """Check if a node looks like LLM/agent output."""
        # Check for variable names containing LLM/agent keywords
        llm_keywords = {
            "llm",
            "agent",
            "response",
            "completion",
            "generated",
            "output",
            "code",
            "gpt",
            "claude",
            "openai",
        }

        if isinstance(node, ast.Name):
            name_lower = node.id.lower()
            return any(keyword in name_lower for keyword in llm_keywords)
        elif isinstance(node, ast.Attribute):
            attr_lower = node.attr.lower()
            return any(keyword in attr_lower for keyword in llm_keywords)
        elif isinstance(node, ast.Call):
            func_name = self._get_func_name(node.func).lower()
            return any(keyword in func_name for keyword in llm_keywords)

        return False

    def _is_test_file(self, file_path: Path) -> bool:
        """Check if this is a test file (apply different rules)."""
        path_str = str(file_path).lower()
        return (
            "test_" in file_path.name
            or "_test.py" in file_path.name
            or "/tests/" in path_str
            or "/test/" in path_str
        )
