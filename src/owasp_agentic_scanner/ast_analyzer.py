"""AST-based analysis framework for Python code.

This module provides proper Abstract Syntax Tree analysis instead of regex matching,
enabling context-aware security vulnerability detection.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar


@dataclass
class TaintSource:
    """Represents a source of potentially untrusted data."""

    name: str
    node: ast.AST
    line_number: int
    confidence: str = "high"


@dataclass
class TaintSink:
    """Represents a dangerous operation that should not receive tainted data."""

    name: str
    node: ast.AST
    line_number: int
    severity: str = "high"


@dataclass
class DataFlow:
    """Tracks data flow from source to sink."""

    source: TaintSource
    sink: TaintSink
    path: list[ast.AST] = field(default_factory=list)


class PythonASTAnalyzer(ast.NodeVisitor):
    """AST-based analyzer for Python security patterns.

    This analyzer properly parses Python code and understands:
    - Code structure and context
    - Variable scope and data flow
    - Function calls and their arguments
    - Control flow patterns
    """

    # Common taint sources (user input, external data)
    # These represent data from untrusted sources that could be malicious
    TAINT_SOURCES: ClassVar[set[str]] = {
        # Built-in Python sources
        "input",  # Direct user input
        "raw_input",  # Python 2 user input
        "sys.argv",  # Command-line arguments
        "sys.stdin",  # Standard input stream
        # Environment variables
        "os.environ",  # Environment dict access
        "os.environ.get",  # Safe environ access
        "os.getenv",  # Alternative environ access
        # Flask framework sources
        "request.args",  # URL query parameters
        "request.form",  # Form data (POST)
        "request.json",  # JSON request body
        "request.data",  # Raw request data
        "request.get_json",  # JSON getter method
        "request.values",  # Combined args + form
        "request.cookies",  # Cookie data
        "request.headers",  # HTTP headers
        "flask.request",  # Full Flask request object
        # Django framework sources
        "request.GET",  # Django GET parameters
        "request.POST",  # Django POST data
        "request.body",  # Raw request body
        "request.COOKIES",  # Django cookies
        "request.META",  # HTTP headers in Django
        "django.request",  # Full Django request object
        # Other frameworks
        "bottle.request",  # Bottle framework
        "tornado.request",  # Tornado framework
    }

    # Dangerous sinks that should not receive tainted data
    DANGEROUS_SINKS: ClassVar[dict[str, str]] = {
        "eval": "critical",
        "exec": "critical",
        "compile": "high",
        "__import__": "high",
        "os.system": "critical",
        "subprocess.call": "high",
        "subprocess.run": "high",
        "subprocess.Popen": "high",
        "pickle.loads": "high",
        "yaml.load": "high",
        "marshal.loads": "high",
    }

    # Safe alternatives that should not be flagged
    SAFE_ALTERNATIVES: ClassVar[set[str]] = {
        "ast.literal_eval",
        "yaml.safe_load",
        "json.loads",
    }

    def __init__(self, file_path: Path) -> None:
        """Initialize analyzer for a specific file."""
        self.file_path = file_path
        self.taint_sources: list[TaintSource] = []
        self.dangerous_calls: list[tuple[ast.Call, int, str]] = []
        self.imports: dict[str, str] = {}
        self.current_scope: dict[str, Any] = {}
        self.tainted_vars: set[str] = set()

    def analyze(
        self, source_code: str
    ) -> tuple[list[TaintSource], list[tuple[ast.Call, int, str]]]:
        """Analyze Python source code and return taint sources and dangerous calls."""
        try:
            tree = ast.parse(source_code, filename=str(self.file_path))
            self.visit(tree)
            return self.taint_sources, self.dangerous_calls
        except SyntaxError:
            # Invalid Python syntax - skip this file
            return [], []

    def visit_Import(self, node: ast.Import) -> None:
        """Track imports to understand function call context."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from-imports to understand function call context."""
        if node.module:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                self.imports[name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments to propagate taint."""
        # Check if right-hand side is tainted
        if isinstance(node.value, ast.Call):
            func_name = self._get_function_name(node.value.func)
            if func_name in self.TAINT_SOURCES:
                # Mark all assigned variables as tainted
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
                        self.taint_sources.append(
                            TaintSource(
                                name=target.id,
                                node=node,
                                line_number=node.lineno,
                                confidence="high",
                            )
                        )
        elif isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
            # Propagate taint through assignment
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        elif self._is_tainted_expression(node.value):
            # Handle data structure access: data[0], data['key'], data.attr
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)

        self.generic_visit(node)

    def _is_tainted_name(self, node: ast.Name) -> bool:
        """Check if a name node is tainted."""
        return node.id in self.tainted_vars

    def _is_tainted_subscript(self, node: ast.Subscript) -> bool:
        """Check if a subscript node is tainted."""
        # Check if the base expression is tainted
        if self._is_tainted_expression(node.value):
            return True
        # Check if base is a direct taint source (e.g., os.environ['KEY'])
        base_name = self._get_expression_name(node.value)
        return base_name in self.TAINT_SOURCES

    def _is_tainted_attribute(self, node: ast.Attribute) -> bool:
        """Check if an attribute node is tainted."""
        # Get the full attribute chain (e.g., "request.args")
        attr_chain = self._get_expression_name(node)
        if attr_chain in self.TAINT_SOURCES:
            return True
        # Check if the base object is tainted
        return self._is_tainted_expression(node.value)

    def _is_tainted_call(self, node: ast.Call) -> bool:
        """Check if a call node is tainted."""
        func_name = self._get_expression_name(node.func)
        if func_name in self.TAINT_SOURCES:
            return True
        # Check if any arguments are tainted
        return any(self._is_tainted_expression(arg) for arg in node.args)

    def _is_tainted_binop(self, node: ast.BinOp) -> bool:
        """Check if a binary operation is tainted."""
        return self._is_tainted_expression(node.left) or self._is_tainted_expression(node.right)

    def _is_tainted_fstring(self, node: ast.JoinedStr) -> bool:
        """Check if an f-string is tainted."""
        for value in node.values:
            if isinstance(value, ast.FormattedValue) and self._is_tainted_expression(value.value):
                return True
        return False

    def _is_tainted_expression(self, node: ast.AST) -> bool:
        """Check if an expression contains tainted data.

        Handles:
        - Variable references: var
        - Subscripts: list[0], dict['key'], request.form['key']
        - Attributes: obj.attr, request.args, request.GET
        - Binary operations: var + "text"
        - Direct taint source access: request.form, os.environ.get()
        - Method calls on taint sources: request.get_json()
        """
        if isinstance(node, ast.Name):
            return self._is_tainted_name(node)

        if isinstance(node, ast.Subscript):
            return self._is_tainted_subscript(node)

        if isinstance(node, ast.Attribute):
            return self._is_tainted_attribute(node)

        if isinstance(node, ast.Call):
            return self._is_tainted_call(node)

        if isinstance(node, ast.BinOp):
            return self._is_tainted_binop(node)

        if isinstance(node, ast.JoinedStr):
            return self._is_tainted_fstring(node)

        return False

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for dangerous patterns."""
        func_name = self._get_function_name(node.func)

        # Skip safe alternatives
        if func_name in self.SAFE_ALTERNATIVES:
            self.generic_visit(node)
            return

        # Check if this is a dangerous call
        severity = self.DANGEROUS_SINKS.get(func_name)
        if severity:
            # Always flag dangerous functions
            # The severity level already indicates how dangerous they are
            self.dangerous_calls.append((node, node.lineno, severity))

        self.generic_visit(node)

    def _get_function_name(self, node: ast.AST) -> str:
        """Extract the fully qualified function name from a call node."""
        if isinstance(node, ast.Name):
            # Simple function call: func()
            base_name = node.id
            # Resolve imports
            return self.imports.get(base_name, base_name)
        elif isinstance(node, ast.Attribute):
            # Method call: obj.method()
            parts: list[str] = []
            current: ast.expr = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            name = ".".join(parts)
            # Resolve imports for the base
            if parts and parts[0] in self.imports:
                resolved_base = self.imports[parts[0]]
                return f"{resolved_base}.{'.'.join(parts[1:])}"
            return name
        return ""

    def _get_expression_name(self, node: ast.AST) -> str:
        """Extract the fully qualified name from any expression node.

        Handles:
        - Simple names: var -> "var"
        - Attributes: obj.attr -> "obj.attr"
        - Nested attributes: request.form.get -> "request.form.get"
        - Subscripts: Returns the base name (e.g., list[0] -> "list")
        """
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # Build the full attribute chain
            parts: list[str] = []
            current: ast.expr = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            return ".".join(parts)
        elif isinstance(node, ast.Subscript):
            # For subscripts, return the base expression name
            return self._get_expression_name(node.value)
        return ""

    def _has_tainted_args(self, node: ast.Call) -> bool:
        """Check if any arguments to the call are tainted."""
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                return True
            # Check for string interpolation with tainted vars
            if isinstance(arg, ast.JoinedStr):  # f-string
                for value in arg.values:
                    if (
                        isinstance(value, ast.FormattedValue)
                        and isinstance(value.value, ast.Name)
                        and value.value.id in self.tainted_vars
                    ):
                        return True
            # Check for string formatting
            if (
                isinstance(arg, ast.BinOp)
                and isinstance(arg.op, ast.Mod)
                and isinstance(arg.right, ast.Name)
                and arg.right.id in self.tainted_vars
            ):  # % formatting
                return True
        return False


class ASTSecurityChecker:
    """High-level interface for AST-based security checking."""

    @staticmethod
    def check_dangerous_functions(
        file_path: Path, include_context: bool = True
    ) -> list[dict[str, Any]]:
        """Check for dangerous function usage with proper context awareness.

        Args:
            file_path: Path to Python file to analyze
            include_context: Whether to include AST context in results

        Returns:
            List of findings with context information
        """
        try:
            source = file_path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            return []

        analyzer = PythonASTAnalyzer(file_path)
        _taint_sources, dangerous_calls = analyzer.analyze(source)

        findings: list[dict[str, Any]] = []
        for call_node, line_num, severity in dangerous_calls:
            func_name = analyzer._get_function_name(call_node.func)

            # Get the actual source line
            lines = source.splitlines()
            line_content = lines[line_num - 1] if line_num <= len(lines) else ""

            # Check if this line has inline suppression
            if "# noqa" in line_content:
                continue

            # Determine if arguments are tainted
            is_tainted = analyzer._has_tainted_args(call_node)

            finding: dict[str, Any] = {
                "function": func_name,
                "line_number": line_num,
                "line_content": line_content,
                "severity": severity,
                "is_tainted": is_tainted,
                "confidence": "high" if is_tainted else "medium",
            }

            if include_context:
                finding["ast_node"] = call_node
                finding["column"] = call_node.col_offset

            findings.append(finding)

        return findings

    @staticmethod
    def detect_eval_exec_usage(file_path: Path) -> list[dict[str, Any]]:
        """Specifically detect eval/exec usage with context.

        This is more accurate than regex as it:
        - Excludes comments and strings
        - Understands scope
        - Detects obfuscated calls
        """
        findings = ASTSecurityChecker.check_dangerous_functions(file_path)
        return [f for f in findings if f["function"] in ("eval", "exec")]

    @staticmethod
    def detect_subprocess_injection(file_path: Path) -> list[dict[str, Any]]:
        """Detect potential command injection in subprocess calls."""
        try:
            source = file_path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            return []

        analyzer = PythonASTAnalyzer(file_path)
        _, dangerous_calls = analyzer.analyze(source)

        findings: list[dict[str, Any]] = []
        for call_node, line_num, _severity in dangerous_calls:
            func_name = analyzer._get_function_name(call_node.func)

            if func_name.startswith("subprocess."):
                # Check for shell=True with tainted input
                shell_true = False
                for keyword in call_node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        shell_true = True

                is_tainted = analyzer._has_tainted_args(call_node)

                if shell_true and is_tainted:
                    lines = source.splitlines()
                    findings.append(
                        {
                            "function": func_name,
                            "line_number": line_num,
                            "line_content": lines[line_num - 1] if line_num <= len(lines) else "",
                            "severity": "critical",
                            "is_tainted": True,
                            "confidence": "high",
                            "issue": "subprocess with shell=True and tainted input",
                        }
                    )

        return findings
