"""Baseline support for suppressing existing findings.

Baselines allow you to:
1. Adopt the tool in existing codebases without fixing everything first
2. Only report NEW issues introduced after baseline creation
3. Track technical debt over time
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from owasp_agentic_scanner.rules.base import Finding

logger = logging.getLogger("owasp_scanner")


@dataclass
class BaselineFinding:
    """A finding stored in the baseline."""

    rule_id: str
    file_path: str
    line_number: int
    message: str
    hash: str  # Hash of the finding for matching

    @classmethod
    def from_finding(cls, finding: Finding) -> "BaselineFinding":
        """Create baseline finding from a regular finding."""
        # Create a hash to identify this specific finding
        finding_hash = cls._compute_hash(
            finding.rule_id,
            finding.file_path,
            finding.line_number,
            finding.message,
            finding.line_content,
        )

        return cls(
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            line_number=finding.line_number,
            message=finding.message,
            hash=finding_hash,
        )

    @staticmethod
    def _compute_hash(
        rule_id: str,
        file_path: str,
        line_number: int,  # noqa: ARG004
        message: str,
        line_content: str,
    ) -> str:
        """Compute a stable hash for a finding."""
        import hashlib

        # Use rule_id, file, line, and a snippet of the content
        # This allows findings to move slightly (line numbers change by a few lines)
        # but still be recognized
        content_snippet = line_content.strip()[:100]
        data = f"{rule_id}:{file_path}:{message}:{content_snippet}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "message": self.message,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaselineFinding":
        """Create from dictionary."""
        return cls(
            rule_id=data["rule_id"],
            file_path=data["file_path"],
            line_number=data["line_number"],
            message=data["message"],
            hash=data["hash"],
        )


class Baseline:
    """Manages baseline findings to suppress known issues."""

    def __init__(self, baseline_file: Path | None = None) -> None:
        """Initialize baseline.

        Args:
            baseline_file: Path to baseline JSON file
        """
        self.baseline_file = baseline_file
        self.findings: dict[str, BaselineFinding] = {}
        self.metadata: dict[str, Any] = {}

        if baseline_file and baseline_file.exists():
            self.load(baseline_file)

    def load(self, baseline_file: Path) -> None:
        """Load baseline from file.

        Args:
            baseline_file: Path to baseline JSON file
        """
        try:
            with open(baseline_file, encoding="utf-8") as f:
                data = json.load(f)

            self.metadata = data.get("metadata", {})
            findings_data = data.get("findings", [])

            self.findings = {}
            for finding_dict in findings_data:
                finding = BaselineFinding.from_dict(finding_dict)
                self.findings[finding.hash] = finding

            logger.info(f"Loaded baseline with {len(self.findings)} findings from {baseline_file}")

        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.error(f"Failed to load baseline from {baseline_file}: {e}")
            self.findings = {}

    def save(self, baseline_file: Path, findings: list[Finding]) -> None:
        """Save current findings as baseline.

        Args:
            baseline_file: Path to save baseline JSON file
            findings: List of findings to baseline
        """
        import datetime

        self.baseline_file = baseline_file
        self.findings = {}

        for finding in findings:
            baseline_finding = BaselineFinding.from_finding(finding)
            self.findings[baseline_finding.hash] = baseline_finding

        self.metadata = {
            "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "total_findings": len(findings),
            "files_scanned": len({f.file_path for f in findings}),
        }

        data = {
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.findings.values()],
        }

        try:
            baseline_file.parent.mkdir(parents=True, exist_ok=True)
            with open(baseline_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            logger.info(f"Saved baseline with {len(self.findings)} findings to {baseline_file}")

        except OSError as e:
            logger.error(f"Failed to save baseline to {baseline_file}: {e}")

    def is_baselined(self, finding: Finding) -> bool:
        """Check if a finding is in the baseline (should be suppressed).

        Args:
            finding: Finding to check

        Returns:
            True if finding is in baseline, False otherwise
        """
        baseline_finding = BaselineFinding.from_finding(finding)

        # Exact match by hash
        if baseline_finding.hash in self.findings:
            return True

        # Fuzzy match: same file, same rule, similar line number (±5 lines)
        # This handles minor code changes that shift line numbers
        for bf in self.findings.values():
            if (
                bf.rule_id == finding.rule_id
                and bf.file_path == finding.file_path
                and abs(bf.line_number - finding.line_number) <= 5
                and bf.message == finding.message
            ):
                return True

        return False

    def filter_new_findings(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Filter findings into new and baselined.

        Args:
            findings: All findings

        Returns:
            Tuple of (new_findings, baselined_findings)
        """
        new_findings = []
        baselined_findings = []

        for finding in findings:
            if self.is_baselined(finding):
                baselined_findings.append(finding)
            else:
                new_findings.append(finding)

        logger.info(
            f"Found {len(new_findings)} new findings and {len(baselined_findings)} baselined findings"
        )

        return new_findings, baselined_findings

    def get_stats(self) -> dict[str, Any]:
        """Get baseline statistics.

        Returns:
            Dictionary with baseline stats
        """
        if not self.findings:
            return {"total": 0}

        # Count by severity, rule, file
        by_rule: dict[str, int] = {}
        by_file: dict[str, int] = {}

        for finding in self.findings.values():
            by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
            by_file[finding.file_path] = by_file.get(finding.file_path, 0) + 1

        return {
            "total": len(self.findings),
            "by_rule": by_rule,
            "by_file": by_file,
            "metadata": self.metadata,
        }
