"""AA03: Identity & Privilege Abuse detection rule."""

import math
import re
from collections import Counter
from pathlib import Path

from owasp_agentic_scanner.constants import (
    MAX_REPETITIVE_CHAR_TYPES,
    MAX_UPPERCASE_PLACEHOLDER_LENGTH,
    MIN_CHARACTER_TYPES,
    MIN_CREDENTIAL_LENGTH,
    MIN_ENTROPY_THRESHOLD,
    MIN_REPETITIVE_LENGTH,
    MIN_SEQUENTIAL_LENGTH,
)
from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Finding,
    Severity,
    pattern,
)


def _has_placeholder_word(value: str) -> bool:
    """Check if value contains placeholder words.

    Args:
        value: The credential value to check

    Returns:
        True if value contains placeholder words
    """
    placeholder_words = [
        "your_",
        "example",
        "placeholder",
        "changeme",
        "replace",
        "insert",
        "paste",
        "enter",
        "todo",
        "fixme",
        "dummy",
        "sample",
        "put_",
        "add_",
        "set_",
    ]
    value_lower = value.lower()

    for placeholder in placeholder_words:
        if placeholder in value_lower and (
            value_lower.startswith(placeholder)
            or f"_{placeholder}" in value_lower
            or placeholder.endswith("_")
        ):
            return True
    return False


def _has_repetitive_chars(value: str) -> bool:
    """Check if value has repetitive characters.

    Args:
        value: The credential value to check

    Returns:
        True if value has repetitive characters (e.g., "xxxxxxxx")
    """
    return len(set(value)) <= MAX_REPETITIVE_CHAR_TYPES and len(value) > MIN_REPETITIVE_LENGTH


def _is_sequential_numbers(value: str) -> bool:
    """Check if value is sequential numbers.

    Args:
        value: The credential value to check

    Returns:
        True if value is sequential numbers (e.g., "12345678")
    """
    if not value.isdigit() or len(value) < MIN_SEQUENTIAL_LENGTH:
        return False

    # All same digit is a placeholder, not sequential (e.g., "00000000")
    if len(set(value)) == 1:
        return False

    for i in range(len(value) - 1):
        diff = int(value[i + 1]) - int(value[i])
        # Allow wrapping (9->0) or consistent increment/decrement
        if abs(diff) != 1 and not (diff == -9 or diff == 9):
            return False
    return True


def _is_placeholder_credential(value: str) -> bool:
    """Check if a credential value appears to be a placeholder.

    Args:
        value: The credential value to check

    Returns:
        True if the value appears to be a placeholder
    """
    value_lower = value.lower()

    # Check for placeholder words
    if _has_placeholder_word(value):
        return True

    # Check for obvious test/fake patterns
    if value_lower in ["test", "fake", "xxx", "***", "..."]:
        return True

    # Check for repetitive characters
    if _has_repetitive_chars(value):
        return True

    # Check for sequential numeric patterns
    if _is_sequential_numbers(value):
        return True

    # Check for sequential patterns
    if re.match(r"^(abc|123|qwerty|password|admin)+$", value_lower):
        return True

    # Check for all same case (placeholders often all caps)
    return value.isupper() and len(value) > MAX_UPPERCASE_PLACEHOLDER_LENGTH


def _calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string.

    Higher entropy indicates more randomness, typical of real credentials.

    Args:
        value: String to calculate entropy for

    Returns:
        Entropy value (0 to ~6 for typical strings)
    """
    if not value:
        return 0.0

    # Count character frequencies
    counter = Counter(value)
    length = len(value)

    # Calculate Shannon entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def _is_likely_real_credential(value: str) -> bool:
    """Check if a credential value looks like a real secret.

    Args:
        value: The credential value to check

    Returns:
        True if the value appears to be a real credential
    """
    # Too short to be a real credential
    if len(value) < MIN_CREDENTIAL_LENGTH:
        return False

    # Check if it's a placeholder
    if _is_placeholder_credential(value):
        return False

    # Calculate character type diversity
    char_types = sum(
        [
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        ]
    )

    # Real credentials usually have multiple character types
    if char_types < MIN_CHARACTER_TYPES:
        return False

    # Check entropy - real credentials have higher entropy
    entropy = _calculate_entropy(value)
    # Low entropy suggests pattern or repetition
    return entropy >= MIN_ENTROPY_THRESHOLD


class PrivilegeAbuseRule(BaseRule):
    """Detect patterns that could lead to identity and privilege abuse.

    Identity & Privilege Abuse occurs when compromised credentials or
    mismanaged permissions allow agents to operate beyond their intended scope.
    """

    rule_id = "AA03"
    rule_name = "Identity & Privilege Abuse"
    owasp_category = "AA03: Identity & Privilege Abuse"
    description = "Detects patterns that could lead to privilege abuse by agents"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            # Enhanced credential detection with case variations
            DetectionPattern(
                pattern=pattern(
                    r"(api_?key|apikey|secret|password|token|auth|credential|private_?key)"
                    r"\s*[:=]\s*[\"']([^\"']{8,})[\"']",
                    re.IGNORECASE,
                ),
                message="Potential hardcoded credential detected",
                recommendation="Use environment variables or secrets management for credentials. "
                "Verify this is not a placeholder before removing.",
                severity=Severity.CRITICAL,
                confidence="medium",  # Medium because we can't validate in pattern
            ),
            DetectionPattern(
                pattern=pattern(r"admin|superuser|root"),
                message="Elevated privilege reference detected",
                recommendation="Apply principle of least privilege. Avoid admin/root access for agents.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"sudo\s|as\s+root|--privileged"),
                message="Privileged execution detected",
                recommendation="Agents should never run with elevated privileges.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"chmod\s+777|chmod\s+\+x\s+.*\$"),
                message="Dangerous permission modification",
                recommendation="Avoid broad permission changes. Use minimal required permissions.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"service_account.*all|all.*permissions|full.*access"),
                message="Overly permissive access pattern",
                recommendation="Scope service accounts to minimal required permissions.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"impersonate|assume.*role|sts.*assume"),
                message="Role assumption/impersonation detected",
                recommendation="Audit and restrict role assumption capabilities.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"auth.*bypass|skip.*auth|no.*auth"),
                message="Authentication bypass pattern",
                recommendation="Never bypass authentication. Implement proper auth for all agent actions.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"),
                message="Potential hardcoded bearer token",
                recommendation="Use secure token storage and rotation.",
                severity=Severity.CRITICAL,
                confidence="medium",
            ),
        ]

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Override scan_file to add credential validation.

        This method adds post-processing to filter out placeholder credentials
        and reduce false positives.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of Finding objects with placeholder credentials filtered out
        """
        # Call parent scan_file to get initial findings
        findings = super().scan_file(file_path)

        # Filter out placeholder credentials
        filtered_findings = []
        for finding in findings:
            # Only filter credential-related findings
            if "credential" in finding.message.lower() or "hardcoded" in finding.message.lower():
                # Extract the credential value from the line
                # Pattern: key=["']value["']
                match = re.search(
                    r"(api_?key|apikey|secret|password|token|auth|credential|private_?key)"
                    r"\s*[:=]\s*[\"']([^\"']+)[\"']",
                    finding.line_content,
                    re.IGNORECASE,
                )

                if match:
                    credential_value = match.group(2)

                    # Skip if it's likely a placeholder
                    if _is_likely_real_credential(credential_value):
                        # This appears to be a real credential
                        filtered_findings.append(finding)
                    # else: Skip placeholders (reduce false positives)
                else:
                    # Couldn't extract value, keep the finding to be safe
                    filtered_findings.append(finding)
            else:
                # Not a credential finding, keep it
                filtered_findings.append(finding)

        return filtered_findings
