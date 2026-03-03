"""Test credential detection improvements."""

import tempfile
from pathlib import Path


def test_placeholder_detection():
    """Test that placeholders are correctly identified."""
    from owasp_agentic_scanner.rules.privilege_abuse import _is_placeholder_credential

    # These should be identified as placeholders
    assert _is_placeholder_credential("YOUR_API_KEY_HERE")
    assert _is_placeholder_credential("example_password")
    assert _is_placeholder_credential("xxxxxxxxxxxxxxxx")
    assert _is_placeholder_credential("12345678")
    assert _is_placeholder_credential("password123")
    assert _is_placeholder_credential("PLACEHOLDER_TOKEN")
    assert _is_placeholder_credential("changeme")
    assert _is_placeholder_credential("put_your_key_here")
    assert _is_placeholder_credential("test")
    assert _is_placeholder_credential("fake")
    assert _is_placeholder_credential("xxx")
    assert _is_placeholder_credential("qwertyqwerty")
    assert _is_placeholder_credential("ALLUPPERCASEPLACEHOLDER")

    # These should NOT be placeholders
    assert not _is_placeholder_credential("sk_live_51HqT2P...")
    assert not _is_placeholder_credential("ghp_1s3K4r3T...")


def test_entropy_calculation():
    """Test entropy calculation for credential validation."""
    from owasp_agentic_scanner.rules.privilege_abuse import _calculate_entropy

    # Empty string
    assert _calculate_entropy("") == 0.0

    # Low entropy (repetitive)
    assert _calculate_entropy("aaaaaaaa") < 1.0
    assert _calculate_entropy("12121212") < 2.0

    # Medium entropy
    assert 2.0 < _calculate_entropy("password123") < 4.0

    # High entropy (random-looking)
    assert _calculate_entropy("aB3$xK9@mQ2") > 3.0
    assert _calculate_entropy("sk_live_51HqT2P2K...") > 3.5


def test_sequential_numbers():
    """Test sequential number detection."""
    from owasp_agentic_scanner.rules.privilege_abuse import _is_sequential_numbers

    # Sequential ascending
    assert _is_sequential_numbers("12345678")
    assert _is_sequential_numbers("23456789")

    # Sequential descending
    assert _is_sequential_numbers("87654321")

    # Sequential with wrapping (9->0)
    assert _is_sequential_numbers("89012345")

    # Not sequential - all same digit (edge case fix)
    assert not _is_sequential_numbers("00000000")
    assert not _is_sequential_numbers("11111111")
    assert not _is_sequential_numbers("99999999")

    # Not sequential - other cases
    assert not _is_sequential_numbers("12346789")  # Skip
    assert not _is_sequential_numbers("abc12345")  # Not digits
    assert not _is_sequential_numbers("1234567")  # Too short
    assert not _is_sequential_numbers("13579246")  # Random


def test_real_credential_detection():
    """Test detection of likely real credentials."""
    from owasp_agentic_scanner.rules.privilege_abuse import _is_likely_real_credential

    # Real-looking credentials
    assert _is_likely_real_credential("sk_live_51HqT2P2KCm")
    assert _is_likely_real_credential("ghp_1s3K4r3Tm0nk3y")
    assert _is_likely_real_credential("AIzaSyC-JlK7jkLm9nO0pQrS")

    # Placeholders
    assert not _is_likely_real_credential("YOUR_API_KEY")
    assert not _is_likely_real_credential("example_password")
    assert not _is_likely_real_credential("xxxxxxxxxxxx")
    assert not _is_likely_real_credential("12345678")
    assert not _is_likely_real_credential("password")


def test_privilege_abuse_filters_placeholders():
    """Test that PrivilegeAbuseRule filters out placeholder credentials."""
    from owasp_agentic_scanner.rules.privilege_abuse import PrivilegeAbuseRule

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.py"

        # File with placeholder credential
        test_file.write_text("""
api_key = "YOUR_API_KEY_HERE"
password = "changeme"
secret = "example_secret"
""")

        rule = PrivilegeAbuseRule()
        findings = rule.scan_file(test_file)

        # Should filter out all placeholders
        credential_findings = [f for f in findings if "credential" in f.message.lower()]
        assert len(credential_findings) == 0


def test_privilege_abuse_detects_real_credentials():
    """Test that PrivilegeAbuseRule detects real-looking credentials."""
    from owasp_agentic_scanner.rules.privilege_abuse import PrivilegeAbuseRule

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.py"

        # File with real-looking credential
        test_file.write_text("""
api_key = "sk_live_51HqT2P2KCmNpQ9J"
password = "MyP@ssw0rd!2024"
secret_token = "ghp_1s3K4r3Tm0nk3yP4ss"
""")

        rule = PrivilegeAbuseRule()
        findings = rule.scan_file(test_file)

        # Should detect real-looking credentials
        credential_findings = [f for f in findings if "credential" in f.message.lower()]
        assert len(credential_findings) >= 2  # At least 2 of the 3


def test_privilege_abuse_case_insensitive():
    """Test that detection is case-insensitive."""
    from owasp_agentic_scanner.rules.privilege_abuse import PrivilegeAbuseRule

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.py"

        # Different case variations
        test_file.write_text("""
API_KEY = "sk_live_51HqT2P2KCmNpQ9J"
Api_Key = "sk_test_49HsE2N1LDnOqR8K"
api_key = "sk_prod_38GrD1M2KEnNrS7L"
""")

        rule = PrivilegeAbuseRule()
        findings = rule.scan_file(test_file)

        # Should detect all variations
        credential_findings = [f for f in findings if "credential" in f.message.lower()]
        assert len(credential_findings) >= 2


if __name__ == "__main__":
    test_placeholder_detection()
    print("✓ Placeholder detection tests passed")

    test_entropy_calculation()
    print("✓ Entropy calculation tests passed")

    test_real_credential_detection()
    print("✓ Real credential detection tests passed")

    test_privilege_abuse_filters_placeholders()
    print("✓ Placeholder filtering tests passed")

    test_privilege_abuse_detects_real_credentials()
    print("✓ Real credential detection tests passed")

    test_privilege_abuse_case_insensitive()
    print("✓ Case-insensitive detection tests passed")

    print("\n✅ All credential detection tests passed!")
