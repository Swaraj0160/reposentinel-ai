"""Unit tests for secret detection, placeholder handling, and redaction."""

from pathlib import Path
import tempfile
import pytest

from reposentinel.scanners.secrets import (
    scan_directory_for_secrets,
    safe_redact,
    calculate_shannon_entropy,
    is_placeholder_or_env_read,
)


def test_positive_aws_key_detection(tmp_path: Path):
    test_file = tmp_path / "creds.py"
    test_file.write_text("AWS_KEY = 'AKIA1234567890ABCDEF'\n", encoding="utf-8")

    findings, scanned = scan_directory_for_secrets(tmp_path)
    assert scanned == 1
    assert len(findings) == 1
    assert findings[0].rule == "AWS Access Key ID"
    assert findings[0].severity == "High"
    assert "AKIA1234567890ABCDEF" not in findings[0].evidence
    assert "[REDACTED_AWS_ACCESS_KEY]" in findings[0].evidence


def test_positive_github_token_detection(tmp_path: Path):
    test_file = tmp_path / "github_auth.js"
    test_file.write_text("const token = 'ghp_1234567890abcdefghijklmnopqrstuvwx';\n", encoding="utf-8")

    findings, _ = scan_directory_for_secrets(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "GitHub Personal Access Token"
    assert "ghp_12345" not in findings[0].evidence


def test_positive_private_key_detection(tmp_path: Path):
    test_file = tmp_path / "id_rsa"
    test_file.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n", encoding="utf-8")

    findings, _ = scan_directory_for_secrets(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "Private Key"
    assert findings[0].severity == "Critical"


def test_positive_database_uri_detection(tmp_path: Path):
    test_file = tmp_path / "db.py"
    test_file.write_text("DATABASE_URL = 'postgres://admin:SuperSecretPass123!@db.internal:5432/app'\n", encoding="utf-8")

    findings, _ = scan_directory_for_secrets(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "Database Connection URI with Password"
    assert "SuperSecretPass123!" not in findings[0].evidence


def test_placeholder_filtering(tmp_path: Path):
    test_file = tmp_path / "config.js"
    test_file.write_text("const API_KEY = 'example_placeholder_token_do_not_use_12345';\n", encoding="utf-8")

    findings, _ = scan_directory_for_secrets(tmp_path, include_placeholders=False)
    assert len(findings) == 0

    # When include_placeholders=True, it should be flagged as is_placeholder
    findings_with_placeholders, _ = scan_directory_for_secrets(tmp_path, include_placeholders=True)
    assert len(findings_with_placeholders) == 1
    assert findings_with_placeholders[0].is_placeholder is True


def test_env_read_pattern_filtering(tmp_path: Path):
    test_file = tmp_path / "app.py"
    test_file.write_text("key = os.getenv('API_KEY', 'default')\npwd = os.environ['DB_PASS']\n", encoding="utf-8")

    findings, _ = scan_directory_for_secrets(tmp_path)
    assert len(findings) == 0


def test_clean_file_no_findings(tmp_path: Path):
    test_file = tmp_path / "math_utils.py"
    test_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    findings, scanned = scan_directory_for_secrets(tmp_path)
    assert scanned == 1
    assert len(findings) == 0


def test_shannon_entropy_calculation():
    # Low entropy repeating string
    low = calculate_shannon_entropy("aaaaaaaaaaaa")
    assert low == 0.0

    # High entropy random base64 string
    high = calculate_shannon_entropy("d8A3b!zK9#Lp2$Qx")
    assert high > 3.5


def test_safe_redaction_does_not_leak_secret():
    raw_line = "API_KEY = 'super_secret_production_key_value_987654321'"
    redacted = safe_redact(raw_line, "super_secret_production_key_value_987654321", "[REDACTED_KEY]")
    assert "super_secret_production_key_value_987654321" not in redacted
    assert "[REDACTED_KEY]" in redacted
