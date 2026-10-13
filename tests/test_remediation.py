"""Unit tests for remediation proposals, unified diffs, and sandbox verification."""

from pathlib import Path
import pytest

from reposentinel.core.models import SecretFinding, Advisory
from reposentinel.remediation.diff_utils import generate_unified_diff, apply_snippet_replacement
from reposentinel.remediation.engine import RemediationEngine


def test_unified_diff_generation():
    orig = "def foo():\n    return 1\n"
    mod = "def foo():\n    return 2\n"
    diff = generate_unified_diff(orig, mod, "foo.py")
    assert "--- a/foo.py" in diff
    assert "+++ b/foo.py" in diff
    assert "-    return 1" in diff
    assert "+    return 2" in diff


def test_apply_snippet_replacement():
    content = "API_KEY = 'secret123'\nPORT = 8080\n"
    res = apply_snippet_replacement(content, "API_KEY = 'secret123'", "API_KEY = os.getenv('API_KEY', '')")
    assert res is not None
    assert "os.getenv('API_KEY', '')" in res
    assert "PORT = 8080" in res


def test_propose_secret_remediation_python():
    finding = SecretFinding(
        id="SEC-0001",
        rule="AWS Access Key ID",
        severity="High",
        file="src/aws.py",
        line=1,
        evidence="[REDACTED_AWS_ACCESS_KEY]",
        recommendation="Rotate",
    )
    orig_content = "AWS_ACCESS_KEY_ID = 'AKIA1234567890ABCDEF'\n"
    proposal = RemediationEngine.propose_secret_remediation(finding, orig_content)

    assert proposal.finding_id == "SEC-0001"
    assert "os.getenv" in proposal.proposed_snippet
    assert "--- a/src/aws.py" in proposal.diff


def test_propose_secret_remediation_javascript():
    finding = SecretFinding(
        id="SEC-0002",
        rule="Generic API Token",
        severity="Medium",
        file="src/client.js",
        line=1,
        evidence="[REDACTED_API_TOKEN]",
        recommendation="Rotate",
    )
    orig_content = "const API_KEY = 'my_secret_token_1234567890';\n"
    proposal = RemediationEngine.propose_secret_remediation(finding, orig_content)

    assert "process.env" in proposal.proposed_snippet


def test_propose_dependency_remediation():
    advisory = Advisory(
        id="GHSA-72xf-g2v4-qvf3",
        package="requests",
        version="2.30.0",
        ecosystem="PyPI",
        fixed_version="2.31.0",
    )
    manifest_content = "requests==2.30.0\nurllib3==2.0.0\n"
    proposal = RemediationEngine.propose_dependency_remediation(advisory, manifest_content, "requirements.txt")

    assert "2.31.0" in proposal.proposed_snippet
    assert "-requests==2.30.0" in proposal.diff or "-requests == 2.30.0" in proposal.diff
    assert "+requests==2.31.0" in proposal.diff or "+requests == 2.31.0" in proposal.diff


def test_verify_patch_in_sandbox_secret(tmp_path: Path):
    # Setup temporary repo with an exposed secret
    src_file = tmp_path / "creds.py"
    src_file.write_text("AWS_KEY = 'AKIA1234567890ABCDEF'\n", encoding="utf-8")

    # Propose safe environment variable replacement
    clean_content = "import os\nAWS_KEY = os.getenv('AWS_KEY', '')\n"

    # Verify patch in sandbox
    res = RemediationEngine.verify_patch_in_sandbox(
        repo_root=tmp_path,
        relative_file_path="creds.py",
        proposed_file_content=clean_content,
        finding_id="SEC-0001",
        finding_type="secret",
    )

    assert res.status == "VERIFIED"
    assert res.scanner_verified is True
    # Confirm original file was NOT modified!
    assert "AKIA1234567890ABCDEF" in src_file.read_text(encoding="utf-8")


def test_verify_patch_in_sandbox_failed(tmp_path: Path):
    # Setup repo with an exposed secret
    src_file = tmp_path / "creds.py"
    src_file.write_text("AWS_KEY = 'AKIA1234567890ABCDEF'\n", encoding="utf-8")

    # Bad patch: still contains hardcoded secret
    bad_content = "AWS_KEY = 'AKIA9999999999ZZZZZZ'\n"

    res = RemediationEngine.verify_patch_in_sandbox(
        repo_root=tmp_path,
        relative_file_path="creds.py",
        proposed_file_content=bad_content,
        finding_id="SEC-0001",
        finding_type="secret",
    )

    assert res.status == "FAILED"
    assert res.scanner_verified is False
