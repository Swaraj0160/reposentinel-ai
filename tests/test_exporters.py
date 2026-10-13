"""Unit tests for report exporters (JSON, Markdown, SARIF)."""

import json
import pytest

from reposentinel.core.models import ScanReport, SecretFinding, Advisory, Dependency
from reposentinel.export.json_exporter import export_report_to_json
from reposentinel.export.markdown_exporter import export_report_to_markdown
from reposentinel.export.sarif_exporter import export_report_to_sarif


@pytest.fixture
def sample_report() -> ScanReport:
    return ScanReport(
        project_name="test_project",
        files_scanned=12,
        secret_findings=[
            SecretFinding(
                id="SEC-0001",
                rule="AWS Access Key ID",
                severity="High",
                file="src/config.py",
                line=5,
                evidence="[REDACTED_AWS_ACCESS_KEY]",
                recommendation="Rotate",
            )
        ],
        dependency_advisories=[
            Advisory(
                id="GHSA-72xf-g2v4-qvf3",
                package="requests",
                version="2.30.0",
                ecosystem="PyPI",
                severity="High",
                fixed_version="2.31.0",
                summary="Proxy leak",
                url="https://osv.dev/vulnerability/GHSA-72xf-g2v4-qvf3",
                source="requirements.txt",
            )
        ],
        dependencies_parsed=[
            Dependency(name="requests", version="2.30.0", ecosystem="PyPI", source="requirements.txt")
        ],
        ai_triage="### AI Triage: Action required on 2 items.",
    )


def test_json_export(sample_report: ScanReport):
    json_str = export_report_to_json(sample_report)
    parsed = json.loads(json_str)

    assert parsed["tool"]["name"] == "RepoSentinel AI"
    assert parsed["report"]["project_name"] == "test_project"
    assert len(parsed["report"]["secret_findings"]) == 1
    assert parsed["report"]["secret_findings"][0]["rule"] == "AWS Access Key ID"


def test_markdown_export(sample_report: ScanReport):
    md_str = export_report_to_markdown(sample_report)

    assert "# RepoSentinel AI Security Audit Report" in md_str
    assert "src/config.py:5" in md_str
    assert "GHSA-72xf-g2v4-qvf3" in md_str
    assert "AI Triage" in md_str


def test_sarif_export(sample_report: ScanReport):
    sarif_str = export_report_to_sarif(sample_report)
    parsed = json.loads(sarif_str)

    assert parsed["version"] == "2.1.0"
    runs = parsed["runs"]
    assert len(runs) == 1
    driver = runs[0]["tool"]["driver"]
    assert driver["name"] == "RepoSentinel AI"

    results = runs[0]["results"]
    assert len(results) == 2  # 1 secret + 1 advisory
    sec_result = next(r for r in results if "SEC" in r["ruleId"])
    assert sec_result["level"] == "error"  # High severity mapped to error
    assert sec_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/config.py"
