"""OASIS SARIF v2.1.0 exporter for integration with GitHub Advanced Security and IDEs."""

import json
from typing import Dict, Any, List

from reposentinel.core.config import APP_NAME, VERSION
from reposentinel.core.models import ScanReport


def export_report_to_sarif(report: ScanReport) -> str:
    """Exports findings to OASIS SARIF v2.1.0 standard schema."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    def map_level(severity: str) -> str:
        s = severity.lower()
        if s in ("critical", "high"):
            return "error"
        elif s == "medium":
            return "warning"
        return "note"

    # 1. Process Secret Findings
    for sec in report.secret_findings:
        rule_id = f"RS-SEC-{sec.rule.upper().replace(' ', '-')}"
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": sec.rule,
                "shortDescription": {"text": f"Potential exposed credential: {sec.rule}"},
                "defaultConfiguration": {"level": map_level(sec.severity)},
                "properties": {
                    "tags": ["security", "secrets", "credentials"],
                    "precision": "high",
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": map_level(sec.severity),
            "message": {
                "text": f"Exposed {sec.rule} in {sec.file}:{sec.line}. Evidence: {sec.evidence}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": sec.file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": sec.line,
                        },
                    }
                }
            ],
        })

    # 2. Process Dependency Advisories
    for adv in report.dependency_advisories:
        rule_id = f"RS-DEP-{adv.id}"
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f"VulnerableDependency-{adv.package}",
                "shortDescription": {"text": f"Vulnerable dependency: {adv.package} ({adv.version})"},
                "helpUri": adv.url,
                "defaultConfiguration": {"level": map_level(adv.severity)},
                "properties": {
                    "tags": ["security", "dependency", "vulnerability"],
                },
            }

        fix_hint = f" Upgrade to {adv.fixed_version}." if adv.fixed_version else ""
        results.append({
            "ruleId": rule_id,
            "level": map_level(adv.severity),
            "message": {
                "text": f"{adv.package} version {adv.version} is affected by {adv.id}: {adv.summary}{fix_hint}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": adv.source or "package.json",
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": 1,
                        },
                    }
                }
            ],
        })

    sarif_log: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": APP_NAME,
                        "semanticVersion": VERSION,
                        "informationUri": "https://github.com/reposentinel-ai/reposentinel",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_log, indent=2)
