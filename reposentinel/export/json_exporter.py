"""JSON report exporter for RepoSentinel AI."""

import json
from datetime import datetime, timezone
from typing import Dict, Any

from reposentinel.core.config import APP_NAME, VERSION
from reposentinel.core.models import ScanReport


def export_report_to_json(report: ScanReport) -> str:
    """Exports a ScanReport model into structured JSON string."""
    data: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/reposentinel-ai/spec/v1/report.schema.json",
        "tool": {
            "name": APP_NAME,
            "version": VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "report": report.to_dict(),
    }
    return json.dumps(data, indent=2, ensure_ascii=False)
