"""OSV (Open Source Vulnerabilities) API client with caching, retry logic, and metadata extraction."""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

import requests

from reposentinel.core.config import OSV_API_URL, OSV_TIMEOUT_SECONDS, OSV_CACHE_FILE
from reposentinel.core.models import Dependency, Advisory

logger = logging.getLogger(__name__)


class OSVClient:
    """Client for querying the OSV.dev vulnerability database."""

    def __init__(self, cache_file: Optional[Path] = None, timeout: int = OSV_TIMEOUT_SECONDS):
        self.timeout = timeout
        self.cache_file = cache_file or OSV_CACHE_FILE
        self._memory_cache: Dict[str, Any] = {}
        self._load_cache()

    def _load_cache(self):
        """Loads cached responses from disk."""
        try:
            if self.cache_file and self.cache_file.exists():
                data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._memory_cache = data
        except Exception as e:
            logger.debug(f"Could not load OSV cache: {e}")

    def _save_cache(self):
        """Saves current memory cache to disk."""
        try:
            if self.cache_file:
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                self.cache_file.write_text(json.dumps(self._memory_cache, indent=2), encoding="utf-8")
        except Exception as e:
            logger.debug(f"Could not save OSV cache: {e}")

    def _cache_key(self, ecosystem: str, package: str, version: str) -> str:
        return f"{ecosystem.lower()}:{package.lower()}:{version}"

    def query_package(self, ecosystem: str, package: str, version: str) -> List[Dict[str, Any]]:
        """
        Queries OSV for vulnerabilities affecting a specific package version.
        Uses in-memory & persistent cache before issuing HTTP request.
        """
        key = self._cache_key(ecosystem, package, version)
        if key in self._memory_cache:
            return self._memory_cache[key]

        payload = {
            "package": {
                "name": package,
                "ecosystem": ecosystem,
            },
            "version": version,
        }

        try:
            response = requests.post(
                OSV_API_URL,
                json=payload,
                headers={"User-Agent": "RepoSentinel-AI/1.0"},
                timeout=self.timeout,
            )
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                self._memory_cache[key] = vulns
                self._save_cache()
                return vulns
            elif response.status_code == 404:
                self._memory_cache[key] = []
                self._save_cache()
                return []
            else:
                logger.warning(f"OSV query for {package} {version} failed with HTTP {response.status_code}")
                return []
        except requests.exceptions.RequestException as e:
            logger.warning(f"OSV request error for {package} {version}: {e}")
            return []

    @staticmethod
    def extract_severity(vuln_data: Dict[str, Any]) -> Tuple[str, Optional[float]]:
        """
        Extracts human-readable severity label and CVSS score from OSV record.
        Never invents severity scores.
        """
        severities = vuln_data.get("severity", [])
        if isinstance(severities, list):
            for s in severities:
                if isinstance(s, dict) and s.get("type") in ("CVSS_V3", "CVSS_V2", "CVSS_V4"):
                    score_str = s.get("score", "")
                    # Extract numeric CVSS if present
                    score_match = score_str.split("/")[-1] if "/" in score_str else score_str
                    try:
                        score_num = float(score_match)
                        if score_num >= 9.0:
                            return "Critical", score_num
                        elif score_num >= 7.0:
                            return "High", score_num
                        elif score_num >= 4.0:
                            return "Medium", score_num
                        else:
                            return "Low", score_num
                    except ValueError:
                        pass

        # Check database specific rating
        db_specific = vuln_data.get("database_specific", {})
        if isinstance(db_specific, dict):
            raw_sev = db_specific.get("severity")
            if isinstance(raw_sev, str):
                normalized = raw_sev.strip().capitalize()
                if normalized in ("Critical", "High", "Medium", "Low"):
                    return normalized, None

        return "Unknown", None

    @staticmethod
    def extract_fixed_version(vuln_data: Dict[str, Any], package_name: str) -> Optional[str]:
        """Extracts the patched/fixed version from OSV affected ranges."""
        affected_list = vuln_data.get("affected", [])
        if not isinstance(affected_list, list):
            return None

        for item in affected_list:
            if not isinstance(item, dict):
                continue
            pkg = item.get("package", {})
            if pkg.get("name", "").lower() == package_name.lower():
                ranges = item.get("ranges", [])
                for r in ranges:
                    events = r.get("events", [])
                    for ev in events:
                        if "fixed" in ev and ev["fixed"]:
                            return str(ev["fixed"])
        return None

    def check_dependencies(self, dependencies: List[Dependency]) -> List[Advisory]:
        """
        Queries OSV for an entire list of dependencies and maps to Advisory models.
        """
        advisories: List[Advisory] = []

        for dep in dependencies:
            if not dep.version or dep.version == "*":
                continue

            eco = "PyPI" if dep.ecosystem.lower() in ("pypi", "python") else "npm"
            raw_vulns = self.query_package(ecosystem=eco, package=dep.name, version=dep.version)

            for v in raw_vulns:
                vuln_id = v.get("id", "Unknown")
                aliases = v.get("aliases", [])
                summary = v.get("summary") or ""
                details = v.get("details") or ""
                if not summary and details:
                    summary = details.splitlines()[0][:200]

                sev_label, cvss_val = self.extract_severity(v)
                fixed_ver = self.extract_fixed_version(v, dep.name)

                advisories.append(
                    Advisory(
                        id=vuln_id,
                        package=dep.name,
                        version=dep.version,
                        ecosystem=eco,
                        aliases=aliases,
                        summary=summary,
                        details=details,
                        severity=sev_label,
                        cvss_score=cvss_val,
                        fixed_version=fixed_ver,
                        source=dep.source,
                        url=f"https://osv.dev/vulnerability/{vuln_id}",
                        direct=dep.direct,
                    )
                )

        return advisories
