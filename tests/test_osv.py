"""Unit tests for OSV vulnerability API client with deterministic mocks."""

from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import requests

from reposentinel.core.models import Dependency
from reposentinel.scanners.osv_client import OSVClient


MOCK_OSV_VULN_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-72xf-g2v4-qvf3",
            "aliases": ["CVE-2023-32681"],
            "summary": "Unintended leak of Proxy-Authorization header in requests",
            "details": "When Requests makes a request with a Proxy-Authorization header, it will unintentionally leak this header.",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N/7.5"
                }
            ],
            "affected": [
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.3.0"},
                                {"fixed": "2.31.0"}
                            ]
                        }
                    ]
                }
            ]
        }
    ]
}


def test_osv_query_and_advisory_mapping(tmp_path: Path):
    cache_file = tmp_path / "test_osv_cache.json"
    client = OSVClient(cache_file=cache_file)

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = MOCK_OSV_VULN_RESPONSE
        mock_post.return_value = mock_resp

        deps = [Dependency(name="requests", version="2.30.0", ecosystem="PyPI", source="requirements.txt")]
        advisories = client.check_dependencies(deps)

        assert len(advisories) == 1
        adv = advisories[0]
        assert adv.id == "GHSA-72xf-g2v4-qvf3"
        assert adv.package == "requests"
        assert adv.version == "2.30.0"
        assert adv.severity == "High"
        assert adv.cvss_score == 7.5
        assert adv.fixed_version == "2.31.0"
        assert "CVE-2023-32681" in adv.aliases
        assert cache_file.exists()


def test_osv_cache_persistence(tmp_path: Path):
    cache_file = tmp_path / "test_osv_cache.json"
    client = OSVClient(cache_file=cache_file)

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = MOCK_OSV_VULN_RESPONSE
        mock_post.return_value = mock_resp

        # First query hits network
        res1 = client.query_package("PyPI", "requests", "2.30.0")
        assert len(res1) == 1
        assert mock_post.call_count == 1

        # Second query should hit memory cache without calling requests.post
        res2 = client.query_package("PyPI", "requests", "2.30.0")
        assert len(res2) == 1
        assert mock_post.call_count == 1

    # Reload client with same cache file
    new_client = OSVClient(cache_file=cache_file)
    with patch("requests.post") as mock_post_2:
        res3 = new_client.query_package("PyPI", "requests", "2.30.0")
        assert len(res3) == 1
        assert mock_post_2.call_count == 0


def test_osv_network_timeout_resilience(tmp_path: Path):
    client = OSVClient(cache_file=tmp_path / "cache.json")

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Connection timed out")):
        res = client.query_package("PyPI", "requests", "2.30.0")
        assert res == []


def test_osv_http_error_handling(tmp_path: Path):
    client = OSVClient(cache_file=tmp_path / "cache.json")

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_post.return_value = mock_resp

        res = client.query_package("PyPI", "requests", "2.30.0")
        assert res == []
