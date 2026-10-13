"""Unit tests for archive extraction safety and Zip-Slip vulnerability prevention."""

import io
import zipfile
from pathlib import Path
import pytest

from reposentinel.core.archive import extract_archive_safely, ArchiveSecurityError


def test_safe_zip_extraction(tmp_path: Path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("project/app.py", "print('hello world')")
        zf.writestr("project/README.md", "# Hello")

    extracted_root, temp_dir = extract_archive_safely(buffer.getvalue())
    assert (extracted_root / "app.py").exists()
    assert (extracted_root / "README.md").exists()


def test_zip_slip_path_traversal_blocked():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        # Malicious Zip-Slip entry trying to escape directory
        zf.writestr("../../../../../etc/passwd", "root:x:0:0:")

    with pytest.raises(ArchiveSecurityError) as exc_info:
        extract_archive_safely(buffer.getvalue())

    assert "traversal" in str(exc_info.value).lower() or "zip-slip" in str(exc_info.value).lower()


def test_corrupted_archive_rejected():
    garbage_bytes = b"Not a zip file at all"
    with pytest.raises(ArchiveSecurityError) as exc_info:
        extract_archive_safely(garbage_bytes)

    assert "invalid" in str(exc_info.value).lower() or "corrupted" in str(exc_info.value).lower()
