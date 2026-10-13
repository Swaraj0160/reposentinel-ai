"""Safe archive handling with Zip-slip path traversal protection."""

import io
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Tuple

from reposentinel.core.config import MAX_FILE_BYTES, MAX_ARCHIVE_BYTES


class ArchiveSecurityError(Exception):
    """Raised when an archive contains suspicious paths or exceeds size bounds."""
    pass


def extract_archive_safely(archive_bytes: bytes) -> Tuple[Path, str]:
    """
    Safely extract a ZIP archive into a temporary directory.
    
    Protections:
    - Verifies overall uncompressed size does not exceed MAX_ARCHIVE_BYTES (zip bomb defense).
    - Verifies individual file size does not exceed MAX_FILE_BYTES.
    - Prevents Zip-Slip path traversal attacks by validating resolved destination paths.
    - Rejects absolute paths, '..' components, and symlinks targeting outside.
    
    Returns:
        (extracted_root_path, temp_dir_path)
    """
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ArchiveSecurityError(
            f"Archive file size ({len(archive_bytes)} bytes) exceeds the safety limit of {MAX_ARCHIVE_BYTES} bytes."
        )

    temp_dir = tempfile.mkdtemp(prefix="reposentinel_extract_")
    root_path = Path(temp_dir).resolve()

    total_uncompressed = 0

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            for member in zf.infolist():
                total_uncompressed += member.file_size
                if total_uncompressed > MAX_ARCHIVE_BYTES:
                    raise ArchiveSecurityError("Archive exceeds uncompressed size safety threshold (possible zip-bomb).")

                if member.file_size > MAX_FILE_BYTES:
                    # Skip oversized files inside the archive
                    continue

                # Clean and resolve the member path
                raw_filename = member.filename
                # Normalize slashes
                clean_name = os.path.normpath(raw_filename)

                # Disallow drive letters or absolute components
                if os.path.isabs(clean_name) or clean_name.startswith("..") or "/../" in raw_filename or "\\..\\" in raw_filename:
                    raise ArchiveSecurityError(f"Disallowed path traversal sequence in archive: {member.filename}")

                target = (root_path / clean_name).resolve()

                # Verify target is strictly within root_path
                try:
                    target.relative_to(root_path)
                except ValueError:
                    raise ArchiveSecurityError(f"Zip-slip path traversal attempt detected: {member.filename}")

                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as source, open(target, "wb") as dest:
                        shutil.copyfileobj(source, dest)

        # Check if the archive contains exactly one top-level folder
        children = [c for c in root_path.iterdir() if not c.name.startswith(".")]
        if len(children) == 1 and children[0].is_dir():
            return children[0], temp_dir
        return root_path, temp_dir

    except (zipfile.BadZipFile, ArchiveSecurityError) as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        if isinstance(exc, ArchiveSecurityError):
            raise
        raise ArchiveSecurityError(f"Invalid or corrupted ZIP archive: {exc}")
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise ArchiveSecurityError(f"Failed to extract archive: {exc}")
