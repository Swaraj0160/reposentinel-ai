"""Unified diff utilities and text replacement tools for remediation."""

import difflib
from typing import Optional


def generate_unified_diff(original: str, modified: str, filename: str = "target_file") -> str:
    """Generates standard unified diff between original and modified text."""
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)

    diff = difflib.unified_diff(
        orig_lines,
        mod_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm="",
    )
    return "\n".join(diff)


def apply_snippet_replacement(
    original_content: str,
    target_snippet: str,
    replacement_snippet: str,
) -> Optional[str]:
    """
    Safely replaces an exact snippet or line in the original content.
    Returns modified content, or None if target_snippet was not found.
    """
    if target_snippet in original_content:
        return original_content.replace(target_snippet, replacement_snippet, 1)

    # Line-by-line fallback with trimmed whitespace
    lines = original_content.splitlines()
    target_trimmed = target_snippet.strip()
    new_lines = []
    replaced = False

    for line in lines:
        if not replaced and line.strip() == target_trimmed:
            new_lines.append(replacement_snippet)
            replaced = True
        else:
            new_lines.append(line)

    if replaced:
        return "\n".join(new_lines) + ("\n" if original_content.endswith("\n") else "")

    return None
