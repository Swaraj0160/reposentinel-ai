"""Central configuration and constants for RepoSentinel AI."""

import os
from pathlib import Path

APP_NAME = "RepoSentinel AI"
VERSION = "1.0.0"
DESCRIPTION = "Open-source AI-assisted developer security and edge-case testing tool."

# File Scanning Limits & Safeguards
MAX_FILE_BYTES = 1_000_000  # 1 MB per file
MAX_ARCHIVE_BYTES = 50_000_000  # 50 MB total archive
MAX_TEXT_LINES = 10_000

SKIP_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    ".next",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".cache",
    "target",
    "vendor",
    "bin",
    "obj",
    ".idea",
    ".vscode",
}

TEXT_EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".md",
    ".sh",
    ".bash",
    ".zsh",
    ".go",
    ".java",
    ".php",
    ".rb",
    ".rs",
    ".c",
    ".cpp",
    ".h",
    ".cs",
    ".sql",
    ".txt",
    ".xml",
    ".properties",
    ".pem",
    ".key",
    ".crt",
    ".cert",
    ".pub",
}

CONFIG_FILENAMES = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".env.test",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Procfile",
    "id_rsa",
    "id_dsa",
    "id_ed25519",
}

# Local AI Configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "180"))

# Vulnerability Database (OSV)
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = int(os.getenv("OSV_TIMEOUT_SECONDS", "10"))
OSV_CACHE_FILE = Path(os.getenv("REPOSENTINEL_CACHE_DIR", tempfile_cache := Path(os.path.expanduser("~")) / ".reposentinel" / "osv_cache.json"))

# Test Execution Limits
TEST_EXECUTION_TIMEOUT = int(os.getenv("TEST_TIMEOUT_SECONDS", "10"))
