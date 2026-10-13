# Contributing to RepoSentinel AI

Thank you for your interest in contributing to **RepoSentinel AI**! We welcome community contributions to build a safer, more transparent, evidence-backed security tool for developers.

---

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment for all contributors. Please be respectful and constructive in all interactions.

---

## Development Setup

RepoSentinel AI is written in Python (3.11+) with Streamlit.

### 1. Clone & Set Up Virtual Environment

```powershell
# Clone the repository
git clone https://github.com/reposentinel-ai/reposentinel.git
cd reposentinel

# Create and activate virtual environment
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Run the Test Suite

We require all pull requests to pass the full automated test suite:

```powershell
pytest -v
```

To run the evaluation benchmark measuring precision and recall on the curated corpus:

```powershell
pytest -v -s tests/test_evaluation_corpus.py
```

### 3. Launch the Local Application

```powershell
streamlit run app.py
```

---

## Core Contribution Guidelines

### Adding New Secret Rules
- Add regex rules in `reposentinel/scanners/secrets.py`.
- Always pair rules with an appropriate `safe_redact` pattern to ensure raw secrets are never logged or exposed.
- Include unit tests in `tests/test_secrets.py` covering:
  1. Positive detection cases
  2. False positive / placeholder fixtures
  3. Redaction verification

### Improving Dependency Parsers
- Dependency parsers live in `reposentinel/scanners/dependencies.py`.
- Parsers must be resilient to malformed files and comments.
- Test against real-world sample lockfiles in `tests/test_dependencies.py`.

### Local AI & Prompt Safety
- We strictly adhere to **local open-weight AI** (Ollama). Never introduce mandatory paid cloud inference APIs.
- Treat all scanned files and repository contents as **untrusted data**.
- Wrap evidence in `<UNTRUSTED_SCANNER_EVIDENCE>` tags and maintain defensive system prompts.
- Always provide deterministic fallbacks for offline environments.

### Edge-Case Testing & Sandbox Isolation
- Generated test code must pass AST security validation in `reposentinel/testing/validator.py`.
- Never execute arbitrary code directly inside the application process. All test executions run in dedicated subprocesses with strict timeouts.

---

## Pull Request Process

1. Create a descriptive feature branch: `git checkout -b feature/my-new-rule`.
2. Commit changes with clear, concise messages.
3. Ensure `pytest` passes with 100% success.
4. Verify no secrets, `.env` files, or temporary cache files are committed.
5. Open a Pull Request detailing what was changed and why.
