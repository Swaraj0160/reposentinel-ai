# RepoSentinel AI — Reproducible 3-Minute Demo Script

This script walks through an end-to-end, reproducible 3-minute live demonstration of **RepoSentinel AI** for Hacktoberfest reviewers, evaluators, and engineers.

---

## Prerequisites (30 Seconds Setup)

In Windows PowerShell:
```powershell
cd C:\Users\asus\Desktop\Hackoberfest\reposentinel-ai
.\.venv\Scripts\Activate.ps1
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## Step 1: Overview & Environment Health (0:00 – 0:30)

1. **Observe the Header:**
   - Notice the status pill in the top-right:
     - If Ollama is running: displays `● Ollama Connected (N models)`.
     - If Ollama is not started: displays `○ Ollama Offline (Using Deterministic Fallback)` — showcasing that RepoSentinel never crashes or leaves users stranded without inference.
2. **Load the Demonstration Project:**
   - In the sidebar under **Quick Demo**, click **"Load Built-in Sample Project"**.
   - Watch the instant scan analyze the sample files and populate the executive metric cards:
     - Scanned text files
     - Detected secret findings
     - Real public OSV vulnerability matches
     - Parsed dependency count

---

## Step 2: Secret Detection & Redaction (0:30 – 1:00)

1. Click on the **🔑 Secret Findings** tab.
2. Observe the detected finding:
   - **Rule:** `AWS Access Key ID` in `src/auth.py:2`.
   - **Evidence:** `AWS_ACCESS_KEY_ID = "[REDACTED_AWS_ACCESS_KEY]"` — points out that sensitive credentials are never displayed or leaked in raw text.
3. Highlight that placeholder tokens in `src/config.js` (`example_placeholder_token_do_not_use_12345`) were filtered out intelligently by heuristic placeholder rules, avoiding false positive alert fatigue.

---

## Step 3: Verified OSV Dependency Advisories (1:00 – 1:30)

1. Click on the **📦 Dependencies (OSV)** tab.
2. Observe the real public advisories matched from the OSV database:
   - `requests` (2.28.1): affected by `GHSA-72xf-g2v4-qvf3` (CVE-2023-32681), rated High severity.
   - Shows the verified patched version: `2.31.0`.
   - `urllib3` (1.26.12): affected by `GHSA-v845-jxx5-vc9f`.
3. Note the direct clickable link to the official OSV.dev record.

---

## Step 4: Edge-Case Test Lab (1:30 – 2:15)

1. Click on the **🧪 Edge-Case Test Lab** tab.
2. The target function `calculate_percentage(obtained, maximum)` from `marks.py` is pre-loaded:
   ```python
   def calculate_percentage(obtained, maximum):
       return (obtained / maximum) * 100
   ```
3. Click **"Generate Edge-Case Tests"**:
   - The generator identifies boundary cases: zero denominator, negative numbers, invalid string inputs, and None values.
   - AST security validator verifies the code contains no disallowed modules or builtins.
4. Click **"Run Tests in Isolated Sandbox"**:
   - Tests execute in a separate subprocess with a 10-second timeout.
   - Pytest executes: notice that the zero-denominator test fails, objectively proving the unhandled division-by-zero vulnerability in the source function!

---

## Step 5: Verified Remediation Sandbox (2:15 – 2:45)

1. Click on the **🔧 Verified Remediation** tab.
2. In the dropdown, select the `[Secret] SEC-0001: AWS Access Key ID` finding.
3. Review the proposed fix:
   - Proposes extracting the credential into `os.getenv("AWS_ACCESS_KEY_ID", "")`.
   - Displays a clean unified diff (`before` vs `after`).
4. Click **"🚀 Apply Patch in Sandbox & Verify Resolution"**:
   - A copy of the repository is created in a temporary sandbox.
   - The proposed patch is applied in isolation.
   - The secret scanner re-scans the patched copy.
   - Displays: `✅ VERIFIED: Secret scanner confirmed the credential was eliminated from the patched file.`
   - Emphasize: **The original repository was never modified without developer approval.**

---

## Step 6: Multi-Format Audit Export (2:45 – 3:00)

1. Click on the **📊 Export Center** tab.
2. Demonstrate one-click download buttons:
   - `Download JSON Report` (structured schema)
   - `Download Markdown Report` (formatted for GitHub PRs)
   - `Download SARIF v2.1.0 Report` (standard format directly ingestible into GitHub Advanced Security)
3. Conclude: RepoSentinel provides an end-to-end, evidence-backed security workflow powered by deterministic scanners, local open-weight AI, and verifiable sandboxing.
