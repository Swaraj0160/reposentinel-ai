# Third-Party Licenses and Notices

This document details the licensing terms for RepoSentinel AI, its dependencies, third-party libraries, local AI models, and upstream data sources.

---

## 1. RepoSentinel AI Original Code

- **License:** MIT License
- **Copyright:** (c) 2026 RepoSentinel AI contributors
- **Text:** See [LICENSE](LICENSE)

---

## 2. Python Dependencies

| Package | Version Range | License | Description |
| :--- | :--- | :--- | :--- |
| `streamlit` | `>=1.39, <2` | **Apache-2.0** | Interactive web application framework |
| `requests` | `>=2.32, <3` | **Apache-2.0** | HTTP library for OSV.dev and Ollama queries |
| `pytest` | `>=8.0, <10` | **MIT** | Automated test suite and sandbox runner |
| `pandas` | (transitive) | **BSD-3-Clause** | Tabular data representation |
| `numpy` | (transitive) | **BSD-3-Clause** | Numerical computing |
| `altair` | (transitive) | **BSD-3-Clause** | Declarative charting library |
| `pyarrow` | (transitive) | **Apache-2.0** | Columnar memory formatting |
| `jinja2` | (transitive) | **BSD-3-Clause** | Template engine |
| `jsonschema` | (transitive) | **MIT** | JSON schema validation |
| `certifi` | (transitive) | **MPL-2.0** | Mozilla CA certificate bundle |
| `urllib3` | (transitive) | **MIT** | Low-level HTTP client |
| `click` | (transitive) | **BSD-3-Clause** | CLI creation kit |
| `packaging` | (transitive) | **Apache-2.0 / BSD-2-Clause** | Version handling utility |

---

## 3. Recommended Open-Weight AI Models

RepoSentinel AI interfaces with locally hosted models running via Ollama. No proprietary cloud inference models are required.

| Model | Default Identifier | Developer / Provider | License | Notice / Usage Terms |
| :--- | :--- | :--- | :--- | :--- |
| **Qwen2.5-Coder** | `qwen2.5-coder:7b` | Alibaba Cloud | **Apache-2.0** | Permissive open-source code generation model. Can be used and adapted freely under Apache 2.0 terms. |
| **Llama 3.2** | `llama3.2:3b` | Meta AI | **Llama 3.2 Community License** | Permissive open-weight license with attribution and acceptable use policy. |
| **DeepSeek-Coder-V2** | `deepseek-coder-v2` | DeepSeek | **MIT** | Open-source code intelligence model. |

---

## 4. Local AI Runtime

- **Ollama:** Open-source local model runtime.
  - **License:** MIT License
  - **Repository:** `https://github.com/ollama/ollama`

---

## 5. Vulnerability Data Source

- **OSV (Open Source Vulnerabilities):**
  - **Provider:** Google / Open Source Security Foundation (OpenSSF).
  - **Data License:** Vulnerability advisory entries aggregated in OSV are licensed under **Creative Commons Attribution 4.0 International (CC-BY 4.0)** or the terms of the respective upstream database (GitHub Security Advisories, PyPI Advisory DB, RustSec, etc.).
  - **Endpoint:** `https://api.osv.dev`
