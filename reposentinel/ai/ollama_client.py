"""Ollama API integration for local open-weight model inference."""

import logging
from typing import List, Dict, Any, Optional, Tuple

import requests

from reposentinel.core.config import OLLAMA_URL, DEFAULT_MODEL, OLLAMA_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client for locally running Ollama instance."""

    def __init__(self, base_url: str = OLLAMA_URL, timeout: int = OLLAMA_TIMEOUT_SECONDS):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def check_connection(self) -> Tuple[bool, str]:
        """
        Tests whether the Ollama server is running and reachable.
        Returns: (is_reachable, message_or_error)
        """
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if resp.status_code == 200:
                return True, "Connected to local Ollama service"
            return False, f"Ollama returned HTTP {resp.status_code}"
        except requests.exceptions.ConnectionError:
            return False, f"Cannot connect to Ollama at {self.base_url}. Service is not running."
        except requests.exceptions.Timeout:
            return False, f"Connection to Ollama at {self.base_url} timed out."
        except Exception as exc:
            return False, f"Ollama error: {exc}"

    def list_models(self) -> List[str]:
        """Returns the list of locally pulled Ollama models."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=4)
            if resp.status_code == 200:
                data = resp.json()
                models = data.get("models", [])
                return [m.get("name", "") for m in models if "name" in m]
        except Exception as exc:
            logger.debug(f"Could not retrieve Ollama models: {exc}")
        return []

    def is_model_installed(self, model_name: str) -> bool:
        """Checks whether a specific model name is available locally."""
        installed = self.list_models()
        installed_lower = [m.lower() for m in installed]
        target = model_name.strip().lower()
        if target in installed_lower:
            return True
        # If user supplied model without tag, check if any tag of this model exists
        if ":" not in target:
            return any(m.startswith(f"{target}:") for m in installed_lower)
        # If tag is latest, check if base model is present
        base, tag = target.split(":", 1)
        if tag == "latest":
            return base in installed_lower
        return False

    def generate(
        self,
        prompt: str,
        model: str = DEFAULT_MODEL,
        format_json: bool = False,
        temperature: float = 0.1,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Requests completion from Ollama.
        
        Returns:
            (completion_text, error_message)
        """
        payload: Dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        if format_json:
            payload["format"] = "json"

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                result = data.get("response", "").strip()
                return result, None
            elif resp.status_code == 404:
                return None, f"Model '{model}' is not pulled in Ollama. Run: ollama pull {model}"
            else:
                return None, f"Ollama HTTP error {resp.status_code}: {resp.text[:200]}"
        except requests.exceptions.ConnectionError:
            return None, f"Could not connect to Ollama at {self.base_url}. Run 'ollama serve' first."
        except requests.exceptions.Timeout:
            return None, f"Inference timed out after {self.timeout} seconds."
        except Exception as exc:
            return None, f"Ollama request error: {exc}"
