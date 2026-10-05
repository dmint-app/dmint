"""Minimal OpenAI-compatible HTTP API client using Python standard library only.

Supports OpenAI, Google Gemini, Groq, OpenRouter, Ollama, and custom OpenAI-compatible endpoints.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Mapping

from dmint.cli.limits import MAX_HTTP_RESPONSE_SIZE_BYTES
from dmint.cli.version import get_user_agent

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"


def mask_secret(secret: str | None) -> str:
    """Return a safely redacted representation of a secret string."""
    if not secret:
        return "<none>"
    if len(secret) <= 8:
        return "***"
    return f"{secret[:3]}...{secret[-4:]}"


def resolve_base_url(base_url: str | None = None, provider: str | None = None) -> str:
    """Resolve the target base URL for OpenAI-compatible completions API."""
    if provider:
        prov = provider.lower().strip()
        if prov in {"gemini", "google"}:
            return GEMINI_BASE_URL
        if prov == "groq":
            return "https://api.groq.com/openai/v1"
        if prov == "openrouter":
            return "https://openrouter.ai/api/v1"
        if prov == "ollama":
            return "http://localhost:11434/v1"

    if base_url:
        url = base_url.strip().rstrip("/")
        if url.endswith("/chat/completions"):
            return url[: -len("/chat/completions")]
        return url

    return DEFAULT_BASE_URL


def resolve_api_key(api_key: str | None = None, provider: str | None = None) -> str | None:
    """Resolve API key from parameter or standard environment variables."""
    if api_key and api_key.strip():
        return api_key.strip()

    prov = (provider or "").lower().strip()
    if prov in {"gemini", "google"}:
        env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if env_key:
            return env_key.strip()
    elif prov == "groq":
        env_key = os.environ.get("GROQ_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if env_key:
            return env_key.strip()

    # Fallback to OPENAI_API_KEY
    env_openai = os.environ.get("OPENAI_API_KEY")
    if env_openai:
        return env_openai.strip()
    return None


def is_chat_text_model(model_id: str) -> bool:
    """Filter out non-text and non-chat model IDs (image, audio, embedding, moderation, etc.)."""
    mid = model_id.lower()
    excluded_keywords = (
        "embedding",
        "image",
        "dall-e",
        "sora",
        "tts",
        "whisper",
        "audio",
        "transcribe",
        "realtime",
        "moderation",
        "canary",
        "babbage",
        "davinci",
        "curie",
        "ada",
    )
    if any(kw in mid for kw in excluded_keywords):
        return False
    return True


def sort_models(models: list[str]) -> list[str]:
    """Sort models prioritizing modern chat/reasoning flagships, then non-dated aliases, then dated snapshots."""
    priority = [
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-5",
        "gpt-5-mini",
        "gpt-5.6-luna",
        "o3-mini",
        "o1",
        "o4-mini",
        "gpt-4.1-mini",
        "gpt-4.1",
        "gpt-4-turbo",
        "gpt-4",
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "gpt-3.5-turbo",
    ]
    p_map = {m: i for i, m in enumerate(priority)}

    def key_fn(m: str):
        if m in p_map:
            return (0, p_map[m], m)
        has_date = bool(re.search(r"\d{4}-\d{2}-\d{2}|\d{6}", m))
        return (2 if has_date else 1, 0, m)

    return sorted(models, key=key_fn)


class OpenAICompatClient:
    """Standard-library HTTP client targeting OpenAI-compatible /chat/completions endpoints."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = resolve_base_url(base_url, provider)
        self.api_key = resolve_api_key(api_key, provider)
        self.model = model or DEFAULT_MODEL
        self.timeout = timeout

    def _execute_request(
        self,
        endpoint: str,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Execute HTTP POST request and return parsed JSON response."""
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            resp_bytes = resp.read(MAX_HTTP_RESPONSE_SIZE_BYTES + 1)
            if len(resp_bytes) > MAX_HTTP_RESPONSE_SIZE_BYTES:
                raise RuntimeError(
                    f"Resource exhaustion error: API response exceeded maximum size limit of {MAX_HTTP_RESPONSE_SIZE_BYTES} bytes."
                )
            try:
                return json.loads(resp_bytes.decode("utf-8"))
            except Exception as exc:
                raise RuntimeError("API response is not valid JSON") from exc

    def chat_completion(
        self,
        messages: list[Mapping[str, Any]],
        *,
        temperature: float = 0.0,
        response_format: Mapping[str, Any] | None = None,
    ) -> str:
        """Send a chat completion request and return the assistant response content string."""
        endpoint = f"{self.base_url}/chat/completions"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
        }
        if response_format:
            payload["response_format"] = response_format

        model_lower = (self.model or "").lower()
        # Reasoning models (e.g. o1, o3, o4) reject custom temperature values
        is_known_reasoning = any(model_lower.startswith(p) for p in ("o1", "o3", "o4")) or "reasoning" in model_lower
        if temperature is not None and not is_known_reasoning:
            payload["temperature"] = temperature

        headers = {
            "Content-Type": "application/json",
            "User-Agent": get_user_agent("policy-author"),
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            resp_data = self._execute_request(endpoint, payload, headers)
        except urllib.error.HTTPError as exc:
            try:
                error_body = exc.read(65536).decode("utf-8", errors="ignore")
                error_json = json.loads(error_body)
                msg = error_json.get("error", {}).get("message", error_body)
            except Exception:
                msg = f"HTTP Error {exc.code}"

            # Auto-retry if temperature is rejected by the model (e.g. gpt-5.6-luna or reasoning models)
            if exc.code == 400 and "temperature" in msg.lower() and "temperature" in payload:
                try:
                    payload_no_temp = dict(payload)
                    del payload_no_temp["temperature"]
                    resp_data = self._execute_request(endpoint, payload_no_temp, headers)
                except urllib.error.HTTPError as retry_exc:
                    try:
                        retry_body = retry_exc.read(65536).decode("utf-8", errors="ignore")
                        retry_json = json.loads(retry_body)
                        retry_msg = retry_json.get("error", {}).get("message", retry_body)
                    except Exception:
                        retry_msg = f"HTTP Error {retry_exc.code}"
                    masked_key = mask_secret(self.api_key)
                    raise RuntimeError(
                        f"OpenAI-compatible API HTTP {retry_exc.code}: {retry_msg} (key: {masked_key})"
                    ) from retry_exc
            else:
                masked_key = mask_secret(self.api_key)
                raise RuntimeError(f"OpenAI-compatible API HTTP {exc.code}: {msg} (key: {masked_key})") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"API connection failed ({self.base_url}): {exc.reason}") from exc
        except Exception as exc:
            raise RuntimeError(f"API request failed: {exc}") from exc

        choices = resp_data.get("choices")
        if not choices or not isinstance(choices, list):
            raise RuntimeError("API response missing 'choices' array")

        message = choices[0].get("message", {})
        content = message.get("content")
        if content is None:
            content = ""

        return extract_json_text(content)

    def list_models(self) -> list[str]:
        """Call GET {base_url}/models and return a list of available model IDs filtered to chat/text models."""
        endpoint = f"{self.base_url}/models"
        headers = {
            "User-Agent": get_user_agent("policy-author"),
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(
            endpoint,
            headers=headers,
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_bytes = resp.read(MAX_HTTP_RESPONSE_SIZE_BYTES + 1)
                if len(resp_bytes) > MAX_HTTP_RESPONSE_SIZE_BYTES:
                    raise RuntimeError(
                        f"Resource exhaustion error: API response exceeded maximum size limit of {MAX_HTTP_RESPONSE_SIZE_BYTES} bytes."
                    )
                try:
                    resp_data = json.loads(resp_bytes.decode("utf-8"))
                except Exception as exc:
                    raise RuntimeError("API response is not valid JSON") from exc
        except urllib.error.HTTPError as exc:
            try:
                error_body = exc.read(65536).decode("utf-8", errors="ignore")
                error_json = json.loads(error_body)
                msg = error_json.get("error", {}).get("message", error_body)
            except Exception:
                msg = f"HTTP Error {exc.code}"
            masked_key = mask_secret(self.api_key)
            raise RuntimeError(f"OpenAI-compatible API HTTP {exc.code}: {msg} (key: {masked_key})") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"API connection failed ({self.base_url}): {exc.reason}") from exc
        except Exception as exc:
            raise RuntimeError(f"API request failed: {exc}") from exc

        data = resp_data.get("data")
        if not isinstance(data, list):
            raise RuntimeError("API response missing 'data' array in models response")

        models: list[str] = []
        for item in data:
            if isinstance(item, dict) and "id" in item and isinstance(item["id"], str):
                models.append(item["id"])

        if not models:
            raise RuntimeError("No model IDs found in /models response")

        chat_models = [m for m in models if is_chat_text_model(m)]
        res = chat_models if chat_models else models
        return sort_models(res)


def extract_json_text(text: str) -> str:
    """Extract clean JSON text, removing markdown code fences if present."""
    text = text.strip()
    if text.startswith("```"):
        # Match ```json ... ``` or ``` ... ```
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return text
