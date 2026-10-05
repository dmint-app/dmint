"""Unit and security tests for OpenAI-compatible HTTP API client (src/dmint/cli/api.py)."""

from io import BytesIO
import json
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from dmint.cli.api import (
    OpenAICompatClient,
    extract_json_text,
    mask_secret,
    resolve_api_key,
    resolve_base_url,
)


class CLIAPITests(unittest.TestCase):
    def test_mask_secret(self):
        self.assertEqual(mask_secret(None), "<none>")
        self.assertEqual(mask_secret(""), "<none>")
        self.assertEqual(mask_secret("12345"), "***")
        self.assertEqual(mask_secret("sk-1234567890abcdef"), "sk-...cdef")

    def test_resolve_base_url(self):
        self.assertEqual(resolve_base_url(provider="gemini"), "https://generativelanguage.googleapis.com/v1beta/openai")
        self.assertEqual(resolve_base_url(provider="groq"), "https://api.groq.com/openai/v1")
        self.assertEqual(resolve_base_url(provider="ollama"), "http://localhost:11434/v1")
        self.assertEqual(resolve_base_url("https://custom.api.com/v1/chat/completions"), "https://custom.api.com/v1")
        self.assertEqual(resolve_base_url(), "https://api.openai.com/v1")

    def test_resolve_api_key(self):
        with patch.dict("os.environ", {"OPENAI_API_KEY": "env-key"}, clear=True):
            self.assertEqual(resolve_api_key(None), "env-key")
            self.assertEqual(resolve_api_key("explicit-key"), "explicit-key")

        with patch.dict("os.environ", {"GEMINI_API_KEY": "gemini-key"}, clear=True):
            self.assertEqual(resolve_api_key(provider="gemini"), "gemini-key")

    def test_extract_json_text(self):
        raw_json = '{\n  "rules": []\n}'
        self.assertEqual(extract_json_text(raw_json), raw_json)

        markdown_json = '```json\n{\n  "rules": []\n}\n```'
        self.assertEqual(extract_json_text(markdown_json), raw_json)

        code_fence = '```\n{\n  "rules": []\n}\n```'
        self.assertEqual(extract_json_text(code_fence), raw_json)

    @patch("urllib.request.urlopen")
    def test_successful_api_request(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"choices": [{"message": {"content": '{"rules": [{"effect": "allow", "tool": "s", "action": "r"}]}'}}]}
        ).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        client = OpenAICompatClient(api_key="sk-test-key", model="gpt-4o-mini")
        result = client.chat_completion([{"role": "user", "content": "hi"}])
        self.assertIn('"effect": "allow"', result)

    @patch("urllib.request.urlopen")
    def test_api_non_2xx_response_masks_secret(self, mock_urlopen):
        error_content = json.dumps({"error": {"message": "Invalid API key"}}).encode("utf-8")
        err = urllib.error.HTTPError(
            url="https://api.openai.com/v1/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=BytesIO(error_content),
        )
        mock_urlopen.side_effect = err

        client = OpenAICompatClient(api_key="secret_api_key_12345")
        with self.assertRaises(RuntimeError) as ctx:
            client.chat_completion([{"role": "user", "content": "hi"}])

        self.assertIn("HTTP 401", str(ctx.exception))
        self.assertNotIn("secret_api_key_12345", str(ctx.exception))
        self.assertIn("sec...2345", str(ctx.exception))

    @patch("urllib.request.urlopen")
    def test_api_timeout_handling(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("timed out")
        client = OpenAICompatClient(api_key="key", timeout=1.0)

        with self.assertRaises(RuntimeError) as ctx:
            client.chat_completion([{"role": "user", "content": "hi"}])

        self.assertIn("API connection failed", str(ctx.exception))

    @patch("urllib.request.urlopen")
    def test_malformed_json_api_response(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"NOT_JSON"
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        client = OpenAICompatClient(api_key="key")
        with self.assertRaises(RuntimeError) as ctx:
            client.chat_completion([{"role": "user", "content": "hi"}])

        self.assertIn("API response is not valid JSON", str(ctx.exception))

    @patch("urllib.request.urlopen")
    def test_list_models_successful_parse(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {
                "data": [
                    {"id": "gpt-4o"},
                    {"id": "gpt-4o-mini"},
                ]
            }
        ).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        client = OpenAICompatClient(api_key="key")
        models = client.list_models()
        self.assertEqual(models, ["gpt-4o", "gpt-4o-mini"])

    @patch("urllib.request.urlopen")
    def test_list_models_404_or_unsupported_raises_error(self, mock_urlopen):
        err = urllib.error.HTTPError(
            url="http://localhost:11434/v1/models",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=BytesIO(b'{"error": "not found"}'),
        )
        mock_urlopen.side_effect = err

        client = OpenAICompatClient(api_key="key")
        with self.assertRaises(RuntimeError) as ctx:
            client.list_models()
        self.assertIn("HTTP 404", str(ctx.exception))

    @patch("urllib.request.urlopen")
    def test_list_models_filters_non_chat_models(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {
                "data": [
                    {"id": "dall-e-3"},
                    {"id": "whisper-1"},
                    {"id": "tts-1"},
                    {"id": "text-embedding-3-small"},
                    {"id": "omni-moderation-latest"},
                    {"id": "gpt-image-2"},
                    {"id": "gpt-realtime"},
                    {"id": "babbage-002"},
                    {"id": "gpt-4o"},
                    {"id": "gpt-5.6-luna"},
                    {"id": "o3-mini"},
                    {"id": "gpt-4o-mini"},
                ]
            }
        ).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        client = OpenAICompatClient(api_key="key")
        models = client.list_models()
        self.assertIn("gpt-4o", models)
        self.assertIn("gpt-4o-mini", models)
        self.assertIn("gpt-5.6-luna", models)
        self.assertIn("o3-mini", models)
        self.assertNotIn("dall-e-3", models)
        self.assertNotIn("whisper-1", models)
        self.assertNotIn("tts-1", models)
        self.assertNotIn("text-embedding-3-small", models)
        self.assertNotIn("omni-moderation-latest", models)
        self.assertNotIn("gpt-image-2", models)
        self.assertNotIn("gpt-realtime", models)
        self.assertNotIn("babbage-002", models)

    @patch("urllib.request.urlopen")
    def test_chat_completion_temperature_retry_on_400(self, mock_urlopen):
        # 1st call fails with 400 temperature error
        err = urllib.error.HTTPError(
            url="https://api.openai.com/v1/chat/completions",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=BytesIO(
                b'{"error": {"message": "Unsupported value: \'temperature\' does not support 0.0 with this model. Only the default (1) value is supported."}}'
            ),
        )
        # 2nd call (retry without temperature) succeeds
        mock_success = MagicMock()
        mock_success.read.return_value = json.dumps(
            {"choices": [{"message": {"content": '{"type": "policy_ready", "rules": []}'}}]}
        ).encode("utf-8")
        mock_success.__enter__.return_value = mock_success

        mock_urlopen.side_effect = [err, mock_success]

        client = OpenAICompatClient(api_key="sk-test-key", model="gpt-5.6-luna")
        result = client.chat_completion([{"role": "user", "content": "hi"}], temperature=0.0)
        self.assertIn('"type": "policy_ready"', result)
        self.assertEqual(mock_urlopen.call_count, 2)
