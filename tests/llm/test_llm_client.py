# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.llm"  # pylint:disable=redefined-builtin

import builtins
import os
import unittest
from unittest import mock

from angr.llm_client import LLMClient

# Keep a reference to the real __import__ so our mock can delegate
_real_import = builtins.__import__


def _import_no_litellm(name, *args, **kwargs):
    """A fake __import__ that raises ImportError for litellm only."""
    if name == "litellm":
        raise ImportError("No module named 'litellm'")
    return _real_import(name, *args, **kwargs)


class TestLLMClientConstruction(unittest.TestCase):
    """Tests for LLMClient construction and from_env."""

    def test_constructor_raises_without_litellm(self):
        """LLMClient constructor should fail with ImportError when litellm is missing."""
        with mock.patch("builtins.__import__", side_effect=_import_no_litellm):
            with self.assertRaises(ImportError) as ctx:
                LLMClient(model="gpt-4")
            assert "litellm" in str(ctx.exception)

    @mock.patch.dict("sys.modules", {"litellm": mock.MagicMock()})
    def test_constructor_stores_params(self):
        """LLMClient stores all constructor parameters."""
        client = LLMClient(
            model="gpt-4",
            api_key="sk-test",
            api_base="http://localhost:8000",
            max_tokens=2048,
            temperature=0.5,
        )
        assert client.model == "gpt-4"
        assert client.api_key == "sk-test"
        assert client.api_base == "http://localhost:8000"
        assert client.max_tokens == 2048
        assert client.temperature == 0.5

    @mock.patch.dict("sys.modules", {"litellm": mock.MagicMock()})
    def test_constructor_defaults(self):
        """LLMClient has sensible defaults for optional parameters."""
        client = LLMClient(model="gpt-4")
        assert client.api_key is None
        assert client.api_base is None
        assert client.max_tokens == 4096
        assert client.temperature == 0.0

    @mock.patch.dict("sys.modules", {"litellm": mock.MagicMock()})
    def test_repr(self):
        """LLMClient repr shows the model."""
        client = LLMClient(model="gpt-4")
        assert "gpt-4" in repr(client)


class TestLLMClientFromEnv(unittest.TestCase):
    """Tests for LLMClient.from_env classmethod."""

    @mock.patch.dict("sys.modules", {"litellm": mock.MagicMock()})
    def test_from_env_returns_none_when_model_unset(self):
        """from_env returns None if ANGR_LLM_MODEL is not set."""
        env = {k: v for k, v in os.environ.items() if not k.startswith("ANGR_LLM_")}
        with mock.patch.dict(os.environ, env, clear=True):
            result = LLMClient.from_env()
            assert result is None

    @mock.patch.dict("sys.modules", {"litellm": mock.MagicMock()})
    def test_from_env_creates_client_with_model(self):
        """from_env creates an LLMClient when ANGR_LLM_MODEL is set."""
        env = {"ANGR_LLM_MODEL": "gpt-4"}
        with mock.patch.dict(os.environ, env, clear=True):
            client = LLMClient.from_env()
            assert client is not None
            assert client.model == "gpt-4"
            assert client.api_key is None
            assert client.api_base is None

    @mock.patch.dict("sys.modules", {"litellm": mock.MagicMock()})
    def test_from_env_passes_all_env_vars(self):
        """from_env reads ANGR_LLM_API_KEY and ANGR_LLM_API_BASE."""
        env = {
            "ANGR_LLM_MODEL": "ollama/llama2",
            "ANGR_LLM_API_KEY": "test-key-123",
            "ANGR_LLM_API_BASE": "http://localhost:11434",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            client = LLMClient.from_env()
            assert client is not None
            assert client.model == "ollama/llama2"
            assert client.api_key == "test-key-123"
            assert client.api_base == "http://localhost:11434"


class TestLLMClientCompletion(unittest.TestCase):
    """Tests for LLMClient.completion and completion_json."""

    @staticmethod
    def _make_mock_litellm():
        return mock.MagicMock()

    def _make_client_and_litellm(self, **kwargs):
        """Create a client with a mocked litellm module."""
        mock_litellm = self._make_mock_litellm()
        with mock.patch.dict("sys.modules", {"litellm": mock_litellm}):
            client = LLMClient(model="test-model", **kwargs)
        return client, mock_litellm

    def _set_response(self, mock_litellm, content):
        resp = mock.MagicMock()
        resp.choices = [mock.MagicMock()]
        resp.choices[0].message.content = content
        mock_litellm.completion.return_value = resp

    def test_completion_calls_litellm(self):
        """completion() calls litellm.completion with correct args."""
        client, mock_litellm = self._make_client_and_litellm(api_key="test-key")
        self._set_response(mock_litellm, "Hello world")

        messages = [{"role": "user", "content": "Hi"}]
        with mock.patch.dict("sys.modules", {"litellm": mock_litellm}):
            result = client.completion(messages)

        assert result == "Hello world"
        mock_litellm.completion.assert_called_once()
        call_kwargs = mock_litellm.completion.call_args[1]
        assert call_kwargs["model"] == "test-model"
        assert call_kwargs["api_key"] == "test-key"
        assert call_kwargs["messages"] == messages

    def test_completion_json_parses_json(self):
        """completion_json() parses a plain JSON response."""
        client, mock_litellm = self._make_client_and_litellm()
        self._set_response(mock_litellm, '{"foo": "bar"}')

        with mock.patch.dict("sys.modules", {"litellm": mock_litellm}):
            result = client.completion_json([{"role": "user", "content": "test"}])
        assert result == {"foo": "bar"}

    def test_completion_json_strips_markdown_fences(self):
        """completion_json() strips markdown code fences before parsing."""
        client, mock_litellm = self._make_client_and_litellm()
        self._set_response(mock_litellm, '```json\n{"key": "value"}\n```')

        with mock.patch.dict("sys.modules", {"litellm": mock_litellm}):
            result = client.completion_json([{"role": "user", "content": "test"}])
        assert result == {"key": "value"}

    def test_completion_json_strips_bare_fences(self):
        """completion_json() strips bare ``` fences (without json tag)."""
        client, mock_litellm = self._make_client_and_litellm()
        self._set_response(mock_litellm, '```\n{"a": 1}\n```')

        with mock.patch.dict("sys.modules", {"litellm": mock_litellm}):
            result = client.completion_json([{"role": "user", "content": "test"}])
        assert result == {"a": 1}

    def test_completion_json_returns_none_on_invalid_json(self):
        """completion_json() returns None when the response isn't valid JSON."""
        client, mock_litellm = self._make_client_and_litellm()
        self._set_response(mock_litellm, "This is not JSON at all")

        with mock.patch.dict("sys.modules", {"litellm": mock_litellm}):
            result = client.completion_json([{"role": "user", "content": "test"}])
        assert result is None

    def test_completion_json_returns_none_on_empty_response(self):
        """completion_json() returns None when the response is empty."""
        client, mock_litellm = self._make_client_and_litellm()
        self._set_response(mock_litellm, "")

        with mock.patch.dict("sys.modules", {"litellm": mock_litellm}):
            result = client.completion_json([{"role": "user", "content": "test"}])
        assert result is None

    def test_completion_without_api_key_or_base(self):
        """completion() omits api_key and api_base when not set."""
        client, mock_litellm = self._make_client_and_litellm()
        self._set_response(mock_litellm, "response")

        with mock.patch.dict("sys.modules", {"litellm": mock_litellm}):
            client.completion([{"role": "user", "content": "test"}])

        call_kwargs = mock_litellm.completion.call_args[1]
        assert "api_key" not in call_kwargs
        assert "api_base" not in call_kwargs


if __name__ == "__main__":
    unittest.main()
