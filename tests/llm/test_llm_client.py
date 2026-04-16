# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.llm"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

from pydantic import BaseModel

from angr.llm_client import LLMClient


class TestLLMClientFromEnv(unittest.TestCase):
    """Tests for LLMClient.from_env classmethod."""

    @mock.patch("angr.llm_client.Agent", mock.MagicMock())
    def test_from_env_returns_none_when_model_unset(self):
        """from_env returns None if ANGR_LLM_MODEL is not set."""
        env = {k: v for k, v in os.environ.items() if not k.startswith("ANGR_LLM_")}
        with mock.patch.dict(os.environ, env, clear=True):
            result = LLMClient.from_env()
            assert result is None

    @mock.patch("angr.llm_client.Agent", mock.MagicMock())
    def test_from_env_creates_client_with_model(self):
        """from_env creates an LLMClient when ANGR_LLM_MODEL is set."""
        env = {"ANGR_LLM_MODEL": "gpt-4"}
        with mock.patch.dict(os.environ, env, clear=True):
            client = LLMClient.from_env()
            assert client is not None
            assert client.model == "gpt-4"
            assert client.api_key is None
            assert client.api_base is None

    @mock.patch("angr.llm_client.Agent", mock.MagicMock())
    def test_from_env_passes_all_env_vars(self):
        """from_env reads ANGR_LLM_API_KEY and ANGR_LLM_API_BASE."""
        env = {
            "ANGR_LLM_MODEL": "ollama/llama2",
            "ANGR_LLM_API_KEY": "test-key-123",
            "ANGR_LLM_API_BASE": "http://localhost:11434",
        }
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("angr.llm_client.OpenAIProvider"),
            mock.patch("angr.llm_client.OpenAIChatModel"),
        ):
            client = LLMClient.from_env()
            assert client is not None
            assert client.model == "ollama/llama2"
            assert client.api_key == "test-key-123"
            assert client.api_base == "http://localhost:11434"


class TestLLMClientCompletion(unittest.TestCase):
    """Tests for LLMClient.completion, completion_structured, and completion_json."""

    def _make_client(self, **kwargs):
        """Create a client with mocked Agent."""
        with mock.patch("angr.llm_client.Agent", mock.MagicMock()):
            return LLMClient(model="test-model", **kwargs)

    def test_completion_calls_agent(self):
        """completion() creates an Agent and calls run_sync."""
        client = self._make_client(api_key="test-key")

        mock_result = mock.MagicMock()
        mock_result.output = "Hello world"
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        messages = [{"role": "user", "content": "Hi"}]
        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            result = client.completion(messages)

        assert result == "Hello world"
        mock_agent_instance.run_sync.assert_called_once()

    def test_completion_structured_returns_model(self):
        """completion_structured() returns a validated Pydantic model."""

        class TestOutput(BaseModel):
            name: str

        client = self._make_client()

        expected = TestOutput(name="test")
        mock_result = mock.MagicMock()
        mock_result.output = expected
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        messages = [{"role": "user", "content": "test"}]
        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            result = client.completion_structured(messages, output_type=TestOutput)

        assert result is not None
        assert result == expected
        assert result.name == "test"

    def test_completion_structured_returns_none_on_failure(self):
        """completion_structured() returns None when the agent raises."""

        class TestOutput(BaseModel):
            name: str

        client = self._make_client()

        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.side_effect = RuntimeError("LLM failed")

        messages = [{"role": "user", "content": "test"}]
        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            result = client.completion_structured(messages, output_type=TestOutput)

        assert result is None

    def test_completion_json_parses_json(self):
        """completion_json() parses a plain JSON response."""
        client = self._make_client()

        mock_result = mock.MagicMock()
        mock_result.output = '{"foo": "bar"}'
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            result = client.completion_json([{"role": "user", "content": "test"}])
        assert result == {"foo": "bar"}

    def test_completion_json_strips_markdown_fences(self):
        """completion_json() strips markdown code fences before parsing."""
        client = self._make_client()

        mock_result = mock.MagicMock()
        mock_result.output = '```json\n{"key": "value"}\n```'
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            result = client.completion_json([{"role": "user", "content": "test"}])
        assert result == {"key": "value"}

    def test_completion_json_returns_none_on_invalid_json(self):
        """completion_json() returns None when the response isn't valid JSON."""
        client = self._make_client()

        mock_result = mock.MagicMock()
        mock_result.output = "This is not JSON at all"
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            result = client.completion_json([{"role": "user", "content": "test"}])
        assert result is None

    def test_completion_json_returns_none_on_empty_response(self):
        """completion_json() returns None when the response is empty."""
        client = self._make_client()

        mock_result = mock.MagicMock()
        mock_result.output = ""
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            result = client.completion_json([{"role": "user", "content": "test"}])
        assert result is None

    def test_model_with_api_base_uses_openai_provider(self):
        """When api_base is set, OpenAIProvider and OpenAIChatModel are used."""
        with (
            mock.patch("angr.llm_client.Agent", mock.MagicMock()),
            mock.patch("angr.llm_client.OpenAIProvider") as mock_provider,
            mock.patch("angr.llm_client.OpenAIChatModel") as mock_chat_model,
        ):
            client = LLMClient(model="my-model", api_base="http://localhost:1234", api_key="sk-test")
            mock_provider.assert_called_once_with(base_url="http://localhost:1234", api_key="sk-test")
            mock_chat_model.assert_called_once_with("my-model", provider=mock_provider.return_value)
            assert client._pydantic_model == mock_chat_model.return_value


if __name__ == "__main__":
    unittest.main()
