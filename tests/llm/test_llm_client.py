# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.llm"  # pylint:disable=redefined-builtin

import os
import asyncio
import unittest
from unittest import mock

from mcp.types import (
    CreateMessageResult,
    CreateMessageRequestParams,
    SamplingMessage,
    TextContent,
    ErrorData,
    ImageContent,
)
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


class TestLLMClientMCPSampling(unittest.TestCase):
    """Tests for LLMClient.create_message (MCP sampling callback)."""

    def _make_client(self, **kwargs):
        with mock.patch("angr.llm_client.Agent", mock.MagicMock()):
            return LLMClient(model="test-model", **kwargs)

    def _make_params(self, text="Hello", system_prompt=None, temperature=None, max_tokens=100, stop_sequences=None):
        return CreateMessageRequestParams(
            messages=[SamplingMessage(role="user", content=TextContent(type="text", text=text))],
            systemPrompt=system_prompt,
            temperature=temperature,
            maxTokens=max_tokens,
            stopSequences=stop_sequences,
        )

    def _run_async(self, coro):
        return asyncio.run(coro)

    def test_create_message_returns_text_result(self):
        """create_message returns a CreateMessageResult with the LLM output."""
        client = self._make_client()

        mock_result = mock.MagicMock()
        mock_result.output = "The capital of France is Paris."
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        ctx = mock.MagicMock()
        params = self._make_params(text="What is the capital of France?")

        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            result = self._run_async(client.create_message(ctx, params))

        assert isinstance(result, CreateMessageResult)
        assert result.role == "assistant"
        assert isinstance(result.content, TextContent)
        assert result.content.text == "The capital of France is Paris."
        assert result.model == "test-model"
        assert result.stopReason == "endTurn"

    def test_create_message_includes_system_prompt(self):
        """create_message prepends the system prompt to the prompt text."""
        client = self._make_client()

        mock_result = mock.MagicMock()
        mock_result.output = "ok"
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        ctx = mock.MagicMock()
        params = self._make_params(text="Hi", system_prompt="You are helpful.")

        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            self._run_async(client.create_message(ctx, params))

        call_args = mock_agent_instance.run_sync.call_args
        prompt = call_args[0][0]
        assert "[system]\nYou are helpful." in prompt
        assert "[user]\nHi" in prompt

    def test_create_message_uses_request_temperature(self):
        """create_message honours temperature from the request params over client default."""
        client = self._make_client(temperature=0.0)

        mock_result = mock.MagicMock()
        mock_result.output = "ok"
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        ctx = mock.MagicMock()
        params = self._make_params(text="Hi", temperature=0.7)

        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            self._run_async(client.create_message(ctx, params))

        call_args = mock_agent_instance.run_sync.call_args
        model_settings = call_args[1]["model_settings"]
        assert model_settings["temperature"] == 0.7

    def test_create_message_falls_back_to_client_temperature(self):
        """create_message uses client temperature when request doesn't specify one."""
        client = self._make_client(temperature=0.5)

        mock_result = mock.MagicMock()
        mock_result.output = "ok"
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        ctx = mock.MagicMock()
        params = self._make_params(text="Hi", temperature=None)

        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            self._run_async(client.create_message(ctx, params))

        call_args = mock_agent_instance.run_sync.call_args
        model_settings = call_args[1]["model_settings"]
        assert model_settings["temperature"] == 0.5

    def test_create_message_passes_stop_sequences(self):
        """create_message forwards stop sequences to model settings."""
        client = self._make_client()

        mock_result = mock.MagicMock()
        mock_result.output = "ok"
        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.return_value = mock_result

        ctx = mock.MagicMock()
        params = self._make_params(text="Hi", stop_sequences=["STOP", "END"])

        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            self._run_async(client.create_message(ctx, params))

        call_args = mock_agent_instance.run_sync.call_args
        model_settings = call_args[1]["model_settings"]
        assert model_settings["stop_sequences"] == ["STOP", "END"]

    def test_create_message_returns_error_on_exception(self):
        """create_message returns ErrorData when the LLM call fails."""
        client = self._make_client()

        mock_agent_instance = mock.MagicMock()
        mock_agent_instance.run_sync.side_effect = RuntimeError("LLM exploded")

        ctx = mock.MagicMock()
        params = self._make_params(text="Hi")

        with mock.patch("angr.llm_client.Agent", return_value=mock_agent_instance):
            result = self._run_async(client.create_message(ctx, params))

        assert isinstance(result, ErrorData)
        assert "LLM exploded" in result.message

    def test_create_message_returns_error_on_empty_content(self):
        """create_message returns ErrorData when no text content is present."""
        client = self._make_client()

        params = CreateMessageRequestParams(
            messages=[
                SamplingMessage(
                    role="user",
                    content=ImageContent(type="image", data="abc", mimeType="image/png"),
                )
            ],
            maxTokens=100,
        )
        ctx = mock.MagicMock()

        with mock.patch("angr.llm_client.Agent", mock.MagicMock()):
            result = self._run_async(client.create_message(ctx, params))

        assert isinstance(result, ErrorData)
        assert "No text content" in result.message


if __name__ == "__main__":
    unittest.main()
