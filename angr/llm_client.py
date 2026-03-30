# pylint:disable=unused-argument,import-outside-toplevel
from __future__ import annotations

import json
import logging
import os
import re
from typing import TypeVar, TYPE_CHECKING, Any

from angr.errors import AngrAIError

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings
    from pydantic_ai.providers import Provider
    from mcp.shared.context import RequestContext
    from mcp.client.session import ClientSession
    from mcp.types import CreateMessageRequestParams, CreateMessageResult, ErrorData

T = TypeVar("T")

l = logging.getLogger(name=__name__)

Agent = None
OpenAIChatModel = None
OpenAIProvider = None


class LLMClient:
    """
    A client for interacting with LLMs via pydantic-ai.
    Used by the decompiler to suggest improved variable names, function names, and types.
    """

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        api_base: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ):
        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._pydantic_model: Model | str = self._build_model()

    def infer_provider(self, provider: str) -> Provider[Any]:
        """Infer the provider from the provider name."""
        if provider.startswith("gateway/"):
            from pydantic_ai.providers.gateway import gateway_provider  # type: ignore

            upstream_provider = provider.removeprefix("gateway/")
            return gateway_provider(upstream_provider)
        if provider in ("google-vertex", "google-gla"):
            from pydantic_ai.providers.google import GoogleProvider

            return GoogleProvider(vertexai=provider == "google-vertex")
        from pydantic_ai.providers import infer_provider_class

        provider_class = infer_provider_class(provider)
        return provider_class(api_key=self.api_key)  # type: ignore

    def _build_model(self) -> Model | str:
        """Build a pydantic-ai model object from the configured settings."""
        if self.api_base:
            global OpenAIChatModel, OpenAIProvider

            if OpenAIChatModel is None or OpenAIProvider is None:
                from pydantic_ai.models.openai import OpenAIChatModel  # type: ignore
                from pydantic_ai.providers.openai import OpenAIProvider  # type: ignore

            provider = OpenAIProvider(base_url=self.api_base, api_key=self.api_key or "no-key")
            return OpenAIChatModel(self.model, provider=provider)

        from pydantic_ai.models import infer_model

        model_name = self.model
        if ":" not in model_name:
            return self.model

        return infer_model(
            model_name,
            provider_factory=self.infer_provider,  # type:ignore
        )  # pylint:disable=unexpected-keyword-arg

    @classmethod
    def from_env(cls) -> LLMClient | None:
        """
        Create an LLMClient from environment variables.

        Uses ANGR_LLM_MODEL (required), ANGR_LLM_API_KEY (optional), and ANGR_LLM_API_BASE (optional).
        Returns None if ANGR_LLM_MODEL is not set.
        """
        model = os.environ.get("ANGR_LLM_MODEL")
        if not model:
            return None
        api_key = os.environ.get("ANGR_LLM_API_KEY")
        api_base = os.environ.get("ANGR_LLM_API_BASE")
        return cls(model=model, api_key=api_key, api_base=api_base)

    def _model_settings(self) -> ModelSettings:
        from pydantic_ai.settings import ModelSettings  # type:ignore

        return ModelSettings(temperature=self.temperature, max_tokens=self.max_tokens)

    def completion(self, messages: list[dict[str, str]], **kwargs) -> str:  # pylint:disable=unused-argument
        """
        Call the LLM with the given messages and return the response text.
        """

        global Agent

        if Agent is None:
            try:
                from pydantic_ai import Agent  # type: ignore
            except ImportError:
                raise ImportError(
                    "pydantic-ai is required for LLM support. You can install it with: pip install angr[llm] or "
                    "pip install pydantic-ai"
                ) from None

        prompt = "\n\n".join(m["content"] for m in messages if m.get("content"))
        agent = Agent(self._pydantic_model, output_type=str)
        result = agent.run_sync(prompt, model_settings=self._model_settings())
        return result.output

    def completion_structured(
        self, messages: list[dict[str, str]], output_type: type[T], raise_exc: bool = False, **kwargs
    ) -> T | None:
        """
        Call the LLM with the given messages and return a validated Pydantic model.
        Returns None if the call fails.

        :param raise_exc:   If True, exceptions are propagated to the caller instead of being caught.
        """

        global Agent

        try:
            if Agent is None:
                from pydantic_ai import Agent  # type: ignore
            from pydantic_ai import UserError
        except ImportError:
            raise ImportError(
                "pydantic-ai is required for LLM support. You can install it with: pip install angr[llm] or "
                "pip install pydantic-ai"
            ) from None

        prompt = "\n\n".join(m["content"] for m in messages if m.get("content"))
        try:
            agent = Agent(self._pydantic_model, output_type=output_type)
            result = agent.run_sync(prompt, model_settings=self._model_settings())
            return result.output
        except UserError as ex:
            if raise_exc:
                raise AngrAIError("Failed to get structured LLM response due to a user error.") from ex
            l.error("Failed to get structured LLM response due to a user error.", exc_info=True)
        except Exception as ex:  # pylint:disable=broad-exception-caught
            if raise_exc:
                raise AngrAIError("Failed to get structured LLM response") from ex
            l.warning("Failed to get structured LLM response", exc_info=True)
        return None

    def completion_json(self, messages: list[dict[str, str]], raise_exc: bool = False, **kwargs) -> dict | None:
        """
        Call the LLM and parse the response as JSON.
        Strips markdown code fences if present. Returns None on parse failure.
        Kept for backwards compatibility; prefer completion_structured().

        :param raise_exc:   If True, exceptions are propagated to the caller instead of being caught.
        """
        text = self.completion(messages, **kwargs)
        if not text:
            return None

        # strip markdown code fences
        text = text.strip()
        text = re.sub(r"^```(?:json)?\s*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
        text = text.strip()

        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError) as ex:
            if raise_exc:
                raise AngrAIError("Failed to parse LLM response as JSON") from ex
            l.warning("Failed to parse LLM response as JSON: %s", text[:200])
            return None

    async def create_message(
        self,
        context: RequestContext[ClientSession, Any],
        params: CreateMessageRequestParams,
    ) -> CreateMessageResult | ErrorData:
        """
        MCP sampling callback. Handles ``sampling/createMessage`` requests from
        MCP servers by forwarding them to the configured LLM via pydantic-ai.

        Suitable for passing directly as the *sampling_callback* argument to
        :class:`mcp.client.session.ClientSession`.

		Here is an example::

		from mcp.client.session import ClientSession
		from angr.llm_client import LLMClient

        client = LLMClient(model="openai:gpt-4o", api_key="sk-...")
        async with ClientSession(
		    read_stream=read,
		    write_stream=write,
		    sampling_callback=client.create_message,
	    ) as session:
            await session.initialize()
			# do whatever you need here
        """
        from mcp.types import (
            CreateMessageResult,
            ErrorData,
            SamplingMessage,
            TextContent,
        )
        from pydantic_ai.settings import ModelSettings as PydanticModelSettings  # type: ignore

        global Agent

        try:
            if Agent is None:
                from pydantic_ai import Agent  # type: ignore
        except ImportError:
            return ErrorData(
                code=-1,
                message="pydantic-ai is required for LLM support. Install with: pip install angr[llm]",
            )

        # build the prompt from MCP messages
        parts: list[str] = []
        if params.systemPrompt:
            parts.append(f"[system]\n{params.systemPrompt}")
        for msg in params.messages:
            blocks = msg.content if isinstance(msg.content, list) else [msg.content]
            for block in blocks:
                if isinstance(block, TextContent):
                    parts.append(f"[{msg.role}]\n{block.text}")
                else:
                    l.warning("Skipping unsupported content type in MCP sampling request: %s", type(block).__name__)

        prompt = "\n\n".join(parts)
        if not prompt:
            return ErrorData(code=-1, message="No text content in sampling request")

        # build model settings, honouring request-level overrides
        settings: dict[str, Any] = {}
        settings["max_tokens"] = params.maxTokens
        temperature = params.temperature if params.temperature is not None else self.temperature
        settings["temperature"] = temperature
        if params.stopSequences:
            settings["stop_sequences"] = params.stopSequences

        try:
            agent = Agent(self._pydantic_model, output_type=str)
            result = agent.run_sync(prompt, model_settings=PydanticModelSettings(**settings))
            return CreateMessageResult(
                role="assistant",
                content=TextContent(type="text", text=result.output),
                model=self.model,
                stopReason="endTurn",
            )
        except Exception as ex:
            l.warning("MCP sampling request failed", exc_info=True)
            return ErrorData(code=-1, message=str(ex))

    def __repr__(self):
        return f"<LLMClient model={self.model!r}>"
