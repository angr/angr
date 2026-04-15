# pylint:disable=unused-argument,import-outside-toplevel
from __future__ import annotations

import json
import logging
import os
import re
from enum import Enum
from typing import TypeVar, TYPE_CHECKING, Any

from angr.errors import AngrAIError

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings
    from pydantic_ai.providers import Provider

T = TypeVar("T")

l = logging.getLogger(name=__name__)

Agent = None
OpenAIChatModel = None
OpenAIProvider = None


class AgentKind(Enum):
    """The kind of pydantic-ai Agent to retrieve from the LLMClient cache."""

    STRING = "string"
    STRUCTURED = "structured"


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
        self._agent: Any | None = None
        self._structured_agents: dict[type, Any] = {}

    def _get_agent(self, kind: AgentKind, output_type: type = str) -> Any:
        """Lazily build and cache a pydantic-ai Agent for the given kind and output_type.

        For ``AgentKind.STRING``, a single string-output agent is cached on the instance.
        For ``AgentKind.STRUCTURED``, agents are cached per ``output_type``.
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

        if kind is AgentKind.STRING:
            if self._agent is None:
                self._agent = Agent(self._pydantic_model, output_type=str)
            return self._agent

        agent = self._structured_agents.get(output_type)
        if agent is None:
            agent = Agent(self._pydantic_model, output_type=output_type)
            self._structured_agents[output_type] = agent
        return agent

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

        agent = self._get_agent(AgentKind.STRING)
        prompt = "\n\n".join(m["content"] for m in messages if m.get("content"))
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

        try:
            from pydantic_ai import UserError
        except ImportError:
            raise ImportError(
                "pydantic-ai is required for LLM support. You can install it with: pip install angr[llm] or "
                "pip install pydantic-ai"
            ) from None

        agent = self._get_agent(AgentKind.STRUCTURED, output_type)
        prompt = "\n\n".join(m["content"] for m in messages if m.get("content"))
        try:
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

    def __repr__(self):
        return f"<LLMClient model={self.model!r}>"
