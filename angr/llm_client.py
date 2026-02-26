# pylint:disable=unused-argument
from __future__ import annotations

import json
import logging
import os
import re
from typing import TypeVar

try:
    from pydantic_ai import Agent  # type: ignore
    from pydantic_ai.settings import ModelSettings  # type: ignore
    from pydantic_ai.models.openai import OpenAIChatModel  # type: ignore
    from pydantic_ai.providers.openai import OpenAIProvider  # type: ignore
except ImportError:
    Agent = None  # type: ignore
    ModelSettings = None  # type: ignore
    OpenAIChatModel = None  # type: ignore
    OpenAIProvider = None  # type: ignore

T = TypeVar("T")

l = logging.getLogger(name=__name__)


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
        if Agent is None:
            raise ImportError(
                "pydantic-ai is required for LLM support. You can install it with: pip install angr[llm] or "
                "pip install pydantic-ai"
            )

        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._pydantic_model = self._build_model()

    def _build_model(self):
        """Build a pydantic-ai model object from the configured settings."""
        if self.api_base:
            provider = OpenAIProvider(base_url=self.api_base, api_key=self.api_key or "no-key")
            return OpenAIChatModel(self.model, provider=provider)
        if ":" in self.model:
            return self.model
        return f"openai:{self.model}"

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
        return ModelSettings(temperature=self.temperature, max_tokens=self.max_tokens)

    def completion(self, messages: list[dict[str, str]], **kwargs) -> str:  # pylint:disable=unused-argument
        """
        Call the LLM with the given messages and return the response text.
        """
        assert Agent is not None

        prompt = "\n\n".join(m["content"] for m in messages if m.get("content"))
        agent = Agent(self._pydantic_model, output_type=str)
        result = agent.run_sync(prompt, model_settings=self._model_settings())
        return result.output

    def completion_structured(self, messages: list[dict[str, str]], output_type: type[T], **kwargs) -> T | None:
        """
        Call the LLM with the given messages and return a validated Pydantic model.
        Returns None if the call fails.
        """
        assert Agent is not None

        prompt = "\n\n".join(m["content"] for m in messages if m.get("content"))
        try:
            agent = Agent(self._pydantic_model, output_type=output_type)
            result = agent.run_sync(prompt, model_settings=self._model_settings())
            return result.output
        except Exception:  # pylint:disable=broad-exception-caught
            l.warning("Failed to get structured LLM response", exc_info=True)
            return None

    def completion_json(self, messages: list[dict[str, str]], **kwargs) -> dict | None:
        """
        Call the LLM and parse the response as JSON.
        Strips markdown code fences if present. Returns None on parse failure.
        Kept for backwards compatibility; prefer completion_structured().
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
        except (json.JSONDecodeError, ValueError):
            l.warning("Failed to parse LLM response as JSON: %s", text[:200])
            return None

    def __repr__(self):
        return f"<LLMClient model={self.model!r}>"
