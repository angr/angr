from __future__ import annotations

import json
import logging
import os
import re

l = logging.getLogger(name=__name__)


class LLMClient:
    """
    A client for interacting with LLMs via LiteLLM.
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
        try:
            import litellm  # noqa: F401
        except ImportError:
            raise ImportError(
                "litellm is required for LLM support. Install it with: pip install angr[llm]  or  pip install litellm"
            )

        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.max_tokens = max_tokens
        self.temperature = temperature

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

    def completion(self, messages: list[dict[str, str]], **kwargs) -> str:
        """
        Call the LLM with the given messages and return the response text.
        """
        import litellm

        call_kwargs: dict = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if self.api_key:
            call_kwargs["api_key"] = self.api_key
        if self.api_base:
            call_kwargs["api_base"] = self.api_base
        call_kwargs.update(kwargs)

        response = litellm.completion(**call_kwargs)
        return response.choices[0].message.content

    def completion_json(self, messages: list[dict[str, str]], **kwargs) -> dict | None:
        """
        Call the LLM and parse the response as JSON.
        Strips markdown code fences if present. Returns None on parse failure.
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
