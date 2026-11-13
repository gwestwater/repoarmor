"""LLM provider abstraction for multiple backends."""

import json
import os
from abc import ABC, abstractmethod
from typing import Any

from ..ui.console import print_error


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        """Send a chat request to the LLM.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            tools: Optional list of tool definitions.

        Returns:
            Response dict with 'content' and optionally 'tool_calls'.
        """
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """Get the model name being used."""
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI provider."""

    def __init__(self, api_key: str | None = None, model: str = "gpt-4o"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "OpenAI API key required. Set OPENAI_API_KEY environment variable "
                "or provide api_key in config."
            )
        self.model = model

        try:
            import openai
            self.client = openai.OpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install repoarmor[llm]"
            )

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        """Send a chat request to OpenAI."""
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
        }

        if tools:
            # Convert to OpenAI tool format
            kwargs["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["parameters"],
                    },
                }
                for t in tools
            ]

        response = self.client.chat.completions.create(**kwargs)

        # Parse response
        result: dict[str, Any] = {"content": "", "tool_calls": []}
        message = response.choices[0].message

        if message.content:
            result["content"] = message.content

        if message.tool_calls:
            for tc in message.tool_calls:
                result["tool_calls"].append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": json.loads(tc.function.arguments),
                })

        return result

    def get_model_name(self) -> str:
        return self.model


def get_llm_provider(
    provider: str = "openai",
    api_key: str | None = None,
    model: str | None = None,
) -> LLMProvider:
    """Get an LLM provider instance.

    Args:
        provider: Provider name (only 'openai' is supported).
        api_key: Optional API key (uses env var if not provided).
        model: Optional model override.

    Returns:
        LLMProvider instance.
    """
    if provider == "openai":
        return OpenAIProvider(
            api_key=api_key,
            model=model or "gpt-4o",
        )
    else:
        raise ValueError(f"Unknown provider: {provider}. Only 'openai' is supported.")
