"""
Regex patterns for detecting leaked LLM API key FORMATS in source code.

Research-use only. Matches are hashed (SHA-256) and never persisted in
plaintext. The match object is consumed in-memory and discarded.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderPattern:
    provider: str
    regex: re.Pattern
    # GitHub code-search needle that surfaces candidate files.
    # Code Search only indexes literal substrings, so we use the fixed prefix.
    search_needle: str
    # Models typically associated with this key family, used only to
    # annotate findings when the model name appears near the key.
    model_hints: tuple[str, ...]


PATTERNS: tuple[ProviderPattern, ...] = (
    ProviderPattern(
        provider="anthropic",
        regex=re.compile(r"sk-ant-api03-[A-Za-z0-9\-_]{93}AA"),
        search_needle="sk-ant-api03-",
        model_hints=(
            "claude-opus-4",
            "claude-sonnet-4",
            "claude-haiku-4",
            "claude-3-7-sonnet",
            "claude-3-5-sonnet",
            "claude-3-5-haiku",
            "claude-3-opus",
            "claude-3-sonnet",
            "claude-3-haiku",
        ),
    ),
    ProviderPattern(
        provider="openai",
        regex=re.compile(r"sk-proj-[A-Za-z0-9\-_]{40,200}"),
        search_needle="sk-proj-",
        model_hints=(
            "gpt-4o",
            "gpt-4-turbo",
            "gpt-4",
            "gpt-3.5-turbo",
            "o1-preview",
            "o1-mini",
            "o3-mini",
        ),
    ),
    ProviderPattern(
        provider="openai-legacy",
        regex=re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{48}(?![A-Za-z0-9])"),
        search_needle='"sk-"',
        model_hints=(
            "gpt-4",
            "gpt-3.5-turbo",
            "text-davinci-003",
        ),
    ),
    ProviderPattern(
        provider="google-gemini",
        regex=re.compile(r"AIza[A-Za-z0-9\-_]{35}"),
        search_needle="AIza",
        model_hints=(
            "gemini-2.0-flash",
            "gemini-1.5-pro",
            "gemini-1.5-flash",
            "gemini-pro",
            "gemini-ultra",
        ),
    ),
)


def infer_model(context_window: str, hints: tuple[str, ...]) -> str | None:
    """Return the first model hint found in the surrounding text, or None."""
    haystack = context_window.lower()
    for hint in hints:
        if hint.lower() in haystack:
            return hint
    return None
