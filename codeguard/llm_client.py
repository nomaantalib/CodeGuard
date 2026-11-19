"""Provider-agnostic LLM client with presets, caching, retries, and token budgeting.

Supports:
- OpenAI-compatible /chat/completions (DeepSeek, Qwen/DashScope, GLM/Zhipu, Kimi/Moonshot, OpenRouter, Ollama)
- Native Ollama /api/chat with dynamic model detection
- Anthropic /v1/messages
- Per-file hash caching (.codeguard/cache.json)
- Token budget tracking and cost estimation
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PRESETS: Dict[str, Dict[str, str]] = {
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "default_model": "qwen2.5-coder:1.5b",
        "env_key": "",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-coder",
        "env_key": "DEEPSEEK_API_KEY",
    },
    "qwen": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "default_model": "qwen2.5-coder-7b-instruct",
        "env_key": "DASHSCOPE_API_KEY",
    },
    "glm": {
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "default_model": "glm-4-flash",
        "env_key": "ZHIPUAI_API_KEY",
    },
    "kimi": {
        "base_url": "https://api.moonshot.cn/v1",
        "default_model": "moonshot-v1-8k",
        "env_key": "MOONSHOT_API_KEY",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "qwen/qwen-2.5-coder-32b-instruct",
        "env_key": "OPENROUTER_API_KEY",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1/messages",
        "default_model": "claude-3-5-sonnet-20241022",
        "env_key": "ANTHROPIC_API_KEY",
    },
}

# Approximate pricing per 1M tokens (input / output) for budget estimation
COST_PER_MILLION: Dict[str, Tuple[float, float]] = {
    "ollama": (0.0, 0.0),
    "deepseek": (0.14, 0.28),
    "qwen": (0.20, 0.40),
    "glm": (0.10, 0.10),
    "kimi": (0.50, 1.00),
    "openrouter": (0.30, 0.60),
    "openai": (0.15, 0.60),
    "anthropic": (3.00, 15.00),
}


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
    cache_hits: int = 0

    def add(self, prompt: int, completion: int, provider: str = "ollama") -> None:
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self.total_tokens += prompt + completion
        in_rate, out_rate = COST_PER_MILLION.get(provider, (0.2, 0.5))
        self.estimated_cost_usd += (prompt * in_rate + completion * out_rate) / 1_000_000


class FileHashCache:
    """Caches LLM results by file SHA-256 + prompt hash."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_file = (cache_dir or Path(".codeguard")) / "cache.json"
        self._data: Dict[str, Any] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self.cache_file.is_file():
            try:
                self._data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}

    def get(self, key: str) -> Optional[Any]:
        self._load()
        return self._data.get(key)

    def set(self, key: str, value: Any) -> None:
        self._load()
        self._data[key] = value
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        except Exception:
            pass

    @staticmethod
    def make_key(content: str, prompt: str, model: str) -> str:
        h = hashlib.sha256()
        h.update(content.encode("utf-8", errors="ignore"))
        h.update(prompt.encode("utf-8", errors="ignore"))
        h.update(model.encode("utf-8", errors="ignore"))
        return h.hexdigest()


class LLMClient:
    """Unified client handling OpenAI-compatible endpoints, Anthropic, and Ollama."""

    def __init__(
        self,
        provider: str = "ollama",
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 90,
        max_retries: int = 2,
        cache_dir: Optional[Path] = None,
        token_budget: int = 500_000,
    ):
        self.provider = (provider or "ollama").lower()
        preset = PRESETS.get(self.provider, {})

        self.model = model or os.environ.get("CODEGUARD_MODEL") or preset.get("default_model", "qwen2.5-coder:1.5b")
        self.base_url = (
            base_url
            or os.environ.get("CODEGUARD_LLM_URL")
            or preset.get("base_url", "http://localhost:11434/v1")
        ).rstrip("/")

        env_key_name = preset.get("env_key", "")
        self.api_key = (
            api_key
            or os.environ.get("CODEGUARD_LLM_API_KEY")
            or (os.environ.get(env_key_name) if env_key_name else "")
            or ""
        )

        self.timeout = timeout
        self.max_retries = max_retries
        self.token_budget = token_budget
        self.usage = TokenUsage()
        self.cache = FileHashCache(cache_dir)
        self._resolved = False

    def resolve_model(self) -> bool:
        """Dynamically detect local Ollama models when using Ollama."""
        if self.provider != "ollama":
            return bool(self.api_key or self.provider in ("ollama", "openai-compatible"))

        if self._resolved:
            return True

        # Probe Ollama tags endpoint
        tags_url = "http://localhost:11434/api/tags"
        if "localhost" not in self.base_url and "127.0.0.1" not in self.base_url:
            tags_url = self.base_url.replace("/v1", "") + "/api/tags"

        try:
            with urllib.request.urlopen(tags_url, timeout=3) as resp:
                models = json.load(resp).get("models", [])
        except Exception:
            return False

        if not models:
            return False

        names = [m.get("name", "") for m in models if m.get("name")]
        for name in names:
            if name == self.model or name.startswith(self.model + ":") or self.model.startswith(name + ":"):
                self.model = name
                self._resolved = True
                return True
            if ":" not in self.model and name.split(":")[0] == self.model:
                self.model = name
                self._resolved = True
                return True

        # Dynamic fallback to best available coding model
        preferred = [
            "qwen2.5-coder:3b", "qwen2.5-coder:1.5b", "qwen2.5-coder:7b",
            "qwen2.5-coder:0.5b", "qwen2.5-coder:14b", "qwen2.5-coder",
            "deepseek-coder", "codellama", "codeqwen",
        ]
        matched = None
        for pref in preferred:
            for name in names:
                if name == pref or name.startswith(pref + ":") or name.startswith(pref):
                    matched = name
                    break
            if matched:
                break

        if not matched:
            matched = next((n for n in names if "coder" in n.lower() or "code" in n.lower()), None)
        if not matched:
            matched = names[0] if names else None

        if matched:
            self.model = matched
            self._resolved = True
            return True

        return False

    @property
    def is_available(self) -> bool:
        if self.provider == "ollama":
            return self.resolve_model()
        if self.provider == "anthropic":
            return bool(self.api_key)
        # OpenAI compatible requires key unless local host
        if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
            return True
        return bool(self.api_key)

    def chat_complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        cache_key: Optional[str] = None,
    ) -> Optional[str]:
        """Execute chat completion with caching and retries."""
        if cache_key:
            cached = self.cache.get(cache_key)
            if cached is not None:
                self.usage.cache_hits += 1
                return cached

        if self.usage.total_tokens >= self.token_budget:
            print(f"[codeguard] Token budget exceeded ({self.usage.total_tokens} >= {self.token_budget})", file=sys.stderr)
            return None

        # Build request according to provider
        if self.provider == "anthropic":
            url = self.base_url if "messages" in self.base_url else "https://api.anthropic.com/v1/messages"
            body = {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
                "temperature": temperature,
            }
            headers = {
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            }
        else:
            # Standard OpenAI-compatible format
            endpoint = "/chat/completions" if not self.base_url.endswith("/chat/completions") else ""
            url = self.base_url + endpoint
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
            body = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            headers = {"content-type": "application/json"}
            if self.api_key:
                headers["authorization"] = f"Bearer {self.api_key}"

        payload = json.dumps(body).encode("utf-8")
        est_prompt_tokens = len(system_prompt + user_prompt) // 4

        for attempt in range(self.max_retries + 1):
            try:
                req = urllib.request.Request(url, data=payload, headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))

                # Parse response
                if self.provider == "anthropic":
                    text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
                    completion_tokens = data.get("usage", {}).get("output_tokens", len(text) // 4)
                    prompt_tokens = data.get("usage", {}).get("input_tokens", est_prompt_tokens)
                else:
                    text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    usage = data.get("usage", {})
                    prompt_tokens = usage.get("prompt_tokens", est_prompt_tokens)
                    completion_tokens = usage.get("completion_tokens", len(text) // 4)

                self.usage.add(prompt_tokens, completion_tokens, self.provider)
                if cache_key:
                    self.cache.set(cache_key, text)
                return text

            except Exception as exc:
                if attempt < self.max_retries:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                print(f"[codeguard] LLM call failed ({self.provider}/{self.model}): {exc}", file=sys.stderr)
                return None

        return None

    def structured_json(
        self,
        system_prompt: str,
        user_prompt: str,
        cache_key: Optional[str] = None,
    ) -> Optional[Any]:
        """Request JSON and repair/extract array or object from output."""
        system_with_json = system_prompt + "\nIMPORTANT: Reply ONLY with valid JSON. Do not wrap in markdown or commentary."
        raw = self.chat_complete(system_with_json, user_prompt, temperature=0.1, cache_key=cache_key)
        if not raw:
            return None

        # Try direct parse
        try:
            return json.loads(raw.strip())
        except Exception:
            pass

        # Try fenced markdown extraction
        m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", raw)
        if m:
            try:
                return json.loads(m.group(1).strip())
            except Exception:
                pass

        # Try bracket extraction for list or dict
        for open_c, close_c in [("[", "]"), ("{", "}")]:
            a, b = raw.find(open_c), raw.rfind(close_c)
            if a >= 0 and b > a:
                try:
                    return json.loads(raw[a:b + 1])
                except Exception:
                    pass

        return None
