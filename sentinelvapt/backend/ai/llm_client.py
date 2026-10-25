"""
SentinelVAPT — LLM Client Abstraction
Supports Groq (primary) and Ollama (fallback) providers.
Logs all calls for debugging and cost tracking.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from backend.config.settings import get_settings

logger = logging.getLogger("sentinelvapt.ai.llm")


class LLMClient:
    """
    Unified LLM client supporting Groq API and Ollama.
    Auto-falls back to Ollama if Groq is unavailable.
    """

    def __init__(self):
        self.settings = get_settings()
        self.provider = self.settings.llm_provider
        self._call_log: List[Dict] = []

    def _log_call(self, provider: str, model: str, prompt_len: int,
                  response_len: int, latency: float, tokens: int, success: bool):
        """Log LLM call metrics."""
        entry = {
            "provider": provider,
            "model": model,
            "prompt_chars": prompt_len,
            "response_chars": response_len,
            "latency_seconds": round(latency, 2),
            "estimated_tokens": tokens,
            "success": success,
            "timestamp": time.time(),
        }
        self._call_log.append(entry)
        logger.info(
            "LLM call: provider=%s model=%s latency=%.2fs tokens=%d success=%s",
            provider, model, latency, tokens, success
        )

    async def generate(self, prompt: str, system_prompt: str = "",
                       json_mode: bool = False, max_retries: int = 3) -> Optional[str]:
        """
        Generate a response from the LLM.
        Tries the configured provider first, falls back to Ollama.
        """
        # Try primary provider
        if self.provider == "groq" and self.settings.groq_api_key:
            for attempt in range(max_retries):
                result = await self._call_groq(prompt, system_prompt, json_mode)
                if result is not None:
                    return result
                logger.warning("Groq attempt %d/%d failed, retrying...", attempt + 1, max_retries)
                time.sleep(1 * (attempt + 1))

            logger.warning("Groq failed after %d retries, falling back to Ollama", max_retries)

        # Fallback to Ollama
        for attempt in range(max_retries):
            result = await self._call_ollama(prompt, system_prompt, json_mode)
            if result is not None:
                return result
            logger.warning("Ollama attempt %d/%d failed", attempt + 1, max_retries)
            time.sleep(1 * (attempt + 1))

        logger.error("All LLM providers failed")
        return None

    async def _call_groq(self, prompt: str, system_prompt: str,
                         json_mode: bool) -> Optional[str]:
        """Call the Groq API."""
        start = time.time()
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": self.settings.groq_model,
                "messages": messages,
                "temperature": 0.1,
                "max_tokens": 8192,
            }

            if json_mode:
                payload["response_format"] = {"type": "json_object"}

            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.settings.groq_api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()

            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            total_tokens = usage.get("total_tokens", 0)
            latency = time.time() - start

            self._log_call("groq", self.settings.groq_model,
                           len(prompt), len(content), latency, total_tokens, True)
            return content

        except Exception as e:
            latency = time.time() - start
            self._log_call("groq", self.settings.groq_model,
                           len(prompt), 0, latency, 0, False)
            logger.error("Groq API error: %s", e)
            return None

    async def _call_ollama(self, prompt: str, system_prompt: str,
                           json_mode: bool) -> Optional[str]:
        """Call the Ollama local API."""
        start = time.time()
        try:
            payload = {
                "model": self.settings.ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 8192,
                },
            }

            if system_prompt:
                payload["system"] = system_prompt

            if json_mode:
                payload["format"] = "json"

            resp = requests.post(
                f"{self.settings.ollama_base_url}/api/generate",
                json=payload,
                timeout=300,
            )
            resp.raise_for_status()
            data = resp.json()

            content = data.get("response", "")
            eval_count = data.get("eval_count", 0)
            latency = time.time() - start

            self._log_call("ollama", self.settings.ollama_model,
                           len(prompt), len(content), latency, eval_count, True)
            return content

        except Exception as e:
            latency = time.time() - start
            self._log_call("ollama", self.settings.ollama_model,
                           len(prompt), 0, latency, 0, False)
            logger.error("Ollama API error: %s", e)
            return None

    def get_call_log(self) -> List[Dict]:
        """Return all logged LLM calls for debugging/cost tracking."""
        return self._call_log.copy()
