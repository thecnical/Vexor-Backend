"""
OpenRouter Provider — 29+ free models
"""
import os
import httpx
from app.ai.providers.base import BaseProvider


class OpenRouterProvider(BaseProvider):
    """OpenRouter — Free models fallback"""

    NAME = "openrouter"
    MODEL = "meta-llama/llama-4-scout:free"
    BASE_URL = "https://openrouter.ai/api/v1"

    def is_available(self) -> bool:
        return bool(os.getenv("OPENROUTER_API_KEY"))

    async def complete(self, prompt: str, system: str = "") -> str:
        api_key = os.getenv("OPENROUTER_API_KEY")
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{self.BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://vexor.security",
                    "X-Title": "Vexor Security Toolkit",
                },
                json={
                    "model": self.MODEL,
                    "messages": messages,
                    "max_tokens": 2048,
                }
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
