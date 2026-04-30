"""
Groq Provider — Fastest free AI
"""
import os
import httpx
from app.ai.providers.base import BaseProvider


class GroqProvider(BaseProvider):
    """Groq — Llama 3.3 70B — Fastest inference"""

    NAME = "groq"
    MODEL = "llama-3.3-70b-versatile"
    BASE_URL = "https://api.groq.com/openai/v1"

    def is_available(self) -> bool:
        return bool(os.getenv("GROQ_API_KEY"))

    async def complete(self, prompt: str, system: str = "") -> str:
        api_key = os.getenv("GROQ_API_KEY")
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
                },
                json={
                    "model": self.MODEL,
                    "messages": messages,
                    "max_tokens": 2048,
                    "temperature": 0.3,
                }
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
