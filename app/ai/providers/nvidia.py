"""
NVIDIA NIM Provider — Free powerful models
"""
import os
import httpx
from app.ai.providers.base import BaseProvider


class NvidiaProvider(BaseProvider):
    """NVIDIA NIM — Qwen/Kimi/GLM — Free at build.nvidia.com"""

    NAME = "nvidia"
    MODEL = "qwen/qwen3-235b-a22b"
    BASE_URL = "https://integrate.api.nvidia.com/v1"

    def is_available(self) -> bool:
        return bool(os.getenv("NVIDIA_API_KEY"))

    async def complete(self, prompt: str, system: str = "") -> str:
        api_key = os.getenv("NVIDIA_API_KEY")
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
