"""
HuggingFace Provider — Free inference API
"""
import os
import httpx
from app.ai.providers.base import BaseProvider


class HuggingFaceProvider(BaseProvider):
    """HuggingFace Inference API — Last resort fallback"""

    NAME = "huggingface"
    MODEL = "mistralai/Mistral-7B-Instruct-v0.3"
    BASE_URL = "https://api-inference.huggingface.co/models"

    def is_available(self) -> bool:
        return bool(os.getenv("HUGGINGFACE_API_KEY"))

    async def complete(self, prompt: str, system: str = "") -> str:
        api_key = os.getenv("HUGGINGFACE_API_KEY")
        full_prompt = f"{system}\n\n{prompt}" if system else prompt

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{self.BASE_URL}/{self.MODEL}",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "inputs": full_prompt,
                    "parameters": {
                        "max_new_tokens": 1024,
                        "temperature": 0.3,
                        "return_full_text": False,
                    }
                }
            )
            resp.raise_for_status()
            result = resp.json()
            if isinstance(result, list) and result:
                return result[0].get("generated_text", "")
            return str(result)
