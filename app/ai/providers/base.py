"""Base AI Provider"""
from abc import ABC, abstractmethod


class BaseProvider(ABC):
    NAME = "base"
    MODEL = ""

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    async def complete(self, prompt: str, system: str = "") -> str:
        pass
