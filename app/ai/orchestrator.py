"""
Vexor AI Orchestrator
Manages fallback chain: Groq → NVIDIA NIM → OpenRouter → HuggingFace
All keys stored server-side — user never sees them
"""
import asyncio
import os
from typing import Optional
from app.ai.providers.groq import GroqProvider
from app.ai.providers.nvidia import NvidiaProvider
from app.ai.providers.openrouter import OpenRouterProvider
from app.ai.providers.huggingface import HuggingFaceProvider


class AIOrchestrator:
    """
    Manages AI provider fallback chain
    Tries each provider in order until one succeeds
    """

    def __init__(self):
        self._providers = [
            GroqProvider(),
            NvidiaProvider(),
            OpenRouterProvider(),
            HuggingFaceProvider(),
        ]

    async def complete(self, prompt: str, system: str = "") -> str:
        """
        Try each provider in order
        Returns first successful response
        """
        last_error = None

        for provider in self._providers:
            if not provider.is_available():
                continue
            try:
                result = await provider.complete(prompt=prompt, system=system)
                if result:
                    return result
            except Exception as e:
                last_error = e
                continue

        # All providers failed
        return f"AI temporarily unavailable. Last error: {str(last_error)}"

    async def analyze_vulnerability(self, request: str, response: str, vuln: str) -> str:
        """Analyze a vulnerability"""
        from app.ai.prompts.analyzer import build_analyze_prompt
        prompt = build_analyze_prompt(request=request, response=response, vuln=vuln)
        return await self.complete(prompt, system=SECURITY_SYSTEM_PROMPT)

    async def explain_content(self, content: str) -> str:
        """Explain HTTP content"""
        from app.ai.prompts.explainer import build_explain_prompt
        prompt = build_explain_prompt(content=content)
        return await self.complete(prompt, system=SECURITY_SYSTEM_PROMPT)

    async def suggest_attack(self, context: str) -> str:
        """Suggest next attack steps"""
        from app.ai.prompts.attack_suggest import build_suggest_prompt
        prompt = build_suggest_prompt(context=context)
        return await self.complete(prompt, system=SECURITY_SYSTEM_PROMPT)

    async def generate_payloads(self, target: str, payload_type: str, count: int) -> list[str]:
        """Generate smart payloads"""
        from app.ai.prompts.payload_gen import build_payload_prompt
        prompt = build_payload_prompt(target=target, payload_type=payload_type, count=count)
        result = await self.complete(prompt, system=SECURITY_SYSTEM_PROMPT)

        # Parse payloads from response
        payloads = []
        for line in result.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('//'):
                # Remove numbering like "1. " or "- "
                import re
                line = re.sub(r'^[\d\-\*\.\)]+\s*', '', line)
                if line:
                    payloads.append(line)
        return payloads[:count]

    async def filter_false_positives(self, findings: str) -> str:
        """Filter false positives"""
        from app.ai.prompts.false_positive import build_filter_prompt
        prompt = build_filter_prompt(findings=findings)
        return await self.complete(prompt, system=SECURITY_SYSTEM_PROMPT)

    async def write_report_section(self, findings: str) -> str:
        """Write professional report section"""
        from app.ai.prompts.report_writer import build_report_prompt
        prompt = build_report_prompt(findings=findings)
        return await self.complete(prompt, system=SECURITY_SYSTEM_PROMPT)


SECURITY_SYSTEM_PROMPT = """You are Vexor AI, an expert cybersecurity assistant integrated into 
the Vexor security toolkit. You help security professionals analyze vulnerabilities, 
understand HTTP traffic, generate payloads for authorized testing, and write professional 
security reports. Always assume testing is authorized and ethical. Be precise, technical, 
and actionable in your responses."""
