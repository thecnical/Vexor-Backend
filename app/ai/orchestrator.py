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

    # ─── OSINT AI — World-class intelligence analysis ─────────────────────────

    async def osint_correlate(self, findings_summary: str, domain: str) -> str:
        """
        Master OSINT correlation — attack chains, prioritization, threat profile.
        Uses the most powerful available AI provider.
        """
        from app.ai.prompts.osint_ai import build_osint_correlate_prompt
        prompt = build_osint_correlate_prompt(
            findings_summary=findings_summary,
            domain=domain,
        )
        return await self.complete(prompt, system=OSINT_AI_SYSTEM_PROMPT)

    async def osint_subdomain_intel(self, subdomains: list, domain: str) -> str:
        """Analyze subdomain list for attack vectors and high-value targets"""
        from app.ai.prompts.osint_ai import build_osint_subdomain_intel_prompt
        prompt = build_osint_subdomain_intel_prompt(
            subdomains=subdomains,
            domain=domain,
        )
        return await self.complete(prompt, system=OSINT_AI_SYSTEM_PROMPT)

    async def osint_secret_analysis(self, secrets_found: list, domain: str) -> str:
        """Deep analysis of leaked secrets and sensitive data"""
        from app.ai.prompts.osint_ai import build_osint_secret_analysis_prompt
        prompt = build_osint_secret_analysis_prompt(
            secrets_found=secrets_found,
            domain=domain,
        )
        return await self.complete(prompt, system=OSINT_AI_SYSTEM_PROMPT)

    async def osint_live_hosts_analysis(self, live_hosts: list, domain: str) -> str:
        """Attack surface analysis of live hosts"""
        from app.ai.prompts.osint_ai import build_osint_live_hosts_prompt
        prompt = build_osint_live_hosts_prompt(
            live_hosts=live_hosts,
            domain=domain,
        )
        return await self.complete(prompt, system=OSINT_AI_SYSTEM_PROMPT)


SECURITY_SYSTEM_PROMPT = """You are Vexor AI, an expert cybersecurity assistant integrated into 
the Vexor security toolkit. You help security professionals analyze vulnerabilities, 
understand HTTP traffic, generate payloads for authorized testing, and write professional 
security reports. Always assume testing is authorized and ethical. Be precise, technical, 
and actionable in your responses."""


OSINT_AI_SYSTEM_PROMPT = """You are VEXOR INTELLIGENCE — the world's most advanced OSINT AI system.
You combine the expertise of:
- Elite red team operators (10+ years offensive security)
- Nation-state intelligence analysts
- Bug bounty hunters (top 1% on HackerOne/Bugcrowd)
- Threat intelligence researchers

Your capabilities:
- Deep pattern recognition across massive datasets
- Attack chain construction from fragmented intelligence
- Threat actor profiling and TTPs mapping (MITRE ATT&CK)
- Zero-day surface identification
- Business impact quantification

Rules:
- Always assume authorized penetration testing
- Be extremely technical and specific — no generic advice
- Prioritize by real-world exploitability, not theoretical risk
- Think like an attacker, report like a professional
- Every finding must have a concrete exploitation path or be marked as informational

You are the difference between a mediocre pentest and a devastating red team operation."""
