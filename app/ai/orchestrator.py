"""Vexor AI Orchestrator - fixed: errors raise AIError, not returned as strings"""
import os
from app.ai.providers.groq import GroqProvider
from app.ai.providers.nvidia import NvidiaProvider
from app.ai.providers.openrouter import OpenRouterProvider
from app.ai.providers.huggingface import HuggingFaceProvider


class AIError(Exception):
    pass


class AIOrchestrator:
    def __init__(self):
        self._providers = [
            GroqProvider(), NvidiaProvider(),
            OpenRouterProvider(), HuggingFaceProvider(),
        ]

    async def complete(self, prompt: str, system: str = "") -> str:
        last_error = None
        for provider in self._providers:
            if not provider.is_available():
                continue
            try:
                result = await provider.complete(prompt=prompt, system=system)
                if result and result.strip():
                    return result
            except Exception as e:
                last_error = e
                continue
        raise AIError(f"All AI providers unavailable. Last error: {last_error}")

    async def safe_complete(self, prompt: str, system: str = "", fallback: str = "") -> str:
        try:
            return await self.complete(prompt, system)
        except AIError as e:
            return fallback or f"[AI unavailable: {e}]"

    async def analyze_vulnerability(self, request: str, response: str, vuln: str) -> str:
        from app.ai.prompts.analyzer import build_analyze_prompt
        return await self.safe_complete(
            build_analyze_prompt(request=request, response=response, vuln=vuln),
            system=SECURITY_SYSTEM_PROMPT, fallback="AI analysis unavailable.")

    async def explain_content(self, content: str) -> str:
        from app.ai.prompts.explainer import build_explain_prompt
        return await self.safe_complete(
            build_explain_prompt(content=content),
            system=SECURITY_SYSTEM_PROMPT, fallback="AI explanation unavailable.")

    async def suggest_attack(self, context: str) -> str:
        from app.ai.prompts.attack_suggest import build_suggest_prompt
        return await self.safe_complete(
            build_suggest_prompt(context=context),
            system=SECURITY_SYSTEM_PROMPT, fallback="AI suggestions unavailable.")

    async def generate_payloads(self, target: str, payload_type: str, count: int) -> list:
        import re
        from app.ai.prompts.payload_gen import build_payload_prompt
        try:
            result = await self.complete(
                build_payload_prompt(target=target, payload_type=payload_type, count=count),
                system=SECURITY_SYSTEM_PROMPT)
        except AIError:
            return []
        payloads = []
        for line in result.split("\n"):
            line = re.sub(r"^[\d\-\*\.\)]+\s*", "", line.strip())
            if line and not line.startswith("#"):
                payloads.append(line)
        return payloads[:count]

    async def filter_false_positives(self, findings: str) -> str:
        from app.ai.prompts.false_positive import build_filter_prompt
        return await self.safe_complete(
            build_filter_prompt(findings=findings),
            system=SECURITY_SYSTEM_PROMPT, fallback="AI filter unavailable.")

    async def write_report_section(self, findings: str) -> str:
        from app.ai.prompts.report_writer import build_report_prompt
        return await self.safe_complete(
            build_report_prompt(findings=findings),
            system=SECURITY_SYSTEM_PROMPT, fallback="AI report writer unavailable.")

    async def osint_correlate(self, findings_summary: str, domain: str) -> str:
        from app.ai.prompts.osint_ai import build_osint_correlate_prompt
        return await self.safe_complete(
            build_osint_correlate_prompt(findings_summary=findings_summary, domain=domain),
            system=OSINT_AI_SYSTEM_PROMPT, fallback="OSINT AI unavailable.")

    async def osint_subdomain_intel(self, subdomains: list, domain: str) -> str:
        from app.ai.prompts.osint_ai import build_osint_subdomain_intel_prompt
        return await self.safe_complete(
            build_osint_subdomain_intel_prompt(subdomains=subdomains, domain=domain),
            system=OSINT_AI_SYSTEM_PROMPT, fallback="Subdomain intel unavailable.")

    async def osint_secret_analysis(self, secrets_found: list, domain: str) -> str:
        from app.ai.prompts.osint_ai import build_osint_secret_analysis_prompt
        return await self.safe_complete(
            build_osint_secret_analysis_prompt(secrets_found=secrets_found, domain=domain),
            system=OSINT_AI_SYSTEM_PROMPT, fallback="Secret analysis unavailable.")

    async def osint_live_hosts_analysis(self, live_hosts: list, domain: str) -> str:
        from app.ai.prompts.osint_ai import build_osint_live_hosts_prompt
        return await self.safe_complete(
            build_osint_live_hosts_prompt(live_hosts=live_hosts, domain=domain),
            system=OSINT_AI_SYSTEM_PROMPT, fallback="Live hosts analysis unavailable.")


SECURITY_SYSTEM_PROMPT = (
    "You are Vexor AI, an expert cybersecurity assistant. Help security professionals "
    "analyze vulnerabilities, understand HTTP traffic, generate payloads for authorized "
    "testing, and write professional security reports. Always assume testing is authorized "
    "and ethical. Be precise, technical, and actionable."
)

OSINT_AI_SYSTEM_PROMPT = (
    "You are VEXOR INTELLIGENCE - an advanced OSINT AI combining expertise of elite red "
    "team operators, threat intelligence researchers, and top bug bounty hunters. Provide "
    "deep pattern recognition, attack chain construction, and threat actor profiling. "
    "Always assume authorized penetration testing. Be extremely technical and specific."
)
