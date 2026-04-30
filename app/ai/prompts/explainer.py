def build_explain_prompt(content: str) -> str:
    return f"""Explain this HTTP content from a security perspective:

{content[:3000]}

Explain:
1. What this request/response does
2. Any security-relevant headers or parameters
3. Potential security issues you notice
4. What an attacker might look for here

Be clear and educational."""
