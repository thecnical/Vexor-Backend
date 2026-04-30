def build_suggest_prompt(context: str) -> str:
    return f"""Based on this security testing context, suggest next attack steps:

{context[:3000]}

Provide:
1. Top 5 next attack vectors to try
2. Specific payloads or techniques for each
3. Tools to use
4. What to look for in responses
5. Priority order

Focus on practical, actionable steps for authorized penetration testing."""
