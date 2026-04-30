def build_payload_prompt(target: str, payload_type: str, count: int) -> str:
    return f"""Generate {count} security testing payloads for: {payload_type}

Target context: {target}

Generate creative, effective payloads that:
1. Cover different bypass techniques
2. Include encoding variations
3. Target different contexts (HTML, JS, SQL, etc.)
4. Include both simple and advanced payloads

Return ONLY the payloads, one per line, no explanations."""
