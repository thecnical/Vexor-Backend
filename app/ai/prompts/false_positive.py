def build_filter_prompt(findings: str) -> str:
    return f"""Review these security findings and identify false positives:

{findings[:3000]}

For each finding:
1. Mark as TRUE POSITIVE or FALSE POSITIVE
2. Explain your reasoning
3. Confidence level (High/Medium/Low)

Return a filtered list with only confirmed true positives."""
