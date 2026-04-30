def build_report_prompt(findings: str) -> str:
    return f"""Write a professional penetration testing report section for these findings:

{findings[:3000]}

Include:
1. Executive Summary
2. Technical Details for each finding
3. Risk Rating with justification
4. Proof of Concept
5. Remediation Recommendations
6. References (CVE, OWASP, etc.)

Use professional security report language."""
