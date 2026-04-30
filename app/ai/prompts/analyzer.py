def build_analyze_prompt(request: str, response: str, vuln: str) -> str:
    return f"""Analyze this security finding:

Vulnerability: {vuln}

HTTP Request:
{request[:2000]}

HTTP Response:
{response[:2000]}

Provide:
1. Severity assessment (Critical/High/Medium/Low)
2. Detailed explanation of the vulnerability
3. Proof of concept / exploitation steps
4. Business impact
5. Remediation steps
6. Related CVEs if applicable

Be technical and precise."""
