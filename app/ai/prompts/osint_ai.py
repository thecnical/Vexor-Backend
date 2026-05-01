"""
Vexor OSINT AI Prompts
World-class intelligence correlation and attack chain analysis
"""


def build_osint_correlate_prompt(findings_summary: str, domain: str) -> str:
    return f"""You are the world's most advanced OSINT intelligence analyst and red team operator.
Analyze the following intelligence gathered on target: {domain}

INTELLIGENCE DATA:
{findings_summary[:8000]}

Perform a DEEP multi-dimensional analysis:

## 1. ATTACK SURFACE MAPPING
- Map all discovered assets (subdomains, IPs, ports, services)
- Identify the most exposed entry points
- Rate each entry point by exploitability (1-10)

## 2. CRITICAL FINDINGS PRIORITIZATION
- List top 5 most dangerous findings with exploitation paths
- For each: severity, attack vector, likelihood, business impact

## 3. ATTACK CHAIN CONSTRUCTION
- Build 2-3 realistic attack chains from initial access to full compromise
- Example: subdomain takeover → phishing → credential harvest → lateral movement
- Include specific tools and techniques for each step

## 4. INTELLIGENCE CORRELATIONS
- Cross-reference findings to identify patterns
- Example: leaked email + DMARC missing = phishing campaign possible
- Example: dev subdomain + exposed port 3306 = database access possible
- Example: old Wayback URLs + .env pattern = config file exposure

## 5. THREAT ACTOR PROFILE
- What type of attacker would target this organization?
- What is their likely motivation (financial, espionage, hacktivism)?
- What TTPs (MITRE ATT&CK) apply?

## 6. IMMEDIATE ACTION ITEMS
- Top 3 things the security team must fix TODAY
- Each with: issue, risk if unpatched, fix command/steps

## 7. OSINT GAPS
- What additional intelligence would strengthen this assessment?
- Recommended next recon steps

Be extremely technical, specific, and actionable. Think like a nation-state threat actor."""


def build_osint_subdomain_intel_prompt(subdomains: list, domain: str) -> str:
    sub_list = "\n".join(subdomains[:100])
    return f"""You are an elite OSINT analyst. Analyze these subdomains for {domain}:

{sub_list}

Identify:
1. HIGH-VALUE TARGETS — which subdomains likely host sensitive systems?
   (admin panels, CI/CD, databases, internal tools, staging environments)

2. ATTACK VECTORS — for each high-value target:
   - Likely technology stack
   - Common vulnerabilities for that stack
   - Specific attack approach

3. SUBDOMAIN TAKEOVER CANDIDATES — which look like they might be abandoned?

4. INFRASTRUCTURE MAPPING — group subdomains by likely function:
   - Production vs staging vs dev
   - Internal tools vs public-facing
   - Third-party services

5. PRIORITY RECON ORDER — which 5 subdomains to investigate first and why?

Be specific and technical."""


def build_osint_secret_analysis_prompt(secrets_found: list, domain: str) -> str:
    secrets_text = "\n".join(str(s) for s in secrets_found[:50])
    return f"""You are a world-class security researcher analyzing leaked secrets for {domain}.

SECRETS/SENSITIVE DATA FOUND:
{secrets_text}

For each secret/finding:
1. CLASSIFY — what type of secret is this? (API key, JWT, password, internal URL, etc.)
2. VALIDATE — is this likely real or a false positive? Why?
3. EXPLOIT — how could an attacker use this?
4. BLAST RADIUS — what systems/data could be compromised?
5. REMEDIATION — exact steps to revoke/fix

Also provide:
- Overall severity of the leaked data (Critical/High/Medium/Low)
- Estimated time to exploit if left unpatched
- Whether this indicates a systemic security problem

Be extremely precise and technical."""


def build_osint_live_hosts_prompt(live_hosts: list, domain: str) -> str:
    hosts_text = "\n".join(str(h) for h in live_hosts[:50])
    return f"""You are an elite penetration tester analyzing live hosts for {domain}.

LIVE HOSTS DISCOVERED:
{hosts_text}

For this attack surface:
1. QUICK WINS — which hosts are most likely vulnerable right now?
   (Look for: admin panels, login pages, API endpoints, old tech stacks)

2. TECHNOLOGY ANALYSIS — identify tech stacks and their known CVEs

3. ATTACK PRIORITIZATION — rank hosts by attack value:
   - Data sensitivity
   - Exploitability
   - Lateral movement potential

4. SPECIFIC ATTACK VECTORS — for top 5 hosts:
   - Exact vulnerability to test
   - Tool/command to use
   - Expected result

5. STEALTH CONSIDERATIONS — how to test without triggering WAF/IDS?

Think like a red team operator with 10 years of experience."""
