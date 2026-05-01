"""
Vexor OSINT Backend Router
API-key-dependent modules proxied here — keys live on Render, never on client
Modules: Shodan · VirusTotal · AlienVault OTX · URLScan.io · Chaos (ProjectDiscovery)
OSINT AI: World-class intelligence correlation via multi-provider AI
"""
import os
import asyncio
import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.auth.dependencies import get_current_user

router = APIRouter()

# ─── Keys from Render environment ────────────────────────────────────────────
SHODAN_KEY    = os.getenv("SHODAN_API_KEY", "")
VT_KEY        = os.getenv("VIRUSTOTAL_API_KEY", "")
OTX_KEY       = os.getenv("OTX_API_KEY", "")
URLSCAN_KEY   = os.getenv("URLSCAN_API_KEY", "")
CHAOS_KEY     = os.getenv("CHAOS_API_KEY", "")

TIMEOUT = 20  # seconds per external call


class OSINTRequest(BaseModel):
    target: str          # domain, IP, or URL
    modules: list[str] = []   # empty = run all available


class OSINTResult(BaseModel):
    module: str
    severity: str
    vuln: str
    evidence: str
    description: str
    available: bool = True   # False if key missing


# ─── Helper ──────────────────────────────────────────────────────────────────

def _domain_from(target: str) -> str:
    """Extract clean domain from target string"""
    from urllib.parse import urlparse
    parsed = urlparse(target if "://" in target else f"https://{target}")
    domain = parsed.hostname or target
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.lower().strip()


# ─── Main endpoint ────────────────────────────────────────────────────────────

@router.post("/scan")
async def osint_scan(req: OSINTRequest, user=Depends(get_current_user)):
    """
    Run all available OSINT modules for a target.
    Returns list of findings — skips modules whose API key is not configured.
    """
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")

    domain = _domain_from(target)
    requested = set(req.modules) if req.modules else {
        "shodan", "virustotal", "otx", "urlscan", "chaos"
    }

    tasks = []
    if "shodan" in requested:
        tasks.append(_shodan(domain))
    if "virustotal" in requested:
        tasks.append(_virustotal(domain))
    if "otx" in requested:
        tasks.append(_otx(domain))
    if "urlscan" in requested:
        tasks.append(_urlscan(domain))
    if "chaos" in requested:
        tasks.append(_chaos(domain))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = []
    for r in results:
        if isinstance(r, Exception):
            continue
        if isinstance(r, list):
            findings.extend(r)
        elif r is not None:
            findings.append(r)

    return {"target": domain, "findings": [f.model_dump() for f in findings]}


@router.get("/status")
async def osint_status(user=Depends(get_current_user)):
    """Returns which OSINT modules are available (keys configured)"""
    return {
        "shodan":     bool(SHODAN_KEY),
        "virustotal": bool(VT_KEY),
        "otx":        bool(OTX_KEY),
        "urlscan":    bool(URLSCAN_KEY),
        "chaos":      bool(CHAOS_KEY),
    }


# ─── Module 1: Shodan ─────────────────────────────────────────────────────────

async def _shodan(domain: str) -> list[OSINTResult]:
    if not SHODAN_KEY:
        return [OSINTResult(
            module="shodan", severity="INFO",
            vuln="Shodan: API Key Not Configured",
            evidence="Set SHODAN_API_KEY on Render backend",
            description="Shodan module unavailable — no API key.",
            available=False,
        )]

    results = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            # DNS resolve via Shodan
            resp = await client.get(
                f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={SHODAN_KEY}"
            )
            ip = None
            if resp.status_code == 200:
                data = resp.json()
                ip = data.get(domain)

            if not ip:
                return results

            # Host info
            host_resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
            )
            if host_resp.status_code != 200:
                return results

            host = host_resp.json()
            ports = host.get("ports", [])
            org   = host.get("org", "N/A")
            isp   = host.get("isp", "N/A")
            os_   = host.get("os", "N/A")
            vulns = host.get("vulns", [])
            tags  = host.get("tags", [])

            # Build evidence
            evidence_lines = [
                f"IP: {ip}",
                f"Org: {org}",
                f"ISP: {isp}",
                f"OS: {os_}",
                f"Open Ports: {', '.join(str(p) for p in ports[:20])}",
            ]
            if tags:
                evidence_lines.append(f"Tags: {', '.join(tags)}")
            if vulns:
                evidence_lines.append(f"CVEs: {', '.join(list(vulns)[:10])}")

            severity = "CRITICAL" if vulns else ("HIGH" if ports else "INFO")

            results.append(OSINTResult(
                module="shodan",
                severity=severity,
                vuln=f"Shodan: {len(ports)} ports, {len(vulns)} CVEs" if vulns
                     else f"Shodan: {len(ports)} open ports found",
                evidence="\n".join(evidence_lines),
                description=(
                    f"Shodan data for {domain} ({ip}): "
                    f"Org={org}, {len(ports)} open ports"
                    + (f", {len(vulns)} known CVEs: {', '.join(list(vulns)[:5])}" if vulns else "")
                ),
            ))

            # Individual CVE findings
            for cve in list(vulns)[:5]:
                results.append(OSINTResult(
                    module="shodan",
                    severity="HIGH",
                    vuln=f"Known Vulnerability: {cve}",
                    evidence=f"Shodan reports {cve} on {ip}",
                    description=f"Shodan detected {cve} on {domain} ({ip}). Verify and patch.",
                ))

    except Exception as e:
        results.append(OSINTResult(
            module="shodan", severity="INFO",
            vuln="Shodan: Query Failed",
            evidence=str(e)[:200],
            description="Shodan query encountered an error.",
        ))

    return results


# ─── Module 2: VirusTotal ─────────────────────────────────────────────────────

async def _virustotal(domain: str) -> list[OSINTResult]:
    if not VT_KEY:
        return [OSINTResult(
            module="virustotal", severity="INFO",
            vuln="VirusTotal: API Key Not Configured",
            evidence="Set VIRUSTOTAL_API_KEY on Render backend",
            description="VirusTotal module unavailable — no API key.",
            available=False,
        )]

    results = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VT_KEY},
            )
            if resp.status_code != 200:
                return results

            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})

            stats = attrs.get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            total      = sum(stats.values()) or 1

            reputation = attrs.get("reputation", 0)
            categories = attrs.get("categories", {})
            cat_vals   = list(set(categories.values()))[:5]

            # Passive DNS subdomains
            sub_resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=20",
                headers={"x-apikey": VT_KEY},
            )
            subdomains = []
            if sub_resp.status_code == 200:
                sub_data = sub_resp.json().get("data", [])
                subdomains = [s.get("id", "") for s in sub_data if s.get("id")]

            severity = "CRITICAL" if malicious > 5 else (
                "HIGH" if malicious > 0 else (
                "MEDIUM" if suspicious > 0 else "INFO"
            ))

            evidence = (
                f"Malicious: {malicious}/{total} engines\n"
                f"Suspicious: {suspicious}\n"
                f"Harmless: {harmless}\n"
                f"Reputation score: {reputation}\n"
                f"Categories: {', '.join(cat_vals) if cat_vals else 'N/A'}"
            )
            if subdomains:
                evidence += f"\nPassive subdomains ({len(subdomains)}): {', '.join(subdomains[:10])}"

            results.append(OSINTResult(
                module="virustotal",
                severity=severity,
                vuln=(
                    f"VirusTotal: MALICIOUS ({malicious} engines)" if malicious > 0
                    else f"VirusTotal: Clean ({harmless} engines clear)"
                ),
                evidence=evidence,
                description=(
                    f"VirusTotal analysis for {domain}: "
                    f"{malicious} malicious, {suspicious} suspicious detections. "
                    f"Reputation: {reputation}."
                ),
            ))

            if subdomains:
                results.append(OSINTResult(
                    module="virustotal",
                    severity="INFO",
                    vuln=f"VT Passive DNS: {len(subdomains)} Subdomains",
                    evidence="\n".join(subdomains[:20]),
                    description=f"VirusTotal passive DNS found {len(subdomains)} subdomains for {domain}.",
                ))

    except Exception as e:
        results.append(OSINTResult(
            module="virustotal", severity="INFO",
            vuln="VirusTotal: Query Failed",
            evidence=str(e)[:200],
            description="VirusTotal query encountered an error.",
        ))

    return results


# ─── Module 3: AlienVault OTX ─────────────────────────────────────────────────

async def _otx(domain: str) -> list[OSINTResult]:
    if not OTX_KEY:
        return [OSINTResult(
            module="otx", severity="INFO",
            vuln="AlienVault OTX: API Key Not Configured",
            evidence="Set OTX_API_KEY on Render backend",
            description="OTX module unavailable — no API key.",
            available=False,
        )]

    results = []
    try:
        headers = {"X-OTX-API-KEY": OTX_KEY}
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            # General info
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers=headers,
            )
            if resp.status_code != 200:
                return results

            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            reputation  = data.get("reputation", 0)
            asn         = data.get("asn", "N/A")
            city        = data.get("city", "N/A")
            country     = data.get("country_name", "N/A")

            # Passive DNS
            dns_resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers=headers,
            )
            passive_dns = []
            if dns_resp.status_code == 200:
                dns_data = dns_resp.json().get("passive_dns", [])
                passive_dns = [
                    f"{r.get('hostname', '')} → {r.get('address', '')}"
                    for r in dns_data[:10]
                ]

            # Malware
            malware_resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/malware",
                headers=headers,
            )
            malware_count = 0
            if malware_resp.status_code == 200:
                malware_count = malware_resp.json().get("count", 0)

            severity = "HIGH" if pulse_count > 10 or malware_count > 0 else (
                "MEDIUM" if pulse_count > 0 else "INFO"
            )

            evidence = (
                f"Threat pulses: {pulse_count}\n"
                f"Malware samples: {malware_count}\n"
                f"Reputation: {reputation}\n"
                f"ASN: {asn}\n"
                f"Location: {city}, {country}"
            )
            if passive_dns:
                evidence += f"\nPassive DNS:\n" + "\n".join(passive_dns)

            results.append(OSINTResult(
                module="otx",
                severity=severity,
                vuln=(
                    f"OTX: {pulse_count} Threat Pulses, {malware_count} Malware Samples"
                    if pulse_count > 0 or malware_count > 0
                    else "OTX: No Threat Intelligence Found"
                ),
                evidence=evidence,
                description=(
                    f"AlienVault OTX for {domain}: "
                    f"{pulse_count} threat pulses, {malware_count} malware samples. "
                    f"Location: {city}, {country}."
                ),
            ))

    except Exception as e:
        results.append(OSINTResult(
            module="otx", severity="INFO",
            vuln="OTX: Query Failed",
            evidence=str(e)[:200],
            description="AlienVault OTX query encountered an error.",
        ))

    return results


# ─── Module 4: URLScan.io ─────────────────────────────────────────────────────

async def _urlscan(domain: str) -> list[OSINTResult]:
    if not URLSCAN_KEY:
        return [OSINTResult(
            module="urlscan", severity="INFO",
            vuln="URLScan.io: API Key Not Configured",
            evidence="Set URLSCAN_API_KEY on Render backend",
            description="URLScan module unavailable — no API key.",
            available=False,
        )]

    results = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            # Search existing scans
            resp = await client.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5",
                headers={"API-Key": URLSCAN_KEY},
            )
            if resp.status_code != 200:
                return results

            data = resp.json()
            total  = data.get("total", 0)
            scans  = data.get("results", [])

            if not scans:
                results.append(OSINTResult(
                    module="urlscan", severity="INFO",
                    vuln="URLScan.io: No Previous Scans Found",
                    evidence=f"No scans found for {domain}",
                    description=f"URLScan.io has no scan history for {domain}.",
                ))
                return results

            latest = scans[0]
            page   = latest.get("page", {})
            task   = latest.get("task", {})
            stats  = latest.get("stats", {})

            screenshot = latest.get("screenshot", "")
            scan_url   = f"https://urlscan.io/result/{latest.get('_id', '')}/"
            ip         = page.get("ip", "N/A")
            server     = page.get("server", "N/A")
            country    = page.get("country", "N/A")
            malicious  = stats.get("malicious", 0)
            requests   = stats.get("requests", 0)

            # Linked domains
            linked_domains = []
            dom_resp = await client.get(
                f"https://urlscan.io/api/v1/result/{latest.get('_id', '')}/",
                headers={"API-Key": URLSCAN_KEY},
            )
            if dom_resp.status_code == 200:
                dom_data = dom_resp.json()
                linked_domains = list(set(
                    d.get("domain", "")
                    for d in dom_data.get("lists", {}).get("domains", [])
                    if d.get("domain") and domain not in d.get("domain", "")
                ))[:10]

            severity = "HIGH" if malicious > 0 else "INFO"
            evidence = (
                f"Total scans: {total}\n"
                f"Latest scan: {task.get('time', 'N/A')}\n"
                f"IP: {ip} ({country})\n"
                f"Server: {server}\n"
                f"HTTP requests: {requests}\n"
                f"Malicious resources: {malicious}\n"
                f"Scan report: {scan_url}"
            )
            if linked_domains:
                evidence += f"\nLinked domains: {', '.join(linked_domains[:8])}"

            results.append(OSINTResult(
                module="urlscan",
                severity=severity,
                vuln=(
                    f"URLScan: {malicious} Malicious Resources Detected"
                    if malicious > 0
                    else f"URLScan: {total} Scans, {requests} HTTP Requests"
                ),
                evidence=evidence,
                description=(
                    f"URLScan.io found {total} scans for {domain}. "
                    f"Server: {server}, IP: {ip} ({country}). "
                    + (f"{malicious} malicious resources detected." if malicious > 0 else "")
                ),
            ))

    except Exception as e:
        results.append(OSINTResult(
            module="urlscan", severity="INFO",
            vuln="URLScan: Query Failed",
            evidence=str(e)[:200],
            description="URLScan.io query encountered an error.",
        ))

    return results


# ─── Module 5: Chaos (ProjectDiscovery) ──────────────────────────────────────

async def _chaos(domain: str) -> list[OSINTResult]:
    if not CHAOS_KEY:
        return [OSINTResult(
            module="chaos", severity="INFO",
            vuln="Chaos DB: API Key Not Configured",
            evidence="Set CHAOS_API_KEY on Render backend",
            description="Chaos passive subdomain DB unavailable — no API key.",
            available=False,
        )]

    results = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
                headers={"Authorization": CHAOS_KEY},
            )
            if resp.status_code == 401:
                return [OSINTResult(
                    module="chaos", severity="INFO",
                    vuln="Chaos DB: Invalid API Key",
                    evidence="401 Unauthorized from Chaos API",
                    description="Chaos API key is invalid or expired.",
                    available=False,
                )]

            if resp.status_code != 200:
                return results

            data = resp.json()
            subdomains = data.get("subdomains", [])
            count = len(subdomains)

            if count == 0:
                results.append(OSINTResult(
                    module="chaos", severity="INFO",
                    vuln="Chaos DB: No Subdomains in Database",
                    evidence=f"Chaos has no passive data for {domain}",
                    description=f"ProjectDiscovery Chaos DB has no subdomains for {domain}.",
                ))
                return results

            # Interesting subdomain patterns
            interesting_patterns = [
                "admin", "dev", "staging", "test", "api", "internal",
                "jenkins", "gitlab", "kibana", "grafana", "db", "vpn",
                "backup", "old", "legacy", "beta", "preprod", "uat",
            ]
            interesting = [
                s for s in subdomains
                if any(p in s.lower() for p in interesting_patterns)
            ]

            severity = "MEDIUM" if interesting else "INFO"
            evidence = (
                f"Total subdomains: {count}\n"
                f"Sample: {', '.join(subdomains[:15])}"
            )
            if interesting:
                evidence += f"\nInteresting: {', '.join(interesting[:10])}"

            results.append(OSINTResult(
                module="chaos",
                severity=severity,
                vuln=f"Chaos DB: {count} Passive Subdomains Found"
                     + (f" ({len(interesting)} interesting)" if interesting else ""),
                evidence=evidence,
                description=(
                    f"ProjectDiscovery Chaos DB found {count} passive subdomains for {domain}. "
                    + (f"Interesting: {', '.join(interesting[:5])}" if interesting else "")
                ),
            ))

    except Exception as e:
        results.append(OSINTResult(
            module="chaos", severity="INFO",
            vuln="Chaos DB: Query Failed",
            evidence=str(e)[:200],
            description="Chaos DB query encountered an error.",
        ))

    return results


# ─── OSINT AI Endpoints ───────────────────────────────────────────────────────

class OSINTCorrelateRequest(BaseModel):
    domain: str
    findings_summary: str   # JSON string of all findings


class OSINTSubdomainIntelRequest(BaseModel):
    domain: str
    subdomains: list[str]


class OSINTSecretAnalysisRequest(BaseModel):
    domain: str
    secrets: list[str]


class OSINTLiveHostsRequest(BaseModel):
    domain: str
    live_hosts: list[str]


@router.post("/ai/correlate")
async def osint_ai_correlate(
    req: OSINTCorrelateRequest,
    user=Depends(get_current_user),
):
    """
    Master OSINT AI — correlates ALL findings into attack chains,
    threat profile, and prioritized action items.
    World-class intelligence analysis.
    """
    from app.ai.orchestrator import AIOrchestrator
    orchestrator = AIOrchestrator()
    result = await orchestrator.osint_correlate(
        findings_summary=req.findings_summary,
        domain=req.domain,
    )
    return {"result": result, "domain": req.domain}


@router.post("/ai/subdomain-intel")
async def osint_ai_subdomain_intel(
    req: OSINTSubdomainIntelRequest,
    user=Depends(get_current_user),
):
    """AI analysis of subdomain list — attack vectors, high-value targets"""
    from app.ai.orchestrator import AIOrchestrator
    orchestrator = AIOrchestrator()
    result = await orchestrator.osint_subdomain_intel(
        subdomains=req.subdomains,
        domain=req.domain,
    )
    return {"result": result, "domain": req.domain}


@router.post("/ai/secret-analysis")
async def osint_ai_secret_analysis(
    req: OSINTSecretAnalysisRequest,
    user=Depends(get_current_user),
):
    """AI deep analysis of leaked secrets and sensitive data"""
    from app.ai.orchestrator import AIOrchestrator
    orchestrator = AIOrchestrator()
    result = await orchestrator.osint_secret_analysis(
        secrets_found=req.secrets,
        domain=req.domain,
    )
    return {"result": result, "domain": req.domain}


@router.post("/ai/live-hosts")
async def osint_ai_live_hosts(
    req: OSINTLiveHostsRequest,
    user=Depends(get_current_user),
):
    """AI attack surface analysis of live hosts"""
    from app.ai.orchestrator import AIOrchestrator
    orchestrator = AIOrchestrator()
    result = await orchestrator.osint_live_hosts_analysis(
        live_hosts=req.live_hosts,
        domain=req.domain,
    )
    return {"result": result, "domain": req.domain}
