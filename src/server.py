"""Domain Intel MCP server: DNS, SSL/TLS, RDAP (WHOIS), email security (SPF/DMARC/MTA-STS) and HTTP checks.

Read-only, public data only. RDAP contact entities are ignored, so no personal data is returned.
"""
import asyncio
import os
import sys

import httpx
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, os.path.dirname(__file__))
from core import ALL_CHECKS, UA, Rdap, make_resolver, normalize_domain, process  # noqa: E402

mcp = FastMCP("domain-intel", host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "8080")))
RESOLVERS = ["1.1.1.1", "8.8.8.8"]


async def _run(domains: list[str], checks: list[str]) -> list[dict]:
    checks = [c for c in checks if c in ALL_CHECKS] or ALL_CHECKS
    seen, uniq = set(), []
    for d in domains:
        n = normalize_domain(d)
        if n and n not in seen:
            seen.add(n)
            uniq.append(d)
    res = make_resolver(RESOLVERS)
    sem = asyncio.Semaphore(5)
    async with httpx.AsyncClient(headers={"User-Agent": UA}, follow_redirects=True, max_redirects=10, timeout=20) as client:
        rdap = Rdap(client)

        async def one(d):
            async with sem:
                try:
                    return await asyncio.wait_for(process(d, checks, res, client, rdap), timeout=60)
                except Exception as ex:  # noqa: BLE001 - per-domain isolation
                    return {"domain": normalize_domain(d), "ok": False, "errors": {"domain": f"{type(ex).__name__}: {str(ex)[:200]}"}}
        return await asyncio.gather(*(one(d) for d in uniq))


@mcp.tool()
async def check_domain(domain: str, checks: list[str] | None = None) -> dict:
    """Full health and security report for one domain.

    checks: any of "dns", "ssl", "rdap", "email", "http" (default: all).
    Returns DNS records (A/AAAA/MX/NS/TXT/CAA), SSL certificate (issuer, expiry, chain, hostname match, TLS version),
    RDAP registration (registrar, created/expiry dates, status, nameservers, DNSSEC), email security (SPF with lookup
    count, DMARC policy, MTA-STS), HTTP (status, final URL, HSTS) and a list of detected issues such as
    "ssl_expiring_<30d", "no_dmarc", "spf_softfail", "domain_expiring_<30d".
    """
    return (await _run([domain], checks or ALL_CHECKS))[0]


@mcp.tool()
async def check_domains(domains: list[str], checks: list[str] | None = None) -> list[dict]:
    """Same report as check_domain for up to 20 domains at once (duplicates are removed)."""
    return await _run(domains[:20], checks or ALL_CHECKS)


@mcp.tool()
async def email_security(domain: str) -> dict:
    """Email deliverability/anti-spoofing check: SPF (record, 'all' qualifier, DNS lookup count >10), DMARC (policy, rua),
    MTA-STS, MX records, plus the issues found. Useful before cold outreach or when emails land in spam."""
    r = (await _run([domain], ["dns", "email"]))[0]
    return {"domain": r.get("domain"), "mx": (r.get("dns") or {}).get("MX"), "email": r.get("email"),
            "issues": [i for i in r.get("issues", []) if i.startswith(("no_spf", "spf", "no_dmarc", "dmarc", "no_mta", "no_mx"))],
            "errors": r.get("errors")}


@mcp.tool()
async def ssl_certificate(domain: str) -> dict:
    """SSL/TLS certificate details for a host: issuer, subject names, valid from/to, days to expiry, chain validity,
    hostname match and negotiated TLS protocol."""
    r = (await _run([domain], ["dns", "ssl"]))[0]
    return {"domain": r.get("domain"), "ssl": r.get("ssl"),
            "issues": [i for i in r.get("issues", []) if i.startswith("ssl")], "errors": r.get("errors")}


@mcp.tool()
async def domain_expiry(domains: list[str]) -> list[dict]:
    """Registration and certificate expiry for up to 20 domains: registrar, domain expiry date and days left,
    SSL expiry and days left. Handy for monitoring a portfolio of domains."""
    rows = await _run(domains[:20], ["dns", "rdap", "ssl"])
    return [{"domain": r.get("domain"), "registrar": (r.get("rdap") or {}).get("registrar"),
             "domainExpires": (r.get("rdap") or {}).get("expires"), "daysToDomainExpiry": (r.get("rdap") or {}).get("daysToDomainExpiry"),
             "sslExpires": (r.get("ssl") or {}).get("validTo"), "daysToSslExpiry": (r.get("ssl") or {}).get("daysToExpiry"),
             "issues": [i for i in r.get("issues", []) if "expir" in i]} for r in rows]


from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "healthy"})


if __name__ == "__main__":
    mcp.run(transport=os.environ.get("MCP_TRANSPORT", "streamable-http"))
