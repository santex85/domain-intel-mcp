"""Domain checks shared by the MCP tools (ported from the Domain Intel Apify actor)."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from checks import (UA, Rdap, check_dns, check_email, check_http, check_ssl, make_resolver,  # noqa: E402,F401
                    normalize_domain, now, valid_domain)

ALL_CHECKS = ["dns", "ssl", "rdap", "email", "http"]


def find_issues(row: dict) -> list[str]:
    iss = []
    d, s, r, e, h = (row.get(k) or {} for k in ("dns", "ssl", "rdap", "email", "http"))
    if d:
        if d.get("exists") is False:
            iss.append("domain_not_found")
        else:
            if not d.get("CAA"):
                iss.append("no_caa")
            if not d.get("AAAA"):
                iss.append("no_ipv6")
            if not d.get("MX"):
                iss.append("no_mx")
    if s:
        dte = s.get("daysToExpiry")
        if dte is not None and dte < 0:
            iss.append("ssl_expired")
        elif dte is not None and dte < 30:
            iss.append("ssl_expiring_<30d")
        if s.get("chainOk") is False:
            iss.append("ssl_chain_invalid")
        if s.get("hostnameMatch") is False:
            iss.append("ssl_hostname_mismatch")
        if s.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
            iss.append("ssl_old_protocol")
    if row.get("errors", {}).get("ssl"):
        iss.append("ssl_unavailable")
    if r.get("registered"):
        dd = r.get("daysToDomainExpiry")
        if dd is not None and dd < 0:
            iss.append("domain_expired")
        elif dd is not None and dd < 30:
            iss.append("domain_expiring_<30d")
        if r.get("dnssec") is False:
            iss.append("no_dnssec")
    if e:
        spf, dm = e.get("spf", {}), e.get("dmarc", {})
        if not spf.get("present"):
            iss.append("no_spf")
        else:
            q = spf.get("allQualifier")
            if q == "softfail":
                iss.append("spf_softfail")
            elif q in ("neutral", "pass"):
                iss.append(f"spf_{q}_all")
            elif q is None and not spf.get("redirect"):
                iss.append("spf_no_all")
            if spf.get("tooManyLookups"):
                iss.append("spf_too_many_lookups")
            if spf.get("multipleRecords"):
                iss.append("spf_multiple_records")
        if not dm.get("present"):
            iss.append("no_dmarc")
        else:
            if dm.get("p") == "none":
                iss.append("dmarc_p_none")
            if not dm.get("ruaPresent"):
                iss.append("dmarc_no_rua")
        if not e.get("mtaSts", {}).get("present"):
            iss.append("no_mta_sts")
    if h:
        if h.get("status", 0) >= 400:
            iss.append(f"http_status_{h['status']}")
        if not str(h.get("finalUrl", "")).startswith("https://"):
            iss.append("no_https_redirect")
        elif not h.get("hsts", {}).get("present"):
            iss.append("no_hsts")
    if row.get("errors", {}).get("http"):
        iss.append("http_unreachable")
    return iss


def billable(row: dict) -> bool:
    """Charge only valid, existing domains where DNS, RDAP or SSL returned data."""
    if set(row.get("issues") or []) & {"invalid_domain", "domain_not_found"}:
        return False
    return bool((row.get("dns") or {}).get("exists") or (row.get("rdap") or {}).get("registered") or row.get("ssl"))


async def run_check(row: dict, name: str, coro):
    try:
        row[name] = await coro
    except Exception as ex:  # noqa: BLE001 - per-check isolation
        row[name] = None
        row.setdefault("errors", {})[name] = f"{type(ex).__name__}: {str(ex)[:200]}"


async def process(raw: str, checks: list[str], res, client, rdap) -> dict:
    domain = normalize_domain(raw)
    row: dict = {"domain": domain, "input": raw, "checkedAt": now().isoformat(timespec="seconds")}
    if not valid_domain(domain):
        row.update({"ok": False, "errors": {"input": "Invalid domain name"}, "issues": ["invalid_domain"]})
        return row
    if "dns" in checks:
        await run_check(row, "dns", check_dns(res, domain))
    exists = (row.get("dns") or {}).get("exists", True)
    tasks = []
    if exists:
        if "ssl" in checks:
            tasks.append(run_check(row, "ssl", check_ssl(domain)))
        if "email" in checks:
            tasks.append(run_check(row, "email", check_email(res, domain, (row.get("dns") or {}).get("TXT"))))
        if "http" in checks:
            tasks.append(run_check(row, "http", check_http(client, domain)))
    if "rdap" in checks:
        tasks.append(run_check(row, "rdap", rdap.lookup(domain)))
    await asyncio.gather(*tasks)
    row["issues"] = find_issues(row)
    row["ok"] = not row.get("errors")
    return row


