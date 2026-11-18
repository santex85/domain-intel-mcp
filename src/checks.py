"""Domain-level checks: DNS, TLS certificate, RDAP registration, email security, HTTP.

Only standard DNS queries, one TLS handshake on port 443 (a second unverified one only when
verification fails, to still read the certificate), one HTTP GET of the homepage, and RDAP
lookups via the IANA bootstrap. RDAP registrant/contact entities are never output.
"""
import asyncio
import re
import socket
import ssl
import time
from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import tldextract
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

_TLDX = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled Public Suffix List, no network


def registrable(domain: str) -> str:
    return _TLDX(domain).top_domain_under_public_suffix or domain


UA = "Mozilla/5.0 (compatible; DomainIntel/1.0; +https://github.com/santex85/domain-intel-mcp)"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$|^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+xn--[a-z0-9-]{1,59}$")


def now() -> datetime:
    return datetime.now(timezone.utc)


def days_until(dt: datetime | None) -> int | None:
    return None if dt is None else (dt - now()).days


def normalize_domain(raw: str) -> str:
    d = (raw or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0].rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return d


def valid_domain(d: str) -> bool:
    return bool(DOMAIN_RE.match(d))


# ---------------- DNS ----------------
DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SOA"]


def make_resolver(nameservers: list[str]) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = nameservers
    r.timeout = 4
    r.lifetime = 8
    return r


async def query(res, name: str, rtype: str) -> list[str]:
    """Return records as text; [] on NXDOMAIN/NoAnswer. Raises on timeouts."""
    try:
        ans = await res.resolve(name, rtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    if ans.rrset is None:
        return []
    out = []
    for r in ans:
        if rtype == "TXT":
            out.append(b"".join(r.strings).decode("utf-8", "replace"))
        elif rtype == "MX":
            out.append(f"{r.preference} {r.exchange.to_text().rstrip('.')}")
        elif rtype in ("NS", "CNAME"):
            out.append(r.target.to_text().rstrip("."))
        else:
            out.append(r.to_text())
    return sorted(out)


async def check_dns(res, domain: str) -> dict:
    out: dict = {}
    nx = False
    try:
        await res.resolve(domain, "SOA")
    except dns.resolver.NXDOMAIN:
        nx = True
    except Exception:
        pass
    if nx:
        return {"exists": False}

    async def one(t):
        try:
            return t, await query(res, domain, t), None
        except Exception as e:  # noqa: BLE001
            return t, [], f"{type(e).__name__}"

    for t, recs, err in await asyncio.gather(*(one(t) for t in DNS_TYPES)):
        out[t] = recs
        if err:
            out.setdefault("errors", {})[t] = err
    out["exists"] = True
    return out


# ---------------- SSL ----------------
def _cert_info(der: bytes) -> dict:
    c = x509.load_der_x509_certificate(der)
    def cn(name):
        a = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return a[0].value if a else None
    def org(name):
        a = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return a[0].value if a else None
    try:
        sans = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    vf = c.not_valid_before_utc
    vt = c.not_valid_after_utc
    return {
        "issuer": org(c.issuer) or cn(c.issuer),
        "issuerCN": cn(c.issuer),
        "subjectCN": cn(c.subject),
        "sans": sans,
        "validFrom": vf.isoformat(),
        "validTo": vt.isoformat(),
        "daysToExpiry": days_until(vt),
        "serialNumber": format(c.serial_number, "x"),
    }


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.split(".", 1)[1] == n[2:]:
            return True
    return False


async def _handshake(host: str, verify: bool):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # hostname is checked separately so a mismatch is reported, not fatal
    if not verify:
        ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host), timeout=10)
    try:
        so = writer.get_extra_info("ssl_object")
        return so.getpeercert(binary_form=True), so.version(), so.cipher()[0] if so.cipher() else None
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 3)
        except Exception:  # noqa: BLE001
            pass


async def check_ssl(host: str) -> dict:
    chain_ok, chain_error = True, None
    try:
        der, proto, cipher = await _handshake(host, verify=True)
    except ssl.SSLCertVerificationError as e:
        chain_ok, chain_error = False, e.verify_message or str(e)
        der, proto, cipher = await _handshake(host, verify=False)
    info = _cert_info(der)
    info.update({
        "protocol": proto,
        "cipher": cipher,
        "chainOk": chain_ok,
        "chainError": chain_error,
        "hostnameMatch": hostname_matches(host, info["sans"] or ([info["subjectCN"]] if info["subjectCN"] else [])),
    })
    return info


# ---------------- RDAP ----------------
class Rdap:
    BOOTSTRAP = "https://data.iana.org/rdap/dns.json"

    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self.map: dict[str, str] | None = None
        self.lock = asyncio.Lock()
        self.host_locks: dict[str, asyncio.Lock] = {}
        self.last_call: dict[str, float] = {}

    async def _load(self):
        async with self.lock:
            if self.map is None:
                r = await self.client.get(self.BOOTSTRAP, timeout=20)
                r.raise_for_status()
                m = {}
                for tlds, urls in r.json()["services"]:
                    url = next((u for u in urls if u.startswith("https")), urls[0])
                    for t in tlds:
                        m[t.lower()] = url if url.endswith("/") else url + "/"
                self.map = m

    async def _get(self, url: str) -> httpx.Response:
        host = httpx.URL(url).host
        lock = self.host_locks.setdefault(host, asyncio.Lock())
        async with lock:  # one request at a time per RDAP server, >=1 s apart
            for attempt in range(4):
                wait = 1.0 - (time.monotonic() - self.last_call.get(host, 0))
                if wait > 0:
                    await asyncio.sleep(wait)
                self.last_call[host] = time.monotonic()
                try:
                    r = await self.client.get(url, timeout=20, headers={"Accept": "application/rdap+json"})
                except httpx.HTTPError:
                    if attempt == 3:
                        raise
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                if r.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                    ra = r.headers.get("retry-after", "")
                    await asyncio.sleep(min(int(ra), 30) if ra.isdigit() else 3 * (attempt + 1))
                    continue
                return r
        raise RuntimeError("unreachable")

    async def lookup(self, domain: str) -> dict:
        await self._load()
        domain = registrable(domain)  # RDAP knows registered domains, not subdomains
        labels = domain.split(".")
        base = None
        for i in range(1, len(labels)):  # longest matching suffix
            base = self.map.get(".".join(labels[i:]))
            if base:
                break
        if not base:
            return {"available": False, "note": "No RDAP service for this TLD in the IANA bootstrap"}
        r = await self._get(f"{base}domain/{domain}")
        if r.status_code == 404:
            return {"available": True, "registered": False, "queriedDomain": domain, "server": base}
        r.raise_for_status()
        out = parse_rdap(r.json(), base)
        out["queriedDomain"] = domain
        return out


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_rdap(j: dict, server: str) -> dict:
    ev = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    registrar, iana_id = None, None
    for ent in j.get("entities", []):
        if "registrar" in (ent.get("roles") or []):  # organisation only; no other entity is read
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item[0] == "fn":
                    registrar = item[3]
            for pid in ent.get("publicIds", []) or []:
                if "IANA" in pid.get("type", ""):
                    iana_id = pid.get("identifier")
    exp = _parse_dt(ev.get("expiration"))
    sd = j.get("secureDNS") or {}
    return {
        "available": True,
        "registered": True,
        "server": server,
        "registrar": registrar,
        "registrarIanaId": iana_id,
        "created": ev.get("registration"),
        "updated": ev.get("last changed"),
        "expires": ev.get("expiration"),
        "daysToDomainExpiry": days_until(exp),
        "status": j.get("status", []),
        "nameservers": sorted((ns.get("ldhName") or "").lower().rstrip(".") for ns in j.get("nameservers", [])),
        "dnssec": bool(sd.get("delegationSigned")) if "delegationSigned" in sd else None,
    }


# ---------------- Email security ----------------
SPF_LOOKUP_MECHS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def _is_lookup(term: str) -> bool:
    t = term.lstrip("+-~?").lower()
    return (t.startswith(("include:", "exists:", "redirect=")) or t in ("a", "mx", "ptr")
            or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:")))


async def spf_lookups(res, record: str, depth: int = 0, seen: set | None = None) -> int:
    """Count DNS-querying terms per RFC 7208 4.6.4, following include/redirect (max depth 10)."""
    seen = seen if seen is not None else set()
    count = 0
    for term in record.split()[1:]:
        if not _is_lookup(term):
            continue
        count += 1
        t = term.lstrip("+-~?")
        target = t.split(":", 1)[1] if t.lower().startswith("include:") else (t.split("=", 1)[1] if t.lower().startswith("redirect=") else None)
        if target and depth < 10 and target not in seen and "%" not in target:
            seen.add(target)
            try:
                sub = [x for x in await query(res, target, "TXT") if x.lower().startswith("v=spf1")]
            except Exception:  # noqa: BLE001
                sub = []
            if sub:
                count += await spf_lookups(res, sub[0], depth + 1, seen)
    return count


def _tags(rec: str) -> dict:
    out = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


async def check_email(res, domain: str, txt: list[str] | None) -> dict:
    if txt is None:
        txt = await query(res, domain, "TXT")
    spf_recs = [t for t in txt if t.lower().startswith("v=spf1")]
    spf: dict = {"present": bool(spf_recs), "record": spf_recs[0] if spf_recs else None, "multipleRecords": len(spf_recs) > 1}
    if spf_recs:
        rec = spf_recs[0]
        all_term = next((t for t in rec.split()[1:] if t.lstrip("+-~?").lower() == "all"), None)
        spf["allMechanism"] = all_term if all_term is None or all_term[0] in "+-~?" else "+" + all_term
        spf["allQualifier"] = {"-": "fail", "~": "softfail", "?": "neutral", "+": "pass"}.get((spf["allMechanism"] or " ")[0])
        spf["redirect"] = next((t.split("=", 1)[1] for t in rec.split() if t.lower().startswith("redirect=")), None)
        spf["dnsLookups"] = await spf_lookups(res, rec)
        spf["tooManyLookups"] = spf["dnsLookups"] > 10

    dm = [t for t in await query(res, f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
    dmarc: dict = {"present": bool(dm)}
    if dm:
        tg = _tags(dm[0])
        dmarc.update({"p": tg.get("p"), "sp": tg.get("sp"), "pct": tg.get("pct"),
                      "ruaPresent": bool(tg.get("rua")), "rufPresent": bool(tg.get("ruf"))})

    mta = [t for t in await query(res, f"_mta-sts.{domain}", "TXT") if t.lower().startswith("v=stsv1")]
    tlsrpt = [t for t in await query(res, f"_smtp._tls.{domain}", "TXT") if t.lower().startswith("v=tlsrptv1")]
    bimi = [t for t in await query(res, f"default._bimi.{domain}", "TXT") if t.lower().startswith("v=bimi1")]
    return {
        "spf": spf,
        "dmarc": dmarc,
        "mtaSts": {"present": bool(mta), "id": _tags(mta[0]).get("id") if mta else None},
        "tlsRpt": {"present": bool(tlsrpt)},
        "bimi": {"present": bool(bimi), "hasLogo": bool(bimi and _tags(bimi[0]).get("l")), "hasVmc": bool(bimi and _tags(bimi[0]).get("a"))},
        "dkim": {"checked": False, "note": "DKIM keys live at <selector>._domainkey.<domain>; selectors are not discoverable from DNS without a sent email, so DKIM is out of scope."},
    }


# ---------------- HTTP ----------------
async def check_http(client: httpx.AsyncClient, domain: str) -> dict:
    t0 = time.monotonic()
    url = f"https://{domain}/"
    try:
        r = await client.get(url, timeout=20)
    except httpx.HTTPError as e:
        url = f"http://{domain}/"
        t0 = time.monotonic()
        r = await client.get(url, timeout=20)
        r.extensions["https_error"] = type(e).__name__
    elapsed = round((time.monotonic() - t0) * 1000)
    chain = [{"url": str(h.url), "status": h.status_code} for h in r.history]
    hsts = r.headers.get("strict-transport-security")
    return {
        "requestedUrl": url,
        "status": r.status_code,
        "finalUrl": str(r.url),
        "redirectChain": chain,
        "httpsError": r.extensions.get("https_error"),
        "hsts": {"present": bool(hsts) and r.url.scheme == "https", "header": hsts},
        "server": r.headers.get("server"),
        "responseTimeMs": elapsed,
    }
