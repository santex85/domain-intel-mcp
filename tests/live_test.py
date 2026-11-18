"""Live smoke test: calls every tool against real DNS/TLS/RDAP/HTTP. Run: .venv/bin/python tests/live_test.py"""
import asyncio, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import server  # noqa: E402


def show(name, r, ok):
    s = json.dumps(r, ensure_ascii=False, default=str)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {len(s)} bytes | {s[:500]}\n")
    return bool(ok)


async def main():
    res = []
    tools = await server.mcp.list_tools()
    res.append(show("list_tools", [t.name for t in tools], len(tools) == 5))
    r = await server.check_domain("github.com")
    res.append(show("check_domain", r, r.get("dns", {}).get("A") and r.get("ssl", {}).get("issuer") and r.get("rdap", {}).get("registrar")))
    r = await server.check_domains(["example.com", "not a domain", "example.com"])
    res.append(show("check_domains", r, len(r) == 2 and "invalid_domain" in r[1]["issues"]))
    r = await server.email_security("google.com")
    res.append(show("email_security", r, r["email"]["spf"]["present"] and r["email"]["dmarc"]["present"]))
    r = await server.ssl_certificate("wikipedia.org")
    res.append(show("ssl_certificate", r, (r.get("ssl") or {}).get("daysToExpiry") is not None))
    r = await server.domain_expiry(["python.org"])
    res.append(show("domain_expiry", r, r[0].get("daysToDomainExpiry") is not None))
    print(f"{sum(res)}/{len(res)} passed")
    sys.exit(0 if all(res) else 1)


asyncio.run(main())
