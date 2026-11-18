# Domain Intel MCP server (DNS, SSL, RDAP/WHOIS, email security)

MCP server that gives an AI agent a health and security report for any domain: DNS records, the SSL/TLS certificate,
RDAP registration data (the modern replacement for WHOIS), email anti-spoofing setup (SPF, DMARC, MTA-STS, TLS-RPT,
BIMI) and the homepage's HTTP behaviour (redirects, HSTS). Each report ends with a list of detected issues such as
`ssl_expiring_<30d`, `no_dmarc` or `spf_too_many_lookups`. No API key is needed.

It is ported from the `domain-intel` Apify actor. The checks and issue rules are the same, but there is no Apify
dependency.

## Tools

| Tool | Parameters | What it does |
|---|---|---|
| `check_domain` | `domain` (str), `checks` (list, optional: any of `dns`, `ssl`, `rdap`, `email`, `http`; default all) | Full report for one domain: DNS (A/AAAA/MX/NS/TXT/CAA), certificate (issuer, SANs, validity, days to expiry, chain validity, hostname match, TLS version, cipher), RDAP (registrar, created/expiry dates, status, nameservers, DNSSEC), email security, HTTP (status, final URL, redirect chain, HSTS, response time) and `issues` |
| `check_domains` | `domains` (list, max 20), `checks` (optional) | The same report for up to 20 domains in parallel. Duplicates are removed. |
| `email_security` | `domain` (str) | SPF (record, `all` qualifier, recursive DNS lookup count and the >10 limit), DMARC (policy, `rua`), MTA-STS, TLS-RPT, BIMI, MX, plus email-related issues |
| `ssl_certificate` | `domain` (str) | Certificate details and SSL issues only |
| `domain_expiry` | `domains` (list, max 20) | Registrar, domain expiry date and days left, certificate expiry and days left, for monitoring a portfolio |

Example calls:

```jsonc
// check_domain
{"domain": "example.com"}
{"domain": "https://www.example.com/page", "checks": ["dns", "ssl"]}   // URLs are normalised to the host
// check_domains
{"domains": ["example.com", "example.org"], "checks": ["rdap", "email"]}
// email_security
{"domain": "google.com"}
// domain_expiry
{"domains": ["python.org", "github.com"]}
```

Sample `domain_expiry` result:

```json
[{"domain": "python.org", "registrar": "Gandi SAS", "domainExpires": "2033-03-28T05:00:00Z", "daysToDomainExpiry": 2322,
  "sslExpires": "2027-02-14T13:03:45+00:00", "daysToSslExpiry": 88, "issues": []}]
```

Issue codes: `invalid_domain`, `domain_not_found`, `no_caa`, `no_ipv6`, `no_mx`, `ssl_expired`, `ssl_expiring_<30d`,
`ssl_chain_invalid`, `ssl_hostname_mismatch`, `ssl_old_protocol`, `ssl_unavailable`, `domain_expired`,
`domain_expiring_<30d`, `no_dnssec`, `no_spf`, `spf_softfail`, `spf_neutral_all`, `spf_pass_all`, `spf_no_all`,
`spf_too_many_lookups`, `spf_multiple_records`, `no_dmarc`, `dmarc_p_none`, `dmarc_no_rua`, `no_mta_sts`,
`http_status_<code>`, `no_https_redirect`, `no_hsts`, `http_unreachable`.

## Install and run

```bash
git clone https://github.com/santex85/domain-intel-mcp && cd domain-intel-mcp
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python src/server.py                         # streamable-http on 0.0.0.0:8080, endpoint /mcp, health at /health
PORT=8095 .venv/bin/python src/server.py               # other port
MCP_TRANSPORT=stdio .venv/bin/python src/server.py     # stdio, for local MCP clients
.venv/bin/python tests/live_test.py                    # live smoke test of every tool
```

Environment variables: `HOST` (default `0.0.0.0`), `PORT` (default `8080`), `MCP_TRANSPORT` (`streamable-http`,
`stdio` or `sse`; default `streamable-http`).

## Limits

- `check_domains` and `domain_expiry` take at most 20 domains per call and run 5 at a time. Each domain has a 60 s
  budget; a failing check is reported under `errors` and does not stop the others.
- DNS goes to the public resolvers 1.1.1.1 and 8.8.8.8.
- RDAP: at most one request per second per RDAP server, with retries on 429/5xx. Some ccTLDs (for example `.de`,
  `.ru`, `.io` at the time of writing) have no RDAP service in the IANA bootstrap, so registration data is not available for them.
  Subdomains are looked up as their registrable domain (Public Suffix List).
- DKIM is not checked: selectors cannot be discovered from DNS without a sent email.
- The HTTP check fetches the homepage once over HTTPS, falling back to HTTP.

## Data sources and terms

- DNS answers come from public resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8) under their normal public-DNS terms.
- The certificate is read from a single TLS handshake with the domain on port 443. A second, unverified handshake is
  made only when verification fails, so the certificate can still be reported.
- Registration data comes from the registries' public RDAP services found through the
  [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json). Each registry sets its own terms of use for RDAP data;
  check them before bulk or commercial reuse. RDAP contact entities (registrant, admin, tech) are never read into the
  output, so no personal data is returned.
- The server only does what a browser or mail server would do: standard DNS queries, one TLS handshake and one GET of
  the homepage. It does not scan ports or probe for vulnerabilities. Check only domains you have a legitimate reason
  to check.

## Use with Claude Desktop or another MCP client

Local (stdio). Clone the repo, create the venv as above, then add this to `claude_desktop_config.json`
(or your client's MCP config), with the paths changed to where you cloned it:

```json
{
  "mcpServers": {
    "domain-intel": {
      "command": "/path/to/domain-intel-mcp/.venv/bin/python",
      "args": ["/path/to/domain-intel-mcp/src/server.py"],
      "env": {"MCP_TRANSPORT": "stdio"}
    }
  }
}
```

Remote (streamable HTTP). Run `.venv/bin/python src/server.py` on a server and point any client that supports
remote MCP servers at `http://<host>:8080/mcp`. `GET /health` returns `{"status": "healthy"}`.

## License

MIT, see [LICENSE](LICENSE). The data returned by the tools stays under the terms of its sources (see above).
