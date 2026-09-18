# API Surface Mapper

A single-page tool that maps the public API surface a browser can reach for any
domain. Type a domain and it reports API-style hostnames that resolve, endpoints
listed in a public API directory, and spec files it can read directly, then maps
each finding to the OWASP API Security Top 10 (2023) category worth reviewing. It
runs entirely in the browser with no backend.

An optional [server engine](#server-engine-optional) runs in Docker and lifts the
limits a browser imposes: certificate transparency enumeration instead of a
wordlist, direct reads instead of CORS-blocked candidates, and parsed specs
instead of links to them. The page detects it automatically and falls back to the
browser engine when it is not there.

**New to this?** [`SETUP.md`](SETUP.md) walks through the server engine from
nothing installed to your first scan, assuming no experience with Docker, Python
or the command line. The same guide is published as a page at
[`/setup-guide.html`](https://tbgh011.github.io/API-surface-mapper/setup-guide.html).

## Live site

Hosted on GitHub Pages: https://tbgh011.github.io/API-surface-mapper/

A quickstart guide ships alongside it at
[`/quickstart-guide.html`](https://tbgh011.github.io/API-surface-mapper/quickstart-guide.html),
covering how to read the evidence tiers, how to verify candidates from a
terminal, and what the tool deliberately does not claim.

## Usage

Enter a domain (like `stripe.com`) and select **Map surface**. Results stream in
under three evidence tiers:

- **Documented** (green): a real, openable spec URL from the APIs.guru directory.
- **Live host** (amber): an API-style hostname that resolves in DNS right now.
- **Verify manually** (blue): a plausible spec path on a resolving host that the
  browser cannot read.

For the third tier, the **Copy verification commands** button gives you curl
lines to confirm each candidate from a terminal.

Each finding also carries a small OWASP chip linking to the specific risk
category, and a **Security review guidance** panel below the results explains the
categories your findings touch.

The quickstart guide walks through all of this in more detail, including a table
of every spec path probed and how to interpret each status code you get back.

## How it works, and its limits

A browser cannot crawl a domain the way a server can. Cross-origin rules (CORS)
stop it from reading responses off hosts you do not control, so anything
unreadable is reported as a candidate to check, not a confirmed API.

Evidence sources, all of which allow cross-origin reads:

- DNS-over-HTTPS (Google and Cloudflare) for host resolution
- The [APIs.guru](https://apis.guru) open directory for documented specs
- Direct fetches for spec files that permit reading

Fuller discovery (complete subdomain enumeration, response inspection, parsed
specs) needs a server-side scanner. The hosted page stays client-side on purpose
so it can run for free with no maintenance; the server engine below is opt-in and
runs on your own machine.

## Server engine (optional)

The browser engine is fenced in by CORS and by DNS-over-HTTPS returning nothing
but A records. The server engine removes both fences. It is a Python service that
serves this same page and a scan API from one container, so the page talks to it
same-origin with no CORS setup and no mixed-content warning.

```bash
docker compose up --build
```

Then open <http://localhost:8000>. A **Server engine** badge appears under the
input; the link beside it switches back to the browser engine at any time. The
GitHub Pages deployment is untouched and keeps working exactly as before.

If that one line assumes more than you want it to, [`SETUP.md`](SETUP.md) covers
installing Docker, getting the code, opening a terminal in the right folder, and
what to do when something goes wrong.

### What it adds

| | Browser engine | Server engine |
| --- | --- | --- |
| Hostnames | 52-word guess list | certificate transparency (crt.sh, Cert Spotter) plus the wordlist |
| DNS | A record, one CNAME | full CNAME chains, AAAA, wildcard detection, dangling-CNAME (takeover) candidates |
| Responses | blocked by CORS on hosts you do not control | read directly, redirects followed, status and headers inspected |
| Specs | "a spec exists" | paths, operations, declared auth schemes, operations declaring no auth, widest object schema |
| OpenID Connect | listed as a candidate | issuer and endpoints parsed, weak grants and `none` client auth flagged |
| GraphQL | hostname only | introspection query sent, exposed type count reported |
| Headers | not visible | CORS reflection and credentials, version banners, missing HSTS |

Two behaviours worth knowing. A host that answers identically on every probed
path (a CDN returning 403 to all twelve, say) is reported once as host-wide
behaviour, not twelve times as protected endpoints. And a domain with a wildcard
DNS record has its wildcard-only names excluded, since otherwise everything looks
live.

### Configuration

All optional, set in `docker-compose.yml`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCOPE_ALLOWLIST` | empty | comma-separated domain suffixes this instance may scan; empty means unrestricted |
| `RATE_LIMIT_PER_MIN` | `12` | scans per minute per client IP |
| `MAX_HOSTS` | `400` | hostnames resolved per scan, most API-shaped first |
| `MAX_PROBE_ORIGINS` | `25` | hosts the spec probe runs against |
| `HTTP_CONCURRENCY` | `24` | simultaneous outbound requests |
| `ALLOWED_ORIGINS` | empty | browser origins allowed to call the API cross-origin; empty means same-origin only |

### Safety

The container binds to `127.0.0.1` only and runs as an unprivileged user. Every
hostname is resolved and checked against the private, loopback, link-local and
cloud-metadata ranges before a connection is opened, and each redirect hop is
checked again, so a hostile DNS record or redirect cannot turn the scanner into
an SSRF proxy. Set `SCOPE_ALLOWLIST` if you want the instance to refuse anything
outside domains you are authorised to test.

This is still passive discovery. It reads what is published, sends one GraphQL
introspection query, and does not authenticate, fuzz, or attempt any exploit.

## OWASP API Security Top 10 mapping

Findings are mapped to the [OWASP API Security Top 10
(2023)](https://owasp.org/projects/api-security-project) so the output points you
toward what to review, not just what exists. Risk links point at the project
repository, which renders the 2023 edition text and survived the owasp.org site
redesign that retired the old `/API-Security/` documentation URLs. The mapping is
intentionally conservative:

- Live hosts map by name. An `auth` or `sso` host points to API2 Broken
  Authentication, a `graphql` host to API4 Unrestricted Resource Consumption, a
  `webhook` or `integrations` host to API7 SSRF, and everything else to API9
  Improper Inventory Management.
- Readable specs map to API3 Broken Object Property Level Authorization and API8
  Security Misconfiguration, since an exposed schema is what you use to check for
  property over-exposure and leaked configuration.
- Candidate endpoints map by path, so an OpenID discovery document points to
  API2.

Two things this mapping is honest about:

- The headline category is API9 Improper Inventory Management. Discovery is an
  inventory problem, and undocumented hosts or old versions sitting beside
  current ones are exactly what API9 covers.
- The most damaging risks, the authorization flaws (API1 BOLA, API5 BFLA, API6),
  are invisible to passive discovery and only surface under authenticated
  testing. The guidance panel says so rather than implying a clean result.

This is a review checklist derived from passive discovery. It is not a
vulnerability assessment, and a mapped category is a prompt to review, not proof
of a flaw.

## Deploy

1. Put `index.html` and `quickstart-guide.html` at the repo root.
2. Repo **Settings**, **Pages**, Source: Deploy from a branch, pick your branch
   and the root folder.
3. Open the `github.io` URL Pages gives you.

Opening the file inside the repo file browser shows the source only. The Pages
URL is what actually runs it.

## Files

- `index.html` - the tool. Single file, vanilla JS, no build step. Runs standalone
  and uses the server engine automatically when one is answering on its origin.
- `quickstart-guide.html` - the usage guide: how to read the results, what each
  tier means, and what the tool does not claim.
- `setup-guide.html` - the beginner setup guide as a styled page, linked from the
  tool's header and footer. Same content as `SETUP.md`; keep the two in step.
- `SETUP.md` - the same guide in Markdown, for people who arrive at the repository
  rather than the hosted page.
- `docker-compose.yml` - brings up the optional server engine on `localhost:8000`.
- `server/` - the Python service. `app/main.py` is the FastAPI app (static UI plus
  a Server-Sent Events scan stream), `app/safety.py` holds the SSRF and scope
  guards, and `app/engine/` holds one module per evidence source: `sources.py`
  (certificate transparency), `dns_probe.py`, `http_probe.py`, `specs.py`,
  `owasp.py`, and `scan.py` for orchestration.

## License

MIT. Swap in whatever you prefer.
