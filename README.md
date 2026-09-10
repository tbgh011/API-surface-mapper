# API Surface Mapper

A single-page tool that maps the public API surface a browser can reach for any
domain. Type a domain and it reports API-style hostnames that resolve, endpoints
listed in a public API directory, and spec files it can read directly, then maps
each finding to the OWASP API Security Top 10 (2023) category worth reviewing. It
runs entirely in the browser with no backend.

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

Fuller discovery (complete subdomain enumeration, authenticated crawling,
response inspection) needs a server-side scanner. This tool stays client-side on
purpose so it can be hosted for free with no maintenance.

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

- `index.html` - the tool. Single file, vanilla JS, no build step.
- `quickstart-guide.html` - the usage guide, linked from the tool's header and
  footer.

## License

MIT. Swap in whatever you prefer.
