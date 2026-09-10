# API Surface Mapper

A single-page tool that maps the public API surface a browser can reach for any
domain. Type a domain and it reports API-style hostnames that resolve, endpoints
listed in a public API directory, and spec files it can read directly. It runs
entirely in the browser with no backend.

## Live site

Hosted on GitHub Pages: `https://YOURNAME.github.io/API-surface-mapper/`

## Usage

Enter a domain (like `stripe.com`) and select **Map surface**. Results stream in
under three evidence tiers:

- **Documented** (green): a real, openable spec URL from the APIs.guru directory.
- **Live host** (amber): an API-style hostname that resolves in DNS right now.
- **Verify manually** (blue): a plausible spec path on a resolving host that the
  browser cannot read.

For the third tier, the **Copy verification commands** button gives you curl
lines to confirm each candidate from a terminal.

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

## Deploy

1. Put `index.html` at the repo root.
2. Repo **Settings**, **Pages**, Source: Deploy from a branch, pick your branch
   and the root folder.
3. Open the `github.io` URL Pages gives you.

Opening the file inside the repo file browser shows the source only. The Pages
URL is what actually runs it.

## License

MIT. Swap in whatever you prefer.
