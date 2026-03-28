# Scanner MVP

Passive-first domain scanning for security posture and digital footprint mapping.

## What this project does

- Accepts a single apex domain such as `fortytwo.io`
- Collects low-noise DNS, WHOIS, TLS, and HTTP metadata
- Flags missing security headers and lightweight configuration issues
- Surfaces related hosts, mail infrastructure, nameservers, TLS SANs, and likely related domains
- Produces a single JSON report that can be opened in a static GitHub Pages UI

## Why the architecture looks like this

A pure GitHub Pages frontend cannot directly perform:

- WHOIS queries
- raw DNS lookups
- TLS socket inspection
- reliable cross-origin HTTP analysis against arbitrary sites

Because of that, this MVP splits into:

- `scripts/scan-domain.js`: local scanner that generates a report
- `index.html` + `src/app.js`: static report viewer for GitHub Pages

This keeps the system:

- API-free
- storage-free
- conservative in network behavior
- deployable as a static site

## Scan philosophy

This project intentionally avoids:

- brute-force subdomain enumeration
- port scanning
- mass crawling
- exploit testing
- third-party enrichment APIs

Instead it uses passive-first collection:

- DNS records: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CAA`
- WHOIS via local `whois`
- TLS certificate metadata from the apex
- a small number of HTTP requests to the apex for headers and page-linked hosts

## Local usage

Requirements:

- Node.js 20+
- `dig`, `whois`, `host`, and `openssl` available on the machine

Run a scan:

```bash
npm run scan -- fortytwo.io
```

This writes:

```text
reports/fortytwo.io.json
```

Start the static viewer locally:

```bash
npm run serve
```

Then open:

```text
http://localhost:4173
```

Load the report JSON from `reports/`.

## Deploying to GitHub Pages

Because the frontend is plain static assets, you can publish the repository root to GitHub Pages directly.

Important:

- GitHub Pages only hosts the viewer
- domain scanning still happens locally
- the generated JSON report is loaded client-side and does not need to be stored server-side

## Current heuristics

The MVP currently checks:

- missing `Strict-Transport-Security`
- missing `Content-Security-Policy`
- missing `X-Frame-Options`
- missing `X-Content-Type-Options`
- missing `Referrer-Policy`
- missing `Permissions-Policy`
- missing SPF
- missing DMARC
- missing CAA
- lack of HTTPS redirect
- TLS handshake failures

## Limits and next steps

Without third-party data sources, related-domain discovery is necessarily conservative. It currently infers footprint from:

- certificate SANs
- referenced page hosts
- MX infrastructure
- nameservers

Good next steps for the next iteration:

1. Add parsing for `_dmarc.<domain>` instead of apex-only DMARC detection.
2. Support optional authenticated scans with stronger ownership checks.
3. Add robots, sitemap, and security.txt discovery.
4. Add GitHub Actions generation of a report artifact without storing historical scan data.
5. Add confidence and evidence objects for each finding.
