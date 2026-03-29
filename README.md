# Scanner MVP

Passive-first technical reconnaissance for domain posture, hosting-layer evidence, IP ownership clues, and ownership metadata.

## What this project does

- Accepts a single apex domain such as `your-domain.com`
- Collects low-noise DNS, WHOIS, TLS, HTTP, hosting-layer metadata, IP ownership clues, normalized provider hints, and lightweight technology fingerprints
- Flags missing security headers and lightweight configuration issues
- Surfaces web stack clues such as `Server`, CDN/WAF hints, cache headers, TLS SANs, nameservers, and mail infrastructure
- Produces a technical report organized into `website`, `infrastructure`, `delivery`, `page`, `headers`, `webstack`, `hosting`, `javascript`, `network`, `ip`, `tls`, and `ownership` sections
- Produces a single JSON report that can be opened in a static GitHub Pages UI

## Why the architecture looks like this

A browser module can power the report viewer, but it cannot replace the collector for the full scan. A pure browser or GitHub Pages frontend cannot directly perform:

- WHOIS queries
- raw DNS lookups
- TLS socket inspection
- reliable cross-origin HTTP analysis against arbitrary sites
- IP WHOIS / PTR enrichment with consistent operator control

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
- a small number of HTTP requests to the apex for headers, redirect behavior, and page-linked hosts

## Local usage

Requirements:

- Node.js 20+
- `dig`, `whois`, `host`, and `openssl` available on the machine

Run a scan:

```bash
npm run scan -- your-domain.com
```

This writes:

```text
reports/your-domain.com.json
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

The bundled sample report in [example-report.json](/Users/jameswright/dev/_mvp/scanner/samples/example-report.json) is generated from `tori.fi`.

## Deploying to GitHub Pages

This repo now includes a GitHub Actions workflow at [deploy-pages.yml](/Users/jameswright/dev/_mvp/scanner/.github/workflows/deploy-pages.yml) that publishes the static viewer automatically from `main`.

The workflow deploys only:

- `index.html`
- `styles.css`
- `src/`
- `samples/`

Important:

- GitHub Pages only hosts the viewer
- domain scanning still happens locally
- the generated JSON report is loaded client-side and does not need to be stored server-side
- `reports/` is ignored and is not published

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
- hosting-layer hints from `Server`, `Via`, `X-Cache`, `CF-*`, and related headers
- normalized cloud and delivery-provider hints such as AWS, Azure, GCP, Cloudflare, Fastly, Akamai, and CloudFront
- IP ownership hints such as ASN, PTR, netblock, country, and estimated region/city when present in WHOIS data
- ownership fingerprinting from WHOIS registrar and registrant fields
- JavaScript/runtime clues from script paths and common framework markers such as `Next.js`, `Nuxt`, and `webpack`
- broader technology hints such as WordPress, Drupal, Shopify, React, Vue, Angular, SvelteKit, Segment, HubSpot, Datadog, Sentry, and Stripe when observable from the page
- confidence and evidence objects for inferred technologies, cloud providers, delivery providers, and IP role classification
- exposure clues from banner disclosure such as `Server` and `X-Powered-By`

## Limits and next steps

Without third-party data sources, related-domain discovery is necessarily conservative. The current MVP infers technical footprint from:

- certificate SANs
- referenced page hosts
- MX infrastructure
- nameservers

`WHOIS-linked domains` is currently marked as coming soon. True reverse-WHOIS expansion needs either a local comparison corpus or an external index; the current scanner only fingerprints ownership metadata from the single WHOIS record it can observe.

`CVE correlation` is also marked as coming soon. The scanner now surfaces software and runtime banner evidence, but reliable CVE matching needs a maintained version-to-advisory knowledge base.

The current expansion path for OSINT is to borrow the categories of evidence that browser sandboxes expose, not to embed third-party result schemas directly into our own report model. A useful reference is the [urlscan quickstart](https://docs.urlscan.io/guides/quickstart): browser execution produces contacted domains and IPs, requested resources, DOM and screenshot artifacts, cookies, and brand-targeting signals. Those are good design inputs for our own enrichment roadmap even when collection stays first-party.

Good next steps for the next iteration:

1. Add redirect-chain and response-header capture beyond the final apex fetch.
2. Deepen the IP layer with ASN clustering, PTR confidence, netblock grouping, and provider normalization.
3. Add robots, sitemap, and security.txt discovery.
4. Add optional reverse-WHOIS enrichment once we decide on a local index or external source.
5. Add a browser-assisted collector mode backed by our own service if we want rendered page telemetry without exposing secrets or losing low-level access.
6. Add confidence and evidence objects for each finding.
