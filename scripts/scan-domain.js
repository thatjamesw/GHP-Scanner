#!/usr/bin/env node

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, writeFile } from "node:fs/promises";
import dns from "node:dns/promises";
import tls from "node:tls";
import path from "node:path";

const execFileAsync = promisify(execFile);
const REQUEST_TIMEOUT_MS = 8000;
const MAX_DISCOVERED_HOSTS = 20;
const USER_AGENT = "scanner-mvp/0.1 (+local-passive-scan)";

async function main() {
  const input = process.argv[2];
  if (!input) {
    console.error("Usage: npm run scan -- <apex-domain>");
    process.exit(1);
  }

  const domain = normalizeApexDomain(input);
  const startedAt = new Date().toISOString();

  const report = {
    schemaVersion: 1,
    generatedAt: startedAt,
    target: domain,
    summary: {},
    findings: [],
    safeguards: {
      scanMode: "passive-first",
      notes: [
        "No brute-force subdomain enumeration is performed.",
        "HTTP collection is limited to the apex and common redirect target.",
        "DNS and WHOIS lookups use local system/network resolvers only.",
        "The scanner is intended for reconnaissance and posture review, not exploitation."
      ]
    },
    dns: {},
    whois: {},
    tls: {},
    http: {},
    page: {},
    lists: {},
    webstack: {},
    javascript: {},
    hosting: {},
    posture: {},
    discovery: {},
    exposures: {},
    ownership: {},
    relationships: {},
    footprint: {
      ips: [],
      nameservers: [],
      mail: [],
      webStackHosts: [],
      relatedDomains: []
    },
    raw: {}
  };

  const [dnsInfo, whoisInfo, tlsInfo, httpInfo] = await Promise.all([
    collectDns(domain),
    collectWhois(domain),
    collectTls(domain),
    collectHttp(domain)
  ]);

  report.dns = dnsInfo.cleaned;
  report.raw.dns = dnsInfo.raw;
  report.whois = whoisInfo.cleaned;
  report.raw.whois = whoisInfo.raw;
  report.tls = tlsInfo.cleaned;
  report.http = httpInfo.cleaned;

  report.footprint = buildFootprint(domain, dnsInfo.cleaned, tlsInfo.cleaned, httpInfo.cleaned, whoisInfo.cleaned);
  report.page = buildPageView(report);
  report.lists = buildListsView(report);
  report.webstack = buildWebstackView(report);
  report.javascript = buildJavaScriptView(report);
  report.hosting = buildHostingView(report);
  report.posture = buildPostureView(report);
  report.discovery = buildDiscoveryView(report);
  report.exposures = buildExposureView(report);
  report.ownership = buildOwnershipView(report);
  report.relationships = buildRelationshipsView();
  report.findings = buildFindings(report);
  report.summary = buildSummary(report);

  const outDir = path.resolve(process.cwd(), "reports");
  await mkdir(outDir, { recursive: true });
  const outFile = path.join(outDir, `${domain}.json`);
  await writeFile(outFile, JSON.stringify(report, null, 2));

  console.log(`Report written to ${outFile}`);
}

function normalizeApexDomain(input) {
  const cleaned = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(cleaned)) {
    throw new Error(`Invalid domain: ${input}`);
  }
  if (cleaned.split(".").length < 2) {
    throw new Error(`Expected apex domain, received: ${input}`);
  }
  return cleaned;
}

async function collectDns(domain) {
  const result = {
    cleaned: {
      a: [],
      aaaa: [],
      cname: [],
      mx: [],
      ns: [],
      txt: {},
      caa: [],
      availability: {
        dns: false,
        txt: false,
        dmarc: false
      }
    },
    raw: {}
  };

  const recordFetchers = [
    ["A", () => dns.resolve4(domain)],
    ["AAAA", () => dns.resolve6(domain)],
    ["CNAME", () => dns.resolveCname(domain)],
    ["MX", () => dns.resolveMx(domain)],
    ["NS", () => dns.resolveNs(domain)],
    ["TXT", () => dns.resolveTxt(domain)],
    ["CAA", () => dns.resolveCaa(domain)]
  ];

  for (const [type, getter] of recordFetchers) {
    try {
      const value = await getter();
      result.raw[type] = value;
      result.cleaned.availability.dns = true;
      if (type === "TXT") {
        result.cleaned.availability.txt = true;
        for (const row of value) {
          const joined = row.join("");
          if (joined.startsWith("v=spf1")) {
            result.cleaned.txt.spf = joined;
          } else if (joined.startsWith("v=DMARC1")) {
            result.cleaned.txt.dmarc = joined;
          } else if (joined.startsWith("google-site-verification=")) {
            result.cleaned.txt.verifications ??= [];
            result.cleaned.txt.verifications.push(joined);
          }
        }
      } else if (type === "MX") {
        result.cleaned.mx = value
          .map((row) => ({ exchange: row.exchange.replace(/\.$/, ""), priority: row.priority }))
          .sort((a, b) => a.priority - b.priority);
      } else if (type === "CAA") {
        result.cleaned.caa = value.map((row) => ({
          critical: row.critical,
          issue: row.issue ?? null,
          iodef: row.iodef ?? null,
          issuewild: row.issuewild ?? null
        }));
      } else if (type === "NS") {
        result.cleaned.ns = value.map((item) => item.replace(/\.$/, ""));
      } else if (type === "CNAME") {
        result.cleaned.cname = value.map((item) => item.replace(/\.$/, ""));
      } else if (type === "A") {
        result.cleaned.a = value;
      } else if (type === "AAAA") {
        result.cleaned.aaaa = value;
      }
    } catch (error) {
      result.raw[type] = { error: error.message };
    }
  }

  try {
    const dmarcRows = await dns.resolveTxt(`_dmarc.${domain}`);
    result.raw.DMARC = dmarcRows;
    result.cleaned.availability.dmarc = true;
    for (const row of dmarcRows) {
      const joined = row.join("");
      if (joined.startsWith("v=DMARC1")) {
        result.cleaned.txt.dmarc = joined;
      }
    }
  } catch (error) {
    result.raw.DMARC = { error: error.message };
  }

  return result;
}

async function collectWhois(domain) {
  try {
    const { stdout } = await execFileAsync("whois", [domain], { timeout: REQUEST_TIMEOUT_MS });
    const text = stdout.trim();
    return {
      cleaned: parseWhois(text),
      raw: text
    };
  } catch (error) {
    return {
      cleaned: { error: error.message },
      raw: ""
    };
  }
}

function parseWhois(text) {
  const fields = [
    ["registrar", /^Registrar:\s*(.+)$/im],
    ["registrantOrganization", /^Registrant Organization:\s*(.+)$/im],
    ["registrantEmail", /^Registrant Email:\s*(.+)$/im],
    ["registrantCountry", /^Registrant Country:\s*(.+)$/im],
    ["creationDate", /^Creation Date:\s*(.+)$/im],
    ["updatedDate", /^Updated Date:\s*(.+)$/im],
    ["expiryDate", /^Registry Expiry Date:\s*(.+)$/im],
    ["abuseEmail", /^Registrar Abuse Contact Email:\s*(.+)$/im],
    ["abusePhone", /^Registrar Abuse Contact Phone:\s*(.+)$/im]
  ];

  const parsed = {};
  for (const [key, regex] of fields) {
    const match = text.match(regex);
    if (match) {
      parsed[key] = match[1].trim();
    }
  }

  const statusMatches = [...text.matchAll(/^Domain Status:\s*(.+)$/gim)].map((match) => match[1].trim());
  if (statusMatches.length) {
    parsed.statuses = statusMatches;
  }

  const nameServerMatches = [...text.matchAll(/^Name Server:\s*(.+)$/gim)]
    .map((match) => match[1].trim().toLowerCase());
  if (nameServerMatches.length) {
    parsed.nameServers = [...new Set(nameServerMatches)];
  }

  parsed.relatednessFingerprint = buildWhoisFingerprint(parsed);
  parsed.embeddedDomains = extractWhoisDomains(text);

  return parsed;
}

function buildWhoisFingerprint(parsed) {
  const fingerprintFields = [
    parsed.registrar,
    parsed.registrantOrganization,
    parsed.registrantEmail,
    parsed.abuseEmail,
    ...(parsed.nameServers ?? [])
  ].filter(Boolean);

  return [...new Set(fingerprintFields)];
}

function extractWhoisDomains(text) {
  const domains = [...text.matchAll(/\b([a-z0-9.-]+\.[a-z]{2,})\b/gi)]
    .map((match) => match[1].toLowerCase())
    .filter((value) => !value.endsWith(".arpa"));

  return [...new Set(domains)].slice(0, MAX_DISCOVERED_HOSTS);
}

async function collectTls(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
        timeout: REQUEST_TIMEOUT_MS
      },
      () => {
        const peer = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        socket.end();

        resolve({
          cleaned: {
            protocol,
            cipher,
            subject: peer.subject ?? {},
            issuer: peer.issuer ?? {},
            serialNumber: peer.serialNumber ?? null,
            fingerprint256: peer.fingerprint256 ?? null,
            validFrom: peer.valid_from ?? null,
            validTo: peer.valid_to ?? null,
            subjectAltNames: parseSubjectAltNames(peer.subjectaltname)
          }
        });
      }
    );

    socket.on("error", (error) => {
      resolve({
        cleaned: {
          error: error.message,
          protocol: null,
          cipher: null,
          subject: {},
          issuer: {},
          serialNumber: null,
          fingerprint256: null,
          validFrom: null,
          validTo: null,
          subjectAltNames: []
        }
      });
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        cleaned: {
          error: "TLS timeout",
          protocol: null,
          cipher: null,
          subject: {},
          issuer: {},
          serialNumber: null,
          fingerprint256: null,
          validFrom: null,
          validTo: null,
          subjectAltNames: []
        }
      });
    });
  });
}

function parseSubjectAltNames(subjectAltNameField) {
  if (!subjectAltNameField) {
    return [];
  }

  return subjectAltNameField
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.startsWith("DNS:"))
    .map((item) => item.replace(/^DNS:/, "").toLowerCase())
    .slice(0, MAX_DISCOVERED_HOSTS);
}

async function collectHttp(domain) {
  const targets = [
    `https://${domain}`,
    `http://${domain}`
  ];

  const results = [];
  for (const url of targets) {
    try {
      results.push(await fetchUrl(url));
    } catch (error) {
      results.push({
        url,
        error: error.message
      });
    }
  }

  const preferred = results.find((item) => item.finalUrl) ?? results[0] ?? {};
  const securityHeaders = preferred.headers ? summarizeSecurityHeaders(preferred.headers) : {};
  const extractedHosts = extractHostsFromBody(domain, preferred.body ?? "");
  const availability = {
    http: results.some((item) => item.finalUrl)
  };
  const hosting = summarizeHosting(preferred.headers ?? {}, preferred.finalUrl ?? null);
  const cookiePosture = summarizeCookiePosture(preferred.cookies ?? []);
  const cors = summarizeCors(preferred.headers ?? {});
  const csp = analyzeCsp(preferred.headers?.["content-security-policy"] ?? null);
  const discovery = preferred.finalUrl ? await discoverWellKnown(preferred.finalUrl) : {};

  return {
    cleaned: {
      checks: results.map(({ body, ...rest }) => rest),
      status: preferred.status ?? null,
      ok: preferred.ok ?? false,
      redirected: Boolean(preferred.finalUrl && preferred.finalUrl !== preferred.url),
      effectiveUrl: preferred.finalUrl ?? null,
      title: extractTitle(preferred.body ?? ""),
      headers: preferred.headers ?? {},
      securityHeaders,
      extractedHosts,
      scripts: extractScripts(preferred.body ?? ""),
      clientHints: extractClientHints(preferred.body ?? "", preferred.headers ?? {}),
      cookies: preferred.cookies ?? [],
      cookiePosture,
      cors,
      csp,
      redirectChain: preferred.redirectChain ?? [],
      discovery,
      availability,
      hosting
    }
  };
}

async function fetchUrl(url) {
  const redirectChain = [];
  let currentUrl = url;

  for (let i = 0; i < 5; i += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        headers: { "user-agent": USER_AGENT },
        signal: controller.signal
      });
      const headers = Object.fromEntries(response.headers.entries());
      const status = response.status;
      const location = response.headers.get("location");
      const cookies = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [];

      redirectChain.push({
        url: currentUrl,
        status,
        location: location ?? null
      });

      if (status >= 300 && status < 400 && location) {
        currentUrl = new URL(location, currentUrl).toString();
        continue;
      }

      const body = await response.text();
      return {
        url,
        status: response.status,
        ok: response.ok,
        finalUrl: currentUrl,
        headers,
        cookies: parseSetCookies(cookies),
        body,
        redirectChain
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  throw new Error("Too many redirects");
}

function summarizeSecurityHeaders(headers) {
  const desired = {
    "strict-transport-security": "missing",
    "content-security-policy": "missing",
    "x-frame-options": "missing",
    "x-content-type-options": "missing",
    "referrer-policy": "missing",
    "permissions-policy": "missing"
  };

  for (const key of Object.keys(desired)) {
    if (headers[key]) {
      desired[key] = "present";
    }
  }

  return desired;
}

function parseSetCookies(setCookies) {
  return setCookies.map((value) => {
    const parts = value.split(";").map((part) => part.trim());
    const [nameValue, ...attributes] = parts;
    const [name] = nameValue.split("=");
    const parsed = {
      name,
      secure: false,
      httpOnly: false,
      sameSite: null,
      domain: null,
      path: null
    };

    for (const attribute of attributes) {
      const [key, raw] = attribute.split("=");
      const lower = key.toLowerCase();
      if (lower === "secure") {
        parsed.secure = true;
      } else if (lower === "httponly") {
        parsed.httpOnly = true;
      } else if (lower === "samesite") {
        parsed.sameSite = raw ?? null;
      } else if (lower === "domain") {
        parsed.domain = raw ?? null;
      } else if (lower === "path") {
        parsed.path = raw ?? null;
      }
    }

    return parsed;
  });
}

function summarizeCookiePosture(cookies) {
  const summary = {
    total: cookies.length,
    missingSecure: 0,
    missingHttpOnly: 0,
    missingSameSite: 0,
    broadDomain: 0
  };

  for (const cookie of cookies) {
    if (!cookie.secure) {
      summary.missingSecure += 1;
    }
    if (!cookie.httpOnly) {
      summary.missingHttpOnly += 1;
    }
    if (!cookie.sameSite) {
      summary.missingSameSite += 1;
    }
    if (cookie.domain?.startsWith(".")) {
      summary.broadDomain += 1;
    }
  }

  return summary;
}

function summarizeCors(headers) {
  const origin = headers["access-control-allow-origin"] ?? null;
  const credentials = headers["access-control-allow-credentials"] ?? null;
  const methods = headers["access-control-allow-methods"] ?? null;
  const flags = [];

  if (origin === "*" && credentials === "true") {
    flags.push("wildcard-origin-with-credentials");
  }
  if (origin === "*") {
    flags.push("wildcard-origin");
  }
  if (methods && /delete|put|patch/i.test(methods)) {
    flags.push("broad-methods");
  }

  return {
    origin,
    credentials,
    methods,
    flags
  };
}

function analyzeCsp(csp) {
  if (!csp) {
    return {
      present: false,
      grade: "missing",
      flags: []
    };
  }

  const flags = [];
  const lower = csp.toLowerCase();
  if (lower.includes("'unsafe-inline'")) {
    flags.push("unsafe-inline");
  }
  if (lower.includes("'unsafe-eval'")) {
    flags.push("unsafe-eval");
  }
  if (/default-src\s+\*/.test(lower) || /script-src\s+\*/.test(lower)) {
    flags.push("wildcard-source");
  }
  if (/frame-src\s+\*/.test(lower) || /connect-src\s+\*/.test(lower)) {
    flags.push("broad-directive");
  }

  const grade = flags.length >= 3 ? "weak" : flags.length > 0 ? "mixed" : "strong";
  return {
    present: true,
    grade,
    flags
  };
}

async function discoverWellKnown(effectiveUrl) {
  const base = new URL(effectiveUrl);
  const paths = [
    "/.well-known/security.txt",
    "/security.txt",
    "/robots.txt",
    "/sitemap.xml"
  ];
  const results = {};

  for (const pathname of paths) {
    try {
      const target = new URL(pathname, base).toString();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      try {
        const response = await fetch(target, {
          method: "GET",
          redirect: "follow",
          headers: { "user-agent": USER_AGENT },
          signal: controller.signal
        });
        const text = await response.text();
        results[pathname] = {
          status: response.status,
          ok: response.ok,
          finalUrl: response.url,
          preview: text.slice(0, 200).replace(/\s+/g, " ").trim()
        };
      } finally {
        clearTimeout(timeout);
      }
    } catch (error) {
      results[pathname] = {
        error: error.message
      };
    }
  }

  return results;
}

function extractTitle(html) {
  const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match ? match[1].trim() : null;
}

function extractHostsFromBody(domain, html) {
  const hostMatches = [...html.matchAll(/\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)].map((match) => match[1].toLowerCase());
  const related = [...new Set(hostMatches)]
    .filter((host) => host !== domain)
    .slice(0, MAX_DISCOVERED_HOSTS);

  return related;
}

function extractScripts(html) {
  const matches = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map((match) => match[1].trim())
    .slice(0, MAX_DISCOVERED_HOSTS);

  return [...new Set(matches)];
}

function extractClientHints(html, headers) {
  const hints = [];
  const body = html.toLowerCase();

  const checks = [
    ["next.js", body.includes("__next_data__") || body.includes("/_next/")],
    ["nuxt", body.includes("__nuxt__") || body.includes("/_nuxt/")],
    ["gatsby", body.includes("___gatsby")],
    ["webpack", body.includes("webpack")],
    ["google-tag-manager", body.includes("googletagmanager")],
    ["google-analytics", body.includes("google-analytics") || body.includes("gtag(")],
    ["adobe-launch", body.includes("assets.adobedtm.com")],
    ["cloudflare-turnstile", body.includes("challenges.cloudflare.com")]
  ];

  for (const [label, matched] of checks) {
    if (matched) {
      hints.push(label);
    }
  }

  if (headers["x-powered-by"]) {
    hints.push(`banner:${headers["x-powered-by"]}`);
  }

  return [...new Set(hints)];
}

function summarizeHosting(headers, effectiveUrl) {
  const signals = [
    ["server", headers.server],
    ["x-powered-by", headers["x-powered-by"]],
    ["via", headers.via],
    ["x-cache", headers["x-cache"]],
    ["x-served-by", headers["x-served-by"]],
    ["cf-cache-status", headers["cf-cache-status"]],
    ["cf-ray", headers["cf-ray"]],
    ["x-amz-cf-pop", headers["x-amz-cf-pop"]],
    ["alt-svc", headers["alt-svc"]]
  ].filter(([, value]) => Boolean(value));

  const indicators = [];
  const headerBlob = JSON.stringify(headers).toLowerCase();

  if (headerBlob.includes("cloudflare") || headers["cf-ray"] || headers["cf-cache-status"]) {
    indicators.push("cloudflare");
  }
  if (headerBlob.includes("fastly") || headers["x-served-by"]) {
    indicators.push("fastly");
  }
  if (headerBlob.includes("akamai")) {
    indicators.push("akamai");
  }
  if (headers["x-amz-cf-pop"] || headers["x-amz-cf-id"]) {
    indicators.push("cloudfront");
  }

  return {
    effectiveHostname: effectiveUrl ? new URL(effectiveUrl).hostname : null,
    headerSignals: signals.map(([key, value]) => ({ key, value })),
    indicators: [...new Set(indicators)],
    provider: inferHostingProvider(headers)
  };
}

function inferHostingProvider(headers) {
  const headerBlob = JSON.stringify(headers).toLowerCase();
  if (headerBlob.includes("vercel") || headers["x-vercel-id"] || headers["x-vercel-cache"]) {
    return "Vercel";
  }
  if (headerBlob.includes("sitecore") || headers["x-sc-rewrite"] || headers["x-matched-path"]) {
    return "Sitecore";
  }
  if (headerBlob.includes("cloudflare") || headers["cf-ray"] || headers["cf-cache-status"]) {
    return "Cloudflare";
  }
  if (headerBlob.includes("fastly") || headers["x-served-by"]) {
    return "Fastly";
  }
  if (headerBlob.includes("akamai")) {
    return "Akamai";
  }
  if (headers["x-amz-cf-pop"] || headers["x-amz-cf-id"]) {
    return "Amazon CloudFront";
  }
  return null;
}

function buildFootprint(domain, dnsInfo, tlsInfo, httpInfo, whoisInfo) {
  const ips = [...new Set([...(dnsInfo.a ?? []), ...(dnsInfo.aaaa ?? [])])];
  const nameservers = [...new Set([...(dnsInfo.ns ?? []), ...((whoisInfo.nameServers ?? []))])];
  const mail = [...new Set((dnsInfo.mx ?? []).map((row) => row.exchange))];
  const webStackHosts = [
    ...(dnsInfo.cname ?? []),
    ...(tlsInfo.subjectAltNames ?? []),
    ...(httpInfo.extractedHosts ?? []),
    ...(httpInfo.hosting?.effectiveHostname ? [httpInfo.hosting.effectiveHostname] : [])
  ];

  const dedupedHosts = [...new Set(webStackHosts)]
    .filter((host) => host !== domain)
    .slice(0, MAX_DISCOVERED_HOSTS);

  return {
    ips,
    nameservers,
    mail,
    webStackHosts: dedupedHosts,
    relatedDomains: []
  };
}

function registrableGuess(hostname) {
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length < 2) {
    return null;
  }

  const compoundSuffixes = new Set([
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "co.il",
    "com.au",
    "com.br",
    "com.mx",
    "co.jp",
    "com.sg"
  ]);
  const suffix = parts.slice(-2).join(".");
  if (parts.length >= 3 && compoundSuffixes.has(suffix)) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

function buildFindings(report) {
  const findings = [];
  const headers = report.http.securityHeaders ?? {};
  const httpAvailable = Boolean(report.http.availability?.http);
  const dnsAvailable = Boolean(report.dns.availability?.dns);
  const txtAvailable = Boolean(report.dns.availability?.txt);
  const dmarcAvailable = Boolean(report.dns.availability?.dmarc);

  if (httpAvailable) {
    for (const [header, state] of Object.entries(headers)) {
      if (state === "missing") {
        findings.push({
          severity: header === "content-security-policy" ? "medium" : "low",
          category: "security-header",
          title: `Missing ${header}`,
          description: `The apex response did not include ${header}.`
        });
      }
    }
  } else {
    findings.push({
      severity: "medium",
      category: "observation-gap",
      title: "HTTP inspection unavailable",
      description: "The scanner could not fetch the apex over HTTP(S), so header and page analysis could not be completed."
    });
  }

  const spf = report.dns.txt.spf;
  const dmarc = report.dns.txt.dmarc;
  if (txtAvailable && !spf) {
    findings.push({
      severity: "medium",
      category: "email-security",
      title: "Missing SPF",
      description: "No SPF TXT record was found for the apex domain."
    });
  }
  if (dmarcAvailable && !dmarc) {
    findings.push({
      severity: "medium",
      category: "email-security",
      title: "Missing DMARC",
      description: "No DMARC TXT record was found for the apex domain."
    });
  }

  if (dnsAvailable && (report.dns.caa ?? []).length === 0) {
    findings.push({
      severity: "low",
      category: "certificate-governance",
      title: "No CAA policy",
      description: "No CAA records were found, so certificate issuance is not explicitly constrained by DNS."
    });
  }

  if (httpAvailable && report.http.effectiveUrl?.startsWith("http://")) {
    findings.push({
      severity: "high",
      category: "transport-security",
      title: "HTTP without HTTPS redirect",
      description: "The apex appears to remain on HTTP instead of redirecting to HTTPS."
    });
  }

  if (report.tls.error) {
    findings.push({
      severity: "high",
      category: "tls",
      title: "TLS handshake failed",
      description: report.tls.error
    });
  }

  if (!dnsAvailable) {
    findings.push({
      severity: "medium",
      category: "observation-gap",
      title: "DNS lookup unavailable",
      description: "DNS resolution did not succeed in the current environment, so infrastructure and mail-security checks are incomplete."
    });
  }

  if ((report.javascript.clientHints ?? []).length > 0) {
    findings.push({
      severity: "low",
      category: "technology-disclosure",
      title: "Client-side stack signals exposed",
      description: `Observed JavaScript/runtime indicators: ${report.javascript.clientHints.join(", ")}.`
    });
  }

  if (report.exposures.bannerDisclosures.length > 0) {
    findings.push({
      severity: "low",
      category: "banner-disclosure",
      title: "Server/runtime banner disclosure",
      description: `Exposed banners: ${report.exposures.bannerDisclosures.map((item) => `${item.source}=${item.value}`).join("; ")}.`
    });
  }

  if (report.http.cookiePosture?.missingHttpOnly > 0) {
    findings.push({
      severity: "medium",
      category: "cookie-posture",
      title: "Cookies missing HttpOnly",
      description: `${report.http.cookiePosture.missingHttpOnly} observed cookies do not declare HttpOnly.`
    });
  }

  if (report.http.cookiePosture?.missingSecure > 0) {
    findings.push({
      severity: "medium",
      category: "cookie-posture",
      title: "Cookies missing Secure",
      description: `${report.http.cookiePosture.missingSecure} observed cookies do not declare Secure.`
    });
  }

  if ((report.http.cors?.flags ?? []).includes("wildcard-origin-with-credentials")) {
    findings.push({
      severity: "high",
      category: "cors",
      title: "CORS wildcard with credentials",
      description: "The response advertises Access-Control-Allow-Origin: * together with credential support."
    });
  } else if ((report.http.cors?.flags ?? []).includes("wildcard-origin")) {
    findings.push({
      severity: "low",
      category: "cors",
      title: "Wildcard CORS origin",
      description: "The response advertises Access-Control-Allow-Origin: *."
    });
  }

  if (report.http.csp?.grade === "weak") {
    findings.push({
      severity: "medium",
      category: "csp",
      title: "Weak CSP quality",
      description: `The CSP is present but permissive: ${report.http.csp.flags.join(", ")}.`
    });
  } else if (report.http.csp?.grade === "mixed") {
    findings.push({
      severity: "low",
      category: "csp",
      title: "CSP contains permissive directives",
      description: `The CSP includes: ${report.http.csp.flags.join(", ")}.`
    });
  }

  const securityTxt = report.discovery?.securityTxt;
  if (securityTxt && !securityTxt.ok) {
    findings.push({
      severity: "low",
      category: "security-contact",
      title: "security.txt not discovered",
      description: "No reachable security.txt file was observed at standard locations."
    });
  }

  return findings;
}

function buildSummary(report) {
  const severityOrder = ["high", "medium", "low"];
  const counts = { high: 0, medium: 0, low: 0 };
  for (const finding of report.findings) {
    counts[finding.severity] += 1;
  }

  const score = Math.max(0, 100 - (counts.high * 20) - (counts.medium * 10) - (counts.low * 4));
  const rating = score >= 85 ? "good" : score >= 65 ? "watch" : "risk";
  const topSeverity = severityOrder.find((severity) => counts[severity] > 0) ?? "none";

  return {
    score,
    rating,
    topSeverity,
    status: topSeverity === "high" ? "red" : topSeverity === "medium" ? "amber" : "green",
    findingCount: report.findings.length,
    ips: report.footprint.ips.length,
    webStackHosts: report.footprint.webStackHosts.length,
    relatedDomains: report.footprint.relatedDomains.length
  };
}

function buildPageView(report) {
  return {
    apexDomain: report.target,
    effectiveUrl: report.http.effectiveUrl ?? null,
    httpStatus: report.http.status ?? null,
    title: report.http.title ?? null,
    redirected: report.http.redirected ?? false,
    primaryIPs: report.footprint.ips,
    server: report.http.headers?.server ?? null,
    tlsIssuer: report.tls.issuer?.CN ?? null,
    tlsProtocol: report.tls.protocol ?? null,
    redirectChain: report.http.redirectChain ?? []
  };
}

function buildListsView(report) {
  return {
    domains: [...new Set([
      report.target,
      ...(report.tls.subjectAltNames ?? []).map(registrableGuess).filter(Boolean),
      ...(report.http.extractedHosts ?? []).map(registrableGuess).filter(Boolean)
    ])],
    hosts: report.footprint.webStackHosts,
    ips: report.footprint.ips,
    nameservers: report.footprint.nameservers,
    mailServers: report.footprint.mail,
    certificateNames: report.tls.subjectAltNames ?? []
  };
}

function buildWebstackView(report) {
  return {
    serverHeader: report.http.headers?.server ?? null,
    poweredBy: report.http.headers?.["x-powered-by"] ?? null,
    reverseProxy: report.http.headers?.via ?? null,
    cacheLayer: report.http.headers?.["x-cache"] ?? report.http.headers?.["cf-cache-status"] ?? null,
    deliveryHints: report.http.hosting?.indicators ?? [],
    headerSignals: report.http.hosting?.headerSignals ?? [],
    observedHosts: report.footprint.webStackHosts
  };
}

function buildJavaScriptView(report) {
  return {
    scriptSources: report.http.scripts ?? [],
    clientHints: report.http.clientHints ?? [],
    thirdPartyHosts: (report.http.extractedHosts ?? []).filter((host) => !host.endsWith(report.target))
  };
}

function buildHostingView(report) {
  return {
    providerHint: report.http.hosting?.provider ?? null,
    deliveryHints: report.http.hosting?.indicators ?? [],
    effectiveHostname: report.http.hosting?.effectiveHostname ?? null,
    edgeHeaders: (report.http.hosting?.headerSignals ?? []).filter((entry) =>
      ["via", "x-cache", "x-served-by", "cf-cache-status", "cf-ray", "x-amz-cf-pop", "server"].includes(entry.key)
    )
  };
}

function buildExposureView(report) {
  const bannerDisclosures = [];
  for (const [source, value] of [
    ["server", report.http.headers?.server],
    ["x-powered-by", report.http.headers?.["x-powered-by"]],
    ["via", report.http.headers?.via]
  ]) {
    if (value) {
      bannerDisclosures.push({ source, value });
    }
  }

  return {
    bannerDisclosures,
    cookiePosture: report.http.cookiePosture ?? {},
    cors: report.http.cors ?? {},
    csp: report.http.csp ?? {},
    cveCorrelation: {
      status: "coming-soon",
      rationale: "Reliable CVE matching needs a maintained software-version knowledge base. The scanner currently surfaces version and banner evidence only."
    }
  };
}

function buildPostureView(report) {
  return {
    cookiePosture: report.http.cookiePosture ?? {},
    cors: report.http.cors ?? {},
    csp: report.http.csp ?? {},
    securityHeaders: report.http.securityHeaders ?? {}
  };
}

function buildDiscoveryView(report) {
  const securityTxt = report.http.discovery?.["/.well-known/security.txt"]?.ok
    ? report.http.discovery["/.well-known/security.txt"]
    : report.http.discovery?.["/security.txt"] ?? null;

  return {
    securityTxt,
    robotsTxt: report.http.discovery?.["/robots.txt"] ?? null,
    sitemapXml: report.http.discovery?.["/sitemap.xml"] ?? null
  };
}

function buildOwnershipView(report) {
  return {
    registrar: report.whois.registrar ?? null,
    registrantOrganization: report.whois.registrantOrganization ?? null,
    registrantEmail: report.whois.registrantEmail ?? null,
    registrantCountry: report.whois.registrantCountry ?? null,
    abuseEmail: report.whois.abuseEmail ?? null,
    nameServers: report.whois.nameServers ?? [],
    fingerprint: report.whois.relatednessFingerprint ?? []
  };
}

function buildRelationshipsView() {
  return {
    whoisLinkedDomains: {
      status: "coming-soon",
      rationale: "Reverse WHOIS expansion requires a comparison corpus or external index. The local scanner currently fingerprints ownership data only.",
      candidates: []
    }
  };
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
