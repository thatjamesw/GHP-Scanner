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
      availability,
      hosting
    }
  };
}

async function fetchUrl(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      headers: { "user-agent": USER_AGENT },
      signal: controller.signal
    });

    const headers = Object.fromEntries(response.headers.entries());
    const body = await response.text();

    return {
      url,
      status: response.status,
      ok: response.ok,
      finalUrl: response.url,
      headers,
      body
    };
  } finally {
    clearTimeout(timeout);
  }
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
    indicators: [...new Set(indicators)]
  };
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
    tlsProtocol: report.tls.protocol ?? null
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
