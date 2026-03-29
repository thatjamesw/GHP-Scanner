#!/usr/bin/env node

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, writeFile } from "node:fs/promises";
import dns from "node:dns/promises";
import tls from "node:tls";
import net from "node:net";
import path from "node:path";
import { createHash } from "node:crypto";

const execFileAsync = promisify(execFile);
const REQUEST_TIMEOUT_MS = 8000;
const MAX_DISCOVERED_HOSTS = 20;
const MAX_IP_INTEL = 12;
const PORT_TIMEOUT_MS = 1200;
const ACTIVE_PORTS = [
  { port: 21, service: "ftp", family: "file-transfer", severity: "medium" },
  { port: 22, service: "ssh", family: "remote-access", severity: "low" },
  { port: 23, service: "telnet", family: "remote-access", severity: "high" },
  { port: 25, service: "smtp", family: "mail", severity: "low" },
  { port: 53, service: "dns", family: "infrastructure", severity: "low" },
  { port: 80, service: "http", family: "web", severity: "low" },
  { port: 110, service: "pop3", family: "mail", severity: "medium" },
  { port: 143, service: "imap", family: "mail", severity: "medium" },
  { port: 443, service: "https", family: "web", severity: "low" },
  { port: 465, service: "smtps", family: "mail", severity: "low" },
  { port: 587, service: "submission", family: "mail", severity: "low" },
  { port: 993, service: "imaps", family: "mail", severity: "low" },
  { port: 995, service: "pop3s", family: "mail", severity: "low" },
  { port: 3306, service: "mysql", family: "database", severity: "high" },
  { port: 3389, service: "rdp", family: "remote-access", severity: "high" },
  { port: 5432, service: "postgres", family: "database", severity: "high" },
  { port: 6379, service: "redis", family: "database", severity: "high" },
  { port: 8080, service: "http-alt", family: "web", severity: "medium" },
  { port: 8443, service: "https-alt", family: "web", severity: "medium" },
  { port: 9200, service: "elasticsearch", family: "search", severity: "high" },
  { port: 27017, service: "mongodb", family: "database", severity: "high" }
];
const COMMON_DKIM_SELECTORS = [
  "default",
  "default1",
  "default2",
  "selector1",
  "selector2",
  "selector3",
  "google",
  "dkim",
  "k1",
  "s1",
  "s2",
  "s1024",
  "mail",
  "smtp",
  "mandrill",
  "mailgun",
  "sendgrid",
  "amazonses",
  "zoho",
  "krs",
  "m1",
  "m2"
];
const USER_AGENT = "scanner-mvp/0.1 (+local-passive-scan)";

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.domain) {
    console.error("Usage: npm run scan -- <apex-domain>");
    process.exit(1);
  }

  const domain = normalizeApexDomain(options.domain);
  const startedAt = new Date().toISOString();

  const report = {
    schemaVersion: 2,
    generatedAt: startedAt,
    target: domain,
    summary: {},
    findings: [],
    safeguards: {
      scanMode: options.active ? "passive-plus-active-basic" : "passive-first",
      notes: [
        "No brute-force subdomain enumeration is performed.",
        "HTTP collection is limited to the apex and common redirect target.",
        "DNS and WHOIS lookups use local system/network resolvers only.",
        "The scanner is intended for reconnaissance and posture review, not exploitation.",
        options.active ? "Active TCP probing was enabled for a curated port set on resolved IPs." : "No active TCP port probing was performed."
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
    website: {},
    infrastructure: {},
    delivery: {},
    email: {},
    services: {},
    graph: {},
    scoring: {},
    posture: {},
    discovery: {},
    exposures: {},
    ownership: {},
    relationships: {},
    ip: {},
    footprint: {
      ips: [],
      nameservers: [],
      mail: [],
      webStackHosts: [],
      relatedDomains: []
    },
    raw: {}
  };

  const [dnsInfo, whoisInfo, apexTlsInfo, httpInfo] = await Promise.all([
    collectDns(domain),
    collectWhois(domain),
    collectTls(domain),
    collectHttp(domain)
  ]);

  const tlsEntries = [{
    hostname: domain,
    cleaned: apexTlsInfo.cleaned,
    raw: apexTlsInfo.raw
  }];
  const effectiveHostname = extractHostname(httpInfo.cleaned.effectiveUrl);
  if (effectiveHostname && effectiveHostname !== domain) {
    const effectiveTlsInfo = await collectTls(effectiveHostname);
    tlsEntries.push({
      hostname: effectiveHostname,
      cleaned: effectiveTlsInfo.cleaned,
      raw: effectiveTlsInfo.raw
    });
  }
  const primaryTls = selectPrimaryTlsEntry(tlsEntries, effectiveHostname);

  report.dns = dnsInfo.cleaned;
  report.raw.dns = dnsInfo.raw;
  report.whois = whoisInfo.cleaned;
  report.raw.whois = whoisInfo.raw;
  report.tls = buildTlsView(primaryTls, tlsEntries);
  report.raw.tls = buildRawTlsView(primaryTls, tlsEntries);
  report.http = httpInfo.cleaned;
  report.raw.http = httpInfo.raw;
  report.ip = await collectIpIntelligence([...new Set([...(dnsInfo.cleaned.a ?? []), ...(dnsInfo.cleaned.aaaa ?? [])])]);

  report.footprint = buildFootprint(domain, report.tls, httpInfo.cleaned, whoisInfo.cleaned, dnsInfo.cleaned);
  report.services = await collectNetworkServices(report.footprint.ips, {
    active: options.active,
    hostHeader: effectiveHostname ?? domain
  });
  report.page = buildPageView(report);
  report.lists = buildListsView(report);
  report.webstack = buildWebstackView(report);
  report.javascript = buildJavaScriptView(report);
  report.hosting = buildHostingView(report);
  report.website = buildWebsiteView(report);
  report.infrastructure = buildInfrastructureView(report);
  report.delivery = buildDeliveryView(report);
  report.email = buildEmailView(report);
  report.posture = buildPostureView(report);
  report.discovery = buildDiscoveryView(report);
  report.exposures = buildExposureView(report);
  report.ownership = buildOwnershipView(report);
  report.relationships = buildRelationshipsView(report);
  report.graph = buildEvidenceGraph(report);
  report.findings = buildFindings(report);
  report.scoring = buildScorecard(report);
  report.summary = buildSummary(report);

  const outDir = path.resolve(process.cwd(), "reports");
  await mkdir(outDir, { recursive: true });
  const outFile = path.join(outDir, `${domain}.json`);
  await writeFile(outFile, JSON.stringify(report, null, 2));

  console.log(`Report written to ${outFile}`);
}

function parseArgs(argv) {
  const options = {
    domain: null,
    active: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg) {
      continue;
    }

    if (!arg.startsWith("--") && !options.domain) {
      options.domain = arg;
    } else if (arg === "--active") {
      options.active = true;
    }
  }

  return options;
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
        result.cleaned.txt.observations = analyzeTxtRecords(value);
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

  try {
    const mtaStsRows = await dns.resolveTxt(`_mta-sts.${domain}`);
    result.raw.MTA_STS = mtaStsRows;
    for (const row of mtaStsRows) {
      const joined = row.join("");
      if (joined.toLowerCase().startsWith("v=stsv1")) {
        result.cleaned.txt.mtaSts = joined;
      }
    }
  } catch (error) {
    result.raw.MTA_STS = { error: error.message };
  }

  try {
    const tlsRptRows = await dns.resolveTxt(`_smtp._tls.${domain}`);
    result.raw.TLS_RPT = tlsRptRows;
    for (const row of tlsRptRows) {
      const joined = row.join("");
      if (joined.toLowerCase().startsWith("v=tlsrptv1")) {
        result.cleaned.txt.tlsRpt = joined;
      }
    }
  } catch (error) {
    result.raw.TLS_RPT = { error: error.message };
  }

  try {
    const bimiRows = await dns.resolveTxt(`default._bimi.${domain}`);
    result.raw.BIMI = bimiRows;
    for (const row of bimiRows) {
      const joined = row.join("");
      if (joined.toLowerCase().startsWith("v=bimi1")) {
        result.cleaned.txt.bimi = joined;
      }
    }
  } catch (error) {
    result.raw.BIMI = { error: error.message };
  }

  result.cleaned.txt.spfAnalysis = analyzeSpf(result.cleaned.txt.spf ?? null);
  result.cleaned.txt.dmarcAnalysis = analyzeDmarc(result.cleaned.txt.dmarc ?? null);
  result.cleaned.txt.tlsRptAnalysis = analyzeTlsRpt(result.cleaned.txt.tlsRpt ?? null);
  result.cleaned.txt.bimiAnalysis = analyzeBimi(result.cleaned.txt.bimi ?? null);
  result.cleaned.txt.mtaStsAnalysis = analyzeMtaSts(result.cleaned.txt.mtaSts ?? null);
  result.cleaned.mxProviderInferences = inferMailProviders(result.cleaned.mx, result.cleaned.txt.spf ?? null);
  result.cleaned.mxProviderHints = inferenceLabels(result.cleaned.mxProviderInferences);
  result.cleaned.nsProviderInferences = inferDnsProviders(result.cleaned.ns);
  result.cleaned.nsProviderHints = inferenceLabels(result.cleaned.nsProviderInferences);
  result.cleaned.dkim = await collectCommonDkim(domain, result.raw, {
    mxProviders: result.cleaned.mxProviderHints,
    spf: result.cleaned.txt.spf ?? null
  });
  result.cleaned.dkim.providerInferences = inferDkimProviders(result.cleaned.dkim.discovered ?? [], result.cleaned.txt.spf ?? null);

  return result;
}

function analyzeTxtRecords(rows) {
  const records = (rows ?? []).map((row) => row.join("").trim()).filter(Boolean);
  const verificationRecords = [];
  const vendorHints = new Set();
  const grouped = new Map();
  let opaqueCount = 0;

  const knownVerificationPatterns = [
    ["Atlassian", /^atlassian-domain-verification=/i],
    ["Adobe", /^adobe-idp-site-verification=/i],
    ["Access", /^access-domain-verification=/i],
    ["Pardot", /^pardot\d+=/i],
    ["GlobalSign", /^_?globalsign-domain-verification=/i],
    ["Notion", /^notion-domain-verification=/i],
    ["Google Search Console", /^google-site-verification=/i],
    ["Google Workspace Recovery", /^google-gws-recovery-domain-verification=/i],
    ["PlayPlay", /^play-play-domain-verification-/i],
    ["Sitecore", /^sitecore-domain-verification=/i],
    ["TeamViewer", /^teamviewer-sso-verification=/i],
    ["OpenAI", /^openai-domain-verification=/i],
    ["Autodesk", /^autodesk-domain-verification=/i],
    ["DocuSign", /^docusign=/i],
    ["Microsoft", /^MS=ms\d+/i]
  ];

  for (const record of records) {
    if (/^v=spf1/i.test(record) || /^v=dmarc1/i.test(record)) {
      continue;
    }

    const matched = knownVerificationPatterns.find(([, pattern]) => pattern.test(record));
    if (matched) {
      const service = matched[0];
      const bucket = txtServiceBucket(service);
      verificationRecords.push({ service, bucket, record });
      vendorHints.add(service);
      const items = grouped.get(bucket) ?? [];
      items.push(service);
      grouped.set(bucket, items);
      continue;
    }

    if (/^[a-z0-9_.-]+=.+/i.test(record)) {
      verificationRecords.push({ service: "Unknown keyed TXT", record });
      continue;
    }

    opaqueCount += 1;
  }

  return {
    total: records.length,
    verificationRecords,
    vendorHints: [...vendorHints],
    buckets: [...grouped.entries()].map(([bucket, services]) => ({
      bucket,
      services: [...new Set(services)].sort()
    })),
    opaqueCount
  };
}

function txtServiceBucket(service) {
  const mapping = {
    "Google Search Console": "Identity & Verification",
    "Google Workspace Recovery": "Identity & Verification",
    "Atlassian": "Collaboration & SaaS",
    "Adobe": "Marketing & Experience",
    "Pardot": "Marketing & CRM",
    "Notion": "Collaboration & SaaS",
    "Sitecore": "Web & CMS",
    "PlayPlay": "Marketing & Experience",
    "TeamViewer": "Enterprise IT",
    "OpenAI": "AI & Automation",
    "Autodesk": "Enterprise IT",
    "Access": "Identity & Verification",
    "Microsoft": "Enterprise IT",
    "GlobalSign": "Trust & PKI",
    "DocuSign": "Trust & PKI"
  };

  return mapping[service] ?? "Other TXT Services";
}

async function collectCommonDkim(domain, rawDns, context = {}) {
  const selectorsToCheck = buildDkimSelectorCandidates(context);
  const selectors = [];

  for (const selector of selectorsToCheck) {
    const fqdn = `${selector}._domainkey.${domain}`;
    try {
      const rows = await dns.resolveTxt(fqdn);
      rawDns[`DKIM_${selector}`] = rows;
      const joined = rows.map((row) => row.join("")).join(" ");
      if (joined.toLowerCase().includes("v=dkim1")) {
        selectors.push({
          selector,
          record: joined
        });
      }
    } catch (error) {
      rawDns[`DKIM_${selector}`] = { error: error.message };
    }
  }

  return {
    checkedSelectors: selectorsToCheck,
    discovered: selectors
  };
}

function buildDkimSelectorCandidates(context) {
  const selectors = new Set(COMMON_DKIM_SELECTORS);
  const spf = (context.spf ?? "").toLowerCase();
  const mxProviders = new Set((context.mxProviders ?? []).map((item) => item.toLowerCase()));

  if (mxProviders.has("google workspace") || spf.includes("_spf.google.com")) {
    selectors.add("google");
  }
  if (mxProviders.has("microsoft 365") || spf.includes("spf.protection.outlook.com")) {
    selectors.add("selector1");
    selectors.add("selector2");
  }
  if (mxProviders.has("amazon ses") || spf.includes("amazonses.com")) {
    selectors.add("amazonses");
    selectors.add("selector1");
    selectors.add("selector2");
  }
  if (mxProviders.has("mailgun") || spf.includes("mailgun.org")) {
    selectors.add("mailgun");
    selectors.add("k1");
  }
  if (mxProviders.has("sendgrid") || spf.includes("sendgrid.net")) {
    selectors.add("sendgrid");
    selectors.add("s1");
    selectors.add("s2");
  }
  if (mxProviders.has("fastmail")) {
    selectors.add("fm1");
    selectors.add("fm2");
  }

  return [...selectors];
}

function analyzeSpf(record) {
  if (!record) {
    return {
      present: false,
      includeCount: 0,
      lookupCount: 0,
      allQualifier: null,
      flags: []
    };
  }

  const lower = record.toLowerCase();
  const includeCount = (lower.match(/\binclude:/g) ?? []).length;
  const redirectCount = (lower.match(/\bredirect=/g) ?? []).length;
  const lookupCount = [
    ...(lower.match(/\binclude:/g) ?? []),
    ...(lower.match(/\ba(?::|$)/g) ?? []),
    ...(lower.match(/\bmx(?::|$)/g) ?? []),
    ...(lower.match(/\bptr(?::|$)/g) ?? []),
    ...(lower.match(/\bexists:/g) ?? []),
    ...(lower.match(/\bredirect=/g) ?? [])
  ].length;

  const allMatch = lower.match(/([+\-~?])all\b/);
  const allQualifier = allMatch ? allMatch[1] : null;
  const flags = [];

  if (!allQualifier) {
    flags.push("missing-all");
  } else if (allQualifier === "+") {
    flags.push("allow-all");
  } else if (allQualifier === "?") {
    flags.push("neutral-all");
  } else if (allQualifier === "~") {
    flags.push("softfail");
  } else if (allQualifier === "-") {
    flags.push("hardfail");
  }

  if (lookupCount >= 10) {
    flags.push("lookup-limit-risk");
  } else if (lookupCount >= 7) {
    flags.push("lookup-pressure");
  }

  if (includeCount >= 5) {
    flags.push("many-includes");
  }
  if (redirectCount > 0) {
    flags.push("uses-redirect");
  }

  return {
    present: true,
    includeCount,
    lookupCount,
    allQualifier,
    flags
  };
}

function analyzeDmarc(record) {
  if (!record) {
    return {
      present: false,
      policy: null,
      subdomainPolicy: null,
      rua: [],
      ruf: [],
      flags: []
    };
  }

  const lower = record.toLowerCase();
  const policy = (lower.match(/\bp=([a-z]+)/) ?? [null, null])[1];
  const subdomainPolicy = (lower.match(/\bsp=([a-z]+)/) ?? [null, null])[1];
  const rua = extractTagValues(record, "rua");
  const ruf = extractTagValues(record, "ruf");
  const flags = [];

  if (policy === "none") {
    flags.push("monitoring-only");
  } else if (policy === "quarantine") {
    flags.push("partial-enforcement");
  } else if (policy === "reject") {
    flags.push("strong-enforcement");
  }
  if (!rua.length) {
    flags.push("missing-aggregate-reporting");
  }

  return {
    present: true,
    policy,
    subdomainPolicy,
    rua,
    ruf,
    flags
  };
}

function analyzeTlsRpt(record) {
  if (!record) {
    return { present: false, rua: [], flags: [] };
  }

  const rua = extractTagValues(record, "rua");
  return {
    present: true,
    rua,
    flags: rua.length ? ["reporting-enabled"] : ["missing-report-uri"]
  };
}

function analyzeBimi(record) {
  if (!record) {
    return { present: false, location: null, authority: null, flags: [] };
  }

  const location = (record.match(/\bl=([^;]+)/i) ?? [null, null])[1]?.trim() ?? null;
  const authority = (record.match(/\ba=([^;]+)/i) ?? [null, null])[1]?.trim() ?? null;
  const flags = [];
  if (!location) {
    flags.push("missing-logo-location");
  }
  if (!authority) {
    flags.push("missing-authority");
  }

  return {
    present: true,
    location,
    authority,
    flags
  };
}

function analyzeMtaSts(record) {
  if (!record) {
    return { present: false, mode: null, flags: [] };
  }

  const mode = (record.match(/\bmode=([^;]+)/i) ?? [null, null])[1]?.trim() ?? null;
  const flags = [];
  if (!mode) {
    flags.push("missing-mode");
  } else {
    flags.push(`mode-${mode}`);
  }

  return {
    present: true,
    mode,
    flags
  };
}

function extractTagValues(record, tag) {
  const match = record.match(new RegExp(`\\b${tag}=([^;]+)`, "i"));
  if (!match) {
    return [];
  }
  return match[1].split(",").map((item) => item.trim()).filter(Boolean);
}

function signal(source, value) {
  return {
    source,
    value: String(value ?? "").trim(),
    normalized: String(value ?? "").trim().toLowerCase()
  };
}

function nonEmptySignals(entries) {
  return (entries ?? []).filter((entry) => entry?.value);
}

function buildSignalsFromValues(source, values) {
  return nonEmptySignals((values ?? []).map((value) => signal(source, value)));
}

function buildSignalsFromObject(entries) {
  return nonEmptySignals((entries ?? []).map(([source, value]) => signal(source, value)));
}

function inferByRules(signals, rules, options = {}) {
  const matches = [];

  for (const rule of rules) {
    const evidenceItems = [];

    for (const matcher of (rule.matchers ?? [])) {
      const matchedSignal = signals.find((entry) => matcher.test(entry));
      if (!matchedSignal) {
        continue;
      }

      evidenceItems.push(evidence(
        matchedSignal.source,
        matcher.describe ? matcher.describe(matchedSignal) : `matched "${matchedSignal.value}"`
      ));
    }

    if (evidenceItems.length < (rule.minMatches ?? 1)) {
      continue;
    }

    matches.push(makeInference(
      rule.label,
      evidenceItems.length >= (rule.strongMatchThreshold ?? 2) ? (rule.confidenceStrong ?? rule.confidence ?? 0.9) : (rule.confidence ?? 0.75),
      evidenceItems
    ));
  }

  if (!matches.length && options.fallbackLabel) {
    return [makeInference(options.fallbackLabel, options.fallbackConfidence ?? 0.3, options.fallbackEvidence ?? [evidence("heuristic", "fallback inference")])];
  }

  return mergeInferences(matches);
}

function includesMatcher(pattern, options = {}) {
  const normalizedPattern = pattern.toLowerCase();
  return {
    test(entry) {
      if (options.source && entry.source !== options.source) {
        return false;
      }
      return entry.normalized.includes(normalizedPattern);
    },
    describe(entry) {
      return options.detail ?? `matched "${pattern}" in ${entry.source}`;
    }
  };
}

function suffixMatcher(suffix, options = {}) {
  const normalizedSuffix = suffix.toLowerCase();
  return {
    test(entry) {
      if (options.source && entry.source !== options.source) {
        return false;
      }
      return entry.normalized.endsWith(normalizedSuffix);
    },
    describe(entry) {
      return options.detail ?? `matched suffix "${suffix}" in ${entry.source}`;
    }
  };
}

function presentMatcher(source, options = {}) {
  return {
    test(entry) {
      return entry.source === source && Boolean(entry.value);
    },
    describe(entry) {
      return options.detail ?? `observed value "${entry.value}" in ${entry.source}`;
    }
  };
}

function extractSpfIncludeHosts(record) {
  if (!record) {
    return [];
  }

  return [...new Set(
    [...record.matchAll(/\binclude:([a-z0-9._-]+\.[a-z]{2,})/gi)]
      .map((match) => match[1].toLowerCase())
  )];
}

function extractMailtoDomains(record) {
  if (!record) {
    return [];
  }

  return [...new Set(
    [...record.matchAll(/mailto:[^@<\s]+@([a-z0-9._-]+\.[a-z]{2,})/gi)]
      .map((match) => match[1].toLowerCase())
  )];
}

function inferMailProviders(mxRows, spfRecord) {
  const signals = [
    ...buildSignalsFromValues("mx-host", (mxRows ?? []).map((row) => row.exchange)),
    ...buildSignalsFromValues("spf", extractSpfIncludeHosts(spfRecord))
  ];

  return inferByRules(signals, [
    { label: "Google Workspace", confidence: 0.75, confidenceStrong: 0.92, matchers: [suffixMatcher("google.com"), suffixMatcher("googlemail.com"), includesMatcher("_spf.google.com")] },
    { label: "Microsoft 365", confidence: 0.75, confidenceStrong: 0.92, matchers: [suffixMatcher("outlook.com"), suffixMatcher("protection.outlook.com"), includesMatcher("spf.protection.outlook.com")] },
    { label: "Proofpoint", confidence: 0.75, matchers: [includesMatcher("pphosted.com"), includesMatcher("proofpoint.com")] },
    { label: "Mimecast", confidence: 0.75, confidenceStrong: 0.9, matchers: [includesMatcher("mimecast"), includesMatcher("mimecast.com")] },
    { label: "Zoho Mail", confidence: 0.75, confidenceStrong: 0.9, matchers: [includesMatcher("zoho"), includesMatcher("zoho.com")] },
    { label: "Amazon SES", confidence: 0.75, confidenceStrong: 0.9, matchers: [includesMatcher("amazonses.com")] },
    { label: "Mailgun", confidence: 0.75, confidenceStrong: 0.9, matchers: [includesMatcher("mailgun.org")] },
    { label: "SendGrid", confidence: 0.75, confidenceStrong: 0.9, matchers: [includesMatcher("sendgrid.net"), includesMatcher("sendgrid")] },
    { label: "Barracuda", confidence: 0.75, confidenceStrong: 0.9, matchers: [includesMatcher("barracudanetworks"), includesMatcher("barracudanetworks.com")] },
    { label: "Cisco Secure Email", confidence: 0.75, confidenceStrong: 0.9, matchers: [includesMatcher("iphmx.com")] },
    { label: "Fastmail", confidence: 0.75, confidenceStrong: 0.9, matchers: [includesMatcher("messagingengine.com"), includesMatcher("spf.messagingengine.com")] },
    { label: "Proton Mail", confidence: 0.75, confidenceStrong: 0.9, matchers: [includesMatcher("protonmail"), includesMatcher("protonmail.ch"), includesMatcher("proton.me")] },
    { label: "Zendesk", confidence: 0.72, matchers: [includesMatcher("mail.zendesk.com")] },
    { label: "OnDMARC", confidence: 0.72, matchers: [includesMatcher("ondmarc.com")] }
  ]);
}

function inferDkimProviders(dkimEntries, spfRecord) {
  const signals = [
    ...buildSignalsFromValues("dkim", (dkimEntries ?? []).flatMap((entry) => [entry.selector, entry.record])),
    ...buildSignalsFromValues("spf", extractSpfIncludeHosts(spfRecord))
  ];

  return inferByRules(signals, [
    { label: "Google Workspace", confidence: 0.72, confidenceStrong: 0.9, matchers: [includesMatcher("google"), includesMatcher("_spf.google.com")] },
    { label: "Microsoft 365", confidence: 0.72, confidenceStrong: 0.9, matchers: [includesMatcher("onmicrosoft.com"), includesMatcher("spf.protection.outlook.com")] },
    { label: "Amazon SES", confidence: 0.72, confidenceStrong: 0.9, matchers: [includesMatcher("amazonses.com")] },
    { label: "SendGrid", confidence: 0.72, confidenceStrong: 0.9, matchers: [includesMatcher("sendgrid"), includesMatcher("sendgrid.net")] },
    { label: "Mailgun", confidence: 0.72, confidenceStrong: 0.9, matchers: [includesMatcher("mailgun.org")] },
    { label: "Mandrill", confidence: 0.72, matchers: [includesMatcher("mandrill")] }
  ]);
}

function inferDnsProviders(nsRows) {
  const signals = buildSignalsFromValues("nameserver", nsRows);
  return inferByRules(signals, [
    { label: "Amazon Route 53", confidence: 0.89, matchers: [includesMatcher("awsdns")] },
    { label: "Cloudflare DNS", confidence: 0.89, matchers: [includesMatcher("cloudflare")] },
    { label: "UltraDNS", confidence: 0.89, matchers: [includesMatcher("ultradns"), includesMatcher("udns")] },
    { label: "Akamai DNS", confidence: 0.84, matchers: [includesMatcher("akam")] },
    { label: "Azure DNS", confidence: 0.89, matchers: [includesMatcher("azure-dns")] },
    { label: "DNS Made Easy", confidence: 0.84, matchers: [includesMatcher("dnsmadeeasy")] },
    { label: "NS1", confidence: 0.84, matchers: [includesMatcher("nsone"), includesMatcher("nsone.net")] },
    { label: "Gandi DNS", confidence: 0.84, matchers: [includesMatcher("gandi")] },
    { label: "Google Cloud DNS", confidence: 0.84, matchers: [includesMatcher("googledomains.com")] }
  ]);
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

async function collectIpIntelligence(ips) {
  const uniqueIps = [...new Set(ips)].slice(0, MAX_IP_INTEL);
  if (!uniqueIps.length) {
    return {
      availability: {
        ipWhois: false
      },
      entries: []
    };
  }

  const entries = await Promise.all(uniqueIps.map(async (ip) => {
    const whoisInfo = await collectIpWhois(ip);
    let ptr = null;

    try {
      const ptrRecords = await dns.reverse(ip);
      ptr = ptrRecords[0] ?? null;
    } catch {
      ptr = null;
    }

    const providerInference = inferNetworkProvider(whoisInfo.cleaned, ptr);
    const roleInference = inferIpRole(whoisInfo.cleaned, ptr);

    return {
      ip,
      ptr,
      location: buildIpLocation(whoisInfo.cleaned),
      provider: providerInference?.label ?? null,
      providerInference,
      roleHint: roleInference?.label ?? null,
      roleInference,
      ...whoisInfo.cleaned
    };
  }));

  return {
    availability: {
      ipWhois: entries.some((entry) => !entry.error)
    },
    entries
  };
}

async function collectNetworkServices(ips, options = {}) {
  const targets = [...new Set((ips ?? []).filter(Boolean))].slice(0, MAX_IP_INTEL);
  if (!options.active) {
    return {
      active: false,
      portsChecked: ACTIVE_PORTS.map((entry) => entry.port),
      entries: [],
      summary: {
        hostsScanned: 0,
        totalOpen: 0
      }
    };
  }

  const entries = [];
  for (const ip of targets) {
    for (const portInfo of ACTIVE_PORTS) {
      entries.push(await probePort(ip, portInfo, options));
    }
  }

  const openEntries = entries.filter((entry) => entry.state === "open");
  return {
    active: true,
    portsChecked: ACTIVE_PORTS.map((entry) => entry.port),
    entries,
    summary: {
      hostsScanned: targets.length,
      totalOpen: openEntries.length,
      fingerprintedOpen: openEntries.filter((entry) => Boolean(entry.fingerprint)).length,
      families: summarizeServiceFamilies(openEntries)
    }
  };
}

async function probePort(ip, portInfo, options = {}) {
  if (["http", "http-alt", "elasticsearch"].includes(portInfo.service)) {
    return probeHttpService(ip, portInfo, { secure: false, hostHeader: options.hostHeader });
  }
  if (["https", "https-alt"].includes(portInfo.service)) {
    return probeHttpService(ip, portInfo, { secure: true, hostHeader: options.hostHeader });
  }
  if (["smtps", "imaps", "pop3s"].includes(portInfo.service)) {
    return probeTlsBannerService(ip, portInfo);
  }
  if (portInfo.service === "redis") {
    return probeRedisService(ip, portInfo);
  }
  if (portInfo.service === "postgres") {
    return probePostgresService(ip, portInfo);
  }
  return probeTcpService(ip, portInfo);
}

function probeTcpService(ip, portInfo) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    let banner = "";

    const finish = (state, extra = {}) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve({
        ip,
        port: portInfo.port,
        service: portInfo.service,
        family: portInfo.family,
        severity: portInfo.severity,
        state,
        banner: banner || null,
        fingerprint: state === "open" ? buildBannerFingerprint(portInfo, banner, extra.fingerprint) : null,
        ...extra
      });
    };

    socket.setTimeout(PORT_TIMEOUT_MS);

    socket.once("connect", () => {
      if (portInfo.service === "dns") {
        finish("open");
        return;
      }
      if (isBannerFriendlyPort(portInfo.port)) {
        setTimeout(() => finish("open"), 250);
      } else {
        finish("open");
      }
    });

    socket.on("data", (data) => {
      banner += data.toString("utf8");
      if (banner.length > 200) {
        banner = banner.slice(0, 200);
      }
      if (isBannerFriendlyPort(portInfo.port)) {
        finish("open");
      }
    });

    socket.once("timeout", () => finish("timeout"));
    socket.once("error", (error) => {
      if (error.code === "ECONNREFUSED") {
        finish("closed");
      } else {
        finish("error", { error: error.code || error.message });
      }
    });

    socket.connect(portInfo.port, ip);
  });
}

function probeHttpService(ip, portInfo, options = {}) {
  return new Promise((resolve) => {
    const transport = options.secure ? tls.connect({
      host: ip,
      port: portInfo.port,
      servername: options.hostHeader || ip,
      rejectUnauthorized: false,
      timeout: PORT_TIMEOUT_MS
    }) : net.connect({ host: ip, port: portInfo.port });

    let settled = false;
    let response = "";

    const finish = (state, extra = {}) => {
      if (settled) {
        return;
      }
      settled = true;
      transport.destroy();
      const fingerprint = state === "open"
        ? buildHttpFingerprint(portInfo, response, extra.tls)
        : null;
      resolve({
        ip,
        port: portInfo.port,
        service: portInfo.service,
        family: portInfo.family,
        severity: portInfo.severity,
        state,
        banner: extractHttpHeadline(response),
        fingerprint,
        ...extra
      });
    };

    transport.setTimeout(PORT_TIMEOUT_MS);

    transport.once("connect", () => {
      const hostHeader = options.hostHeader || ip;
      transport.write(`HEAD / HTTP/1.1\r\nHost: ${hostHeader}\r\nUser-Agent: scanner-mvp/0.1\r\nConnection: close\r\n\r\n`);
    });

    transport.on("data", (data) => {
      response += data.toString("utf8");
      if (response.length > 4096) {
        response = response.slice(0, 4096);
      }
      if (response.includes("\r\n\r\n")) {
        const tlsInfo = options.secure ? readTlsSocketInfo(transport) : null;
        finish("open", tlsInfo ? { tls: tlsInfo } : {});
      }
    });

    transport.once("timeout", () => finish("timeout"));
    transport.once("error", (error) => {
      if (error.code === "ECONNREFUSED") {
        finish("closed");
      } else {
        finish("error", { error: error.code || error.message });
      }
    });
    transport.once("end", () => {
      if (response) {
        const tlsInfo = options.secure ? readTlsSocketInfo(transport) : null;
        finish("open", tlsInfo ? { tls: tlsInfo } : {});
      }
    });
  });
}

function probeTlsBannerService(ip, portInfo) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: ip,
      port: portInfo.port,
      servername: undefined,
      rejectUnauthorized: false,
      timeout: PORT_TIMEOUT_MS
    });
    let settled = false;
    let banner = "";

    const finish = (state, extra = {}) => {
      if (settled) {
        return;
      }
      settled = true;
      const tlsInfo = readTlsSocketInfo(socket);
      socket.destroy();
      resolve({
        ip,
        port: portInfo.port,
        service: portInfo.service,
        family: portInfo.family,
        severity: portInfo.severity,
        state,
        banner: banner || null,
        fingerprint: state === "open" ? buildBannerFingerprint(portInfo, banner, tlsInfo ? { tls: tlsInfo } : null) : null,
        ...(tlsInfo ? { tls: tlsInfo } : {}),
        ...extra
      });
    };

    socket.once("secureConnect", () => {
      setTimeout(() => finish("open"), 250);
    });

    socket.on("data", (data) => {
      banner += data.toString("utf8");
      if (banner.length > 200) {
        banner = banner.slice(0, 200);
      }
      finish("open");
    });

    socket.once("timeout", () => finish("timeout"));
    socket.once("error", (error) => {
      if (error.code === "ECONNREFUSED") {
        finish("closed");
      } else {
        finish("error", { error: error.code || error.message });
      }
    });
  });
}

function probeRedisService(ip, portInfo) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: ip, port: portInfo.port });
    let settled = false;
    let banner = "";

    const finish = (state, extra = {}) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve({
        ip,
        port: portInfo.port,
        service: portInfo.service,
        family: portInfo.family,
        severity: portInfo.severity,
        state,
        banner: banner || null,
        fingerprint: state === "open" ? buildBannerFingerprint(portInfo, banner) : null,
        ...extra
      });
    };

    socket.setTimeout(PORT_TIMEOUT_MS);
    socket.once("connect", () => {
      socket.write("*1\r\n$4\r\nPING\r\n");
      setTimeout(() => finish("open"), 250);
    });
    socket.on("data", (data) => {
      banner += data.toString("utf8");
      if (banner.length > 200) {
        banner = banner.slice(0, 200);
      }
      finish("open");
    });
    socket.once("timeout", () => finish("timeout"));
    socket.once("error", (error) => {
      if (error.code === "ECONNREFUSED") {
        finish("closed");
      } else {
        finish("error", { error: error.code || error.message });
      }
    });
  });
}

function probePostgresService(ip, portInfo) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: ip, port: portInfo.port });
    let settled = false;
    let banner = "";

    const finish = (state, extra = {}) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve({
        ip,
        port: portInfo.port,
        service: portInfo.service,
        family: portInfo.family,
        severity: portInfo.severity,
        state,
        banner: banner || null,
        fingerprint: state === "open" ? buildBannerFingerprint(portInfo, banner, extra.fingerprint) : null,
        ...extra
      });
    };

    socket.setTimeout(PORT_TIMEOUT_MS);
    socket.once("connect", () => {
      const sslRequest = Buffer.alloc(8);
      sslRequest.writeUInt32BE(8, 0);
      sslRequest.writeUInt32BE(80877103, 4);
      socket.write(sslRequest);
      setTimeout(() => finish("open"), 250);
    });
    socket.on("data", (data) => {
      banner += data.toString("utf8");
      if (banner.length > 80) {
        banner = banner.slice(0, 80);
      }
      const firstByte = data[0];
      if (firstByte === 83 || firstByte === 78) {
        finish("open", {
          fingerprint: {
            protocol: "postgres",
            observation: firstByte === 83 ? "accepted SSLRequest" : "declined SSLRequest",
            product: "PostgreSQL-compatible service"
          }
        });
        return;
      }
      finish("open");
    });
    socket.once("timeout", () => finish("timeout"));
    socket.once("error", (error) => {
      if (error.code === "ECONNREFUSED") {
        finish("closed");
      } else {
        finish("error", { error: error.code || error.message });
      }
    });
  });
}

function summarizeServiceFamilies(entries) {
  const counts = new Map();
  for (const entry of entries ?? []) {
    const family = entry.family ?? "unknown";
    counts.set(family, (counts.get(family) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([family, count]) => `${family} (${count})`);
}

function buildBannerFingerprint(portInfo, banner, extra = null) {
  const cleaned = cleanProbeBanner(banner);
  const product = inferProductFromBanner(portInfo.service, cleaned);
  const fingerprint = {
    protocol: portInfo.service,
    family: portInfo.family,
    product,
    observation: cleaned || null
  };

  return {
    ...fingerprint,
    ...(extra ?? {})
  };
}

function buildHttpFingerprint(portInfo, responseText, tlsInfo = null) {
  const [statusLine, ...headerLines] = String(responseText).split(/\r?\n/);
  const headers = {};
  for (const line of headerLines) {
    if (!line || !line.includes(":")) {
      continue;
    }
    const index = line.indexOf(":");
    const key = line.slice(0, index).trim().toLowerCase();
    const value = line.slice(index + 1).trim();
    if (!headers[key]) {
      headers[key] = value;
    }
  }

  const statusMatch = statusLine.match(/HTTP\/\d+(?:\.\d+)?\s+(\d{3})/i);
  const serverHeader = headers.server ?? null;
  const product = inferHttpProduct(portInfo.service, serverHeader);
  return {
    protocol: portInfo.service,
    family: portInfo.family,
    statusCode: statusMatch ? Number(statusMatch[1]) : null,
    serverHeader,
    location: headers.location ?? null,
    product,
    observation: cleanProbeBanner(statusLine) || null,
    headers,
    ...(tlsInfo ? { tls: tlsInfo } : {})
  };
}

function readTlsSocketInfo(socket) {
  try {
    const peer = socket.getPeerCertificate?.(true);
    const peerSubject = peer?.subject?.CN ?? peer?.subjectaltname ?? null;
    const info = {
      alpn: socket.alpnProtocol || null,
      authorized: socket.authorized ?? false,
      authorizationError: socket.authorizationError ?? null,
      subjectCN: peer?.subject?.CN ?? null,
      issuerCN: peer?.issuer?.CN ?? null,
      validTo: peer?.valid_to ?? null,
      fingerprint256: peer?.fingerprint256 ?? null,
      peerSubject
    };
    const hasMeaningfulValue = Object.values(info).some((value) => value !== null && value !== false && value !== "");
    return hasMeaningfulValue ? info : null;
  } catch {
    return null;
  }
}

function extractHttpHeadline(responseText) {
  return cleanProbeBanner(String(responseText).split(/\r?\n/, 1)[0] ?? "");
}

function cleanProbeBanner(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim().slice(0, 160) || null;
}

function inferProductFromBanner(service, banner) {
  const text = String(banner ?? "").toLowerCase();
  if (!text) {
    return null;
  }
  if (service === "ssh" && text.includes("openssh")) {
    return "OpenSSH";
  }
  if (service === "ftp" && text.includes("ftp")) {
    return "FTP service";
  }
  if (["smtp", "smtps", "submission"].includes(service) && text.includes("smtp")) {
    return "SMTP service";
  }
  if (["imap", "imaps"].includes(service) && text.includes("imap")) {
    return "IMAP service";
  }
  if (["pop3", "pop3s"].includes(service) && text.includes("pop3")) {
    return "POP3 service";
  }
  if (service === "mysql" && /\d+\.\d+\.\d+/.test(text)) {
    return "MySQL-compatible service";
  }
  if (service === "redis" && text.includes("pong")) {
    return "Redis";
  }
  if (service === "telnet") {
    return "Telnet service";
  }
  return null;
}

function inferHttpProduct(service, serverHeader) {
  const header = String(serverHeader ?? "").toLowerCase();
  if (service === "elasticsearch") {
    return "Elasticsearch-compatible HTTP service";
  }
  if (!header) {
    return service.startsWith("https") ? "HTTPS service" : "HTTP service";
  }
  if (header.includes("cloudflare")) {
    return "Cloudflare edge";
  }
  if (header.includes("nginx")) {
    return "nginx";
  }
  if (header.includes("apache")) {
    return "Apache HTTP Server";
  }
  if (header.includes("iis")) {
    return "Microsoft IIS";
  }
  if (header.includes("envoy")) {
    return "Envoy";
  }
  return serverHeader;
}

function isBannerFriendlyPort(port) {
  return [21, 22, 23, 25, 110, 143, 3306, 465, 587, 993, 995].includes(port);
}

async function collectIpWhois(ip) {
  try {
    const { stdout } = await execFileAsync("whois", [ip], { timeout: REQUEST_TIMEOUT_MS });
    const text = stdout.trim();
    return {
      cleaned: parseIpWhois(text),
      raw: text
    };
  } catch (error) {
    return {
      cleaned: { error: error.message },
      raw: ""
    };
  }
}

function parseIpWhois(text) {
  const patterns = [
    ["asn", /(?:originas|origin|aut-num|originas0):\s*(AS?\d+)/im],
    ["asnName", /(?:org-name|as-name|aut-num|owner):\s*(.+)$/im],
    ["netName", /(?:netname|network name):\s*(.+)$/im],
    ["cidr", /(?:cidr|route6?|route):\s*(.+)$/im],
    ["country", /^country:\s*(.+)$/im],
    ["region", /^(?:stateprov|state|region):\s*(.+)$/im],
    ["city", /^city:\s*(.+)$/im],
    ["registry", /^(?:refer|source):\s*(.+)$/im],
    ["organization", /^(?:orgname|org-name|organization|owner):\s*(.+)$/im]
  ];

  const parsed = {};
  for (const [key, regex] of patterns) {
    const match = text.match(regex);
    if (match) {
      parsed[key] = match[1].trim();
    }
  }

  return parsed;
}

function buildIpLocation(parsed) {
  return {
    country: parsed.country ?? null,
    region: parsed.region ?? null,
    city: parsed.city ?? null,
    precision: parsed.city || parsed.region ? "whois-estimated" : parsed.country ? "country" : "unknown"
  };
}

function inferNetworkProvider(parsed, ptr) {
  const signals = buildSignalsFromObject([
    ["ip-organization", parsed.organization],
    ["ip-asn-name", parsed.asnName],
    ["ip-netname", parsed.netName],
    ["ptr", ptr]
  ]);

  const matches = inferByRules(signals, [
    { label: "Amazon Web Services", confidence: 0.78, confidenceStrong: 0.92, matchers: [includesMatcher("amazon"), includesMatcher("aws"), includesMatcher("compute.amazonaws.com"), includesMatcher("cloudfront")] },
    { label: "Microsoft Azure", confidence: 0.78, confidenceStrong: 0.92, matchers: [includesMatcher("microsoft"), includesMatcher("azure"), includesMatcher("cloudapp.azure.com")] },
    { label: "Google Cloud", confidence: 0.78, confidenceStrong: 0.92, matchers: [includesMatcher("google"), includesMatcher("gcp"), includesMatcher("googleusercontent.com"), includesMatcher("1e100.net")] },
    { label: "Cloudflare", confidence: 0.78, confidenceStrong: 0.92, matchers: [includesMatcher("cloudflare")] },
    { label: "Fastly", confidence: 0.78, confidenceStrong: 0.92, matchers: [includesMatcher("fastly")] },
    { label: "Akamai", confidence: 0.78, confidenceStrong: 0.92, matchers: [includesMatcher("akamai"), includesMatcher("akamaitechnologies")] },
    { label: "DigitalOcean", confidence: 0.78, matchers: [includesMatcher("digitalocean")] },
    { label: "OVHcloud", confidence: 0.78, matchers: [includesMatcher("ovh")] },
    { label: "Hetzner", confidence: 0.78, matchers: [includesMatcher("hetzner")] },
    { label: "Oracle Cloud", confidence: 0.78, matchers: [includesMatcher("oracle"), includesMatcher("oci")] },
    { label: "Linode", confidence: 0.78, matchers: [includesMatcher("linode"), includesMatcher("akamai connected cloud")] },
    { label: "Proofpoint", confidence: 0.76, matchers: [includesMatcher("pphosted"), includesMatcher("proofpoint")] },
    { label: "Mimecast", confidence: 0.76, matchers: [includesMatcher("mimecast")] }
  ]);
  if (matches.length) {
    return matches[0];
  }

  const fallback = parsed.organization ?? parsed.asnName ?? parsed.netName ?? null;
  if (!fallback) {
    return null;
  }

  return makeInference(fallback, 0.45, [evidence("ip-whois", "fallback to organization or ASN owner text")]);
}

function inferIpRole(parsed, ptr) {
  const signals = buildSignalsFromObject([
    ["ip-organization", parsed.organization],
    ["ip-asn-name", parsed.asnName],
    ["ip-netname", parsed.netName],
    ["ptr", ptr]
  ]);

  const matches = inferByRules(signals, [
    { label: "edge", confidence: 0.82, confidenceStrong: 0.9, matchers: [includesMatcher("cloudflare"), includesMatcher("fastly"), includesMatcher("akamai"), includesMatcher("cloudfront")] },
    { label: "mail", confidence: 0.82, confidenceStrong: 0.9, matchers: [includesMatcher("proofpoint"), includesMatcher("mimecast"), includesMatcher("pphosted"), includesMatcher("zendesk"), includesMatcher("outbound.protection.outlook.com")] },
    { label: "dns", confidence: 0.8, matchers: [includesMatcher("ultradns"), includesMatcher("googledomains"), includesMatcher("awsdns"), includesMatcher("azure-dns")] }
  ]);

  return matches[0] ?? null;
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
        const chain = buildCertificateChain(peer);
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
            subjectAltNames: parseSubjectAltNames(peer.subjectaltname),
            chain
          },
          raw: {
            chain
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
          subjectAltNames: [],
          chain: []
        },
        raw: {
          chain: []
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
          subjectAltNames: [],
          chain: []
        },
        raw: {
          chain: []
        }
      });
    });
  });
}

function extractHostname(url) {
  if (!url) {
    return null;
  }

  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function selectPrimaryTlsEntry(entries, effectiveHostname) {
  return entries.find((entry) => entry.hostname === effectiveHostname && !entry.cleaned?.error)
    ?? entries.find((entry) => !entry.cleaned?.error)
    ?? entries[0];
}

function buildTlsView(primaryEntry, entries) {
  const primary = primaryEntry?.cleaned ?? {};
  return {
    ...primary,
    hostname: primaryEntry?.hostname ?? null,
    entries: entries.map((entry) => ({
      hostname: entry.hostname,
      ...entry.cleaned
    }))
  };
}

function buildRawTlsView(primaryEntry, entries) {
  return {
    primaryHost: primaryEntry?.hostname ?? null,
    entries: entries.map((entry) => ({
      hostname: entry.hostname,
      ...(entry.raw ?? {})
    }))
  };
}

function buildCertificateChain(peer) {
  const chain = [];
  const seen = new Set();
  let current = peer;

  while (current && typeof current === "object" && Object.keys(current).length) {
    const fingerprint = current.fingerprint256 ?? `${current.subject?.CN ?? "unknown"}:${current.serialNumber ?? "n/a"}`;
    if (seen.has(fingerprint)) {
      break;
    }
    seen.add(fingerprint);

    chain.push({
      subjectCN: current.subject?.CN ?? null,
      issuerCN: current.issuer?.CN ?? null,
      serialNumber: current.serialNumber ?? null,
      fingerprint256: current.fingerprint256 ?? null,
      validFrom: current.valid_from ?? null,
      validTo: current.valid_to ?? null,
      selfSigned: current.subject?.CN && current.subject?.CN === current.issuer?.CN
    });

    if (!current.issuerCertificate || current.issuerCertificate === current) {
      break;
    }
    current = current.issuerCertificate;
  }

  return chain;
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
  const observedNavigation = selectObservedNavigation(results, preferred);
  const securityHeaders = preferred.headers ? summarizeSecurityHeaders(preferred.headers) : {};
  const extractedHosts = extractHostsFromBody(domain, preferred.body ?? "");
  const availability = {
    http: results.some((item) => item.finalUrl)
  };
  const technologySignals = extractClientHints(preferred.body ?? "", preferred.headers ?? {});
  const hosting = summarizeHosting(preferred.headers ?? {}, preferred.finalUrl ?? null);
  const cookiePosture = summarizeCookiePosture(preferred.cookies ?? []);
  const cors = summarizeCors(preferred.headers ?? {});
  const csp = analyzeCsp(preferred.headers?.["content-security-policy"] ?? null);
  const discovery = preferred.finalUrl ? await discoverWellKnown(preferred.finalUrl) : {};
  const assetFingerprint = await buildAssetFingerprint(preferred.body ?? "", preferred.finalUrl ?? null);
  const redirectHeaderDiffs = buildRedirectHeaderDiffs(observedNavigation.redirectChain ?? []);

  return {
    cleaned: {
      checks: results.map(({ body, ...rest }) => rest),
      status: preferred.status ?? null,
      ok: preferred.ok ?? false,
      redirected: observedNavigation.redirected,
      effectiveUrl: preferred.finalUrl ?? null,
      title: extractTitle(preferred.body ?? ""),
      headers: preferred.headers ?? {},
      securityHeaders,
      extractedHosts,
      scripts: extractScripts(preferred.body ?? ""),
      assetFingerprint,
      clientHints: technologySignals.hints,
      technologyInferences: technologySignals.inferences,
      cookies: preferred.cookies ?? [],
      cookiePosture,
      cors,
      csp,
      redirectChain: observedNavigation.redirectChain ?? [],
      redirectCount: observedNavigation.redirectCount,
      redirectHeaderDiffs,
      discovery,
      availability,
      hosting
    },
    raw: {
      checks: results.map(({ body, ...rest }) => rest),
      redirectChain: observedNavigation.redirectChain ?? [],
      redirectHeaderDiffs,
      assetFingerprint
    }
  };
}

function selectObservedNavigation(results, preferred) {
  const successful = (results ?? []).filter((item) => item?.finalUrl);
  if (!successful.length) {
    return {
      redirected: false,
      redirectCount: 0,
      redirectChain: preferred?.redirectChain ?? []
    };
  }

  const ranked = [...successful].sort((left, right) => {
    const leftCount = countRedirects(left.redirectChain ?? []);
    const rightCount = countRedirects(right.redirectChain ?? []);
    if (rightCount !== leftCount) {
      return rightCount - leftCount;
    }
    return (right.redirectChain?.length ?? 0) - (left.redirectChain?.length ?? 0);
  });
  const best = ranked[0];
  return {
    redirected: successful.some((item) => countRedirects(item.redirectChain ?? []) > 0),
    redirectCount: countRedirects(best.redirectChain ?? []),
    redirectChain: best.redirectChain ?? []
  };
}

function countRedirects(chain) {
  return (chain ?? []).filter((entry) => Boolean(entry.location)).length;
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
        location: location ?? null,
        headers
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

async function buildAssetFingerprint(html, effectiveUrl) {
  const favicon = extractFaviconPath(html);
  const iconLinks = [...html.matchAll(/<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']/gi)]
    .map((match) => match[1].trim())
    .slice(0, MAX_DISCOVERED_HOSTS);
  const staticHints = [...html.matchAll(/\b(?:\/_next\/|\/wp-content\/|\/assets\/|\/static\/|\/dist\/)[^"'\s<>)]+/gi)]
    .map((match) => match[0].trim())
    .slice(0, MAX_DISCOVERED_HOSTS);
  const hash = createHash("sha256").update(staticHints.join("|")).digest("hex").slice(0, 16);
  const faviconDetails = effectiveUrl
    ? await fetchFaviconFingerprint(effectiveUrl, favicon, iconLinks)
    : {
        faviconUrl: null,
        faviconHash: null,
        faviconStatus: null,
        faviconError: null
      };

  return {
    favicon,
    iconLinks: [...new Set(iconLinks)],
    staticHints: [...new Set(staticHints)],
    staticHash: staticHints.length ? hash : null,
    ...faviconDetails
  };
}

async function fetchFaviconFingerprint(effectiveUrl, favicon, iconLinks) {
  const base = new URL(effectiveUrl);
  const candidates = [
    favicon,
    ...(iconLinks ?? []),
    "/favicon.ico"
  ]
    .filter(Boolean)
    .map((item) => {
      try {
        return new URL(item, base).toString();
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  for (const candidate of [...new Set(candidates)]) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(candidate, {
        method: "GET",
        redirect: "follow",
        headers: { "user-agent": USER_AGENT },
        signal: controller.signal
      });

      if (!response.ok) {
        continue;
      }

      const buffer = Buffer.from(await response.arrayBuffer());
      return {
        faviconUrl: response.url,
        faviconHash: createHash("sha256").update(buffer).digest("hex").slice(0, 24),
        faviconStatus: response.status,
        faviconError: null
      };
    } catch (error) {
      return {
        faviconUrl: candidate,
        faviconHash: null,
        faviconStatus: null,
        faviconError: error.message
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  return {
    faviconUrl: null,
    faviconHash: null,
    faviconStatus: null,
    faviconError: null
  };
}

function buildRedirectHeaderDiffs(chain) {
  if (!chain?.length) {
    return [];
  }

  const diffs = [];
  for (let index = 0; index < chain.length; index += 1) {
    const current = chain[index];
    const previous = chain[index - 1];
    const diff = diffHeaders(previous?.headers ?? {}, current.headers ?? {});
    diffs.push({
      hop: index + 1,
      url: current.url,
      status: current.status,
      location: current.location ?? null,
      summary: summarizeHeaderDiff(diff),
      ...diff
    });
  }

  return diffs;
}

function diffHeaders(previousHeaders, currentHeaders) {
  const previousKeys = new Set(Object.keys(previousHeaders ?? {}));
  const currentKeys = new Set(Object.keys(currentHeaders ?? {}));
  const added = [];
  const removed = [];
  const changed = [];

  for (const key of currentKeys) {
    if (!previousKeys.has(key)) {
      added.push({ key, value: currentHeaders[key] });
    } else if (previousHeaders[key] !== currentHeaders[key]) {
      changed.push({ key, from: previousHeaders[key], to: currentHeaders[key] });
    }
  }

  for (const key of previousKeys) {
    if (!currentKeys.has(key)) {
      removed.push({ key, value: previousHeaders[key] });
    }
  }

  return { added, removed, changed };
}

function summarizeHeaderDiff(diff) {
  const parts = [];
  if (diff.added.length) {
    parts.push(`added ${diff.added.map((entry) => entry.key).join(", ")}`);
  }
  if (diff.changed.length) {
    parts.push(`changed ${diff.changed.map((entry) => entry.key).join(", ")}`);
  }
  if (diff.removed.length) {
    parts.push(`removed ${diff.removed.map((entry) => entry.key).join(", ")}`);
  }
  return parts.length ? parts.join(" | ") : "no header changes";
}

function extractFaviconPath(html) {
  const match = html.match(/<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']/i);
  return match ? match[1].trim() : null;
}

function extractClientHints(html, headers) {
  const hints = [];
  const inferences = [];
  const body = html.toLowerCase();

  const checks = [
    ["next.js", ["__next_data__", "/_next/"]],
    ["nuxt", ["__nuxt__", "/_nuxt/"]],
    ["gatsby", ["___gatsby"]],
    ["react", ["react", "reactdom"]],
    ["vue", ["vue.js", "vue.runtime"]],
    ["angular", ["ng-version", "angular"]],
    ["svelte", ["_app/immutable", "sveltekit"]],
    ["webpack", ["webpack"]],
    ["wordpress", ["/wp-content/", "/wp-includes/"]],
    ["drupal", ["drupal-settings-json", "/sites/default/files/"]],
    ["shopify", ["cdn.shopify.com", "shopify.theme"]],
    ["hubspot", ["js.hs-scripts.com"]],
    ["segment", ["segment.com", "analytics.js"]],
    ["google-tag-manager", ["googletagmanager"]],
    ["google-analytics", ["google-analytics", "gtag("]],
    ["adobe-launch", ["assets.adobedtm.com"]],
    ["cloudflare-turnstile", ["challenges.cloudflare.com"]],
    ["hotjar", ["hotjar"]],
    ["cookiebot", ["cookiebot"]],
    ["datadog-rum", ["datadoghq"]],
    ["sentry", ["sentry"]],
    ["stripe", ["js.stripe.com"]]
  ];

  for (const [label, patterns] of checks) {
    const matches = patterns.filter((pattern) => body.includes(pattern));
    if (matches.length) {
      hints.push(label);
      inferences.push(makeInference(
        label,
        matches.length >= 2 ? 0.9 : 0.72,
        matches.map((pattern) => evidence("html", `matched "${pattern}" in page content`))
      ));
    }
  }

  if (headers["x-powered-by"]) {
    hints.push(`banner:${headers["x-powered-by"]}`);
    inferences.push(makeInference(
      headers["x-powered-by"],
      0.8,
      [evidence("header:x-powered-by", `observed value "${headers["x-powered-by"]}"`)]
    ));
  }

  return {
    hints: [...new Set(hints)],
    inferences: mergeInferences(inferences)
  };
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
    provider: inferHostingProvider(headers)?.label ?? null,
    providerInference: inferHostingProvider(headers),
    deliveryNetwork: inferDeliveryNetwork(headers)?.label ?? null,
    deliveryInference: inferDeliveryNetwork(headers),
    stack: inferServerStack(headers).map((entry) => entry.label),
    stackInferences: inferServerStack(headers)
  };
}

function inferHostingProvider(headers) {
  const signals = buildSignalsFromObject([
    ["header:server", headers.server],
    ["header:x-vercel-id", headers["x-vercel-id"]],
    ["header:x-vercel-cache", headers["x-vercel-cache"]],
    ["header:x-sc-rewrite", headers["x-sc-rewrite"]],
    ["header:x-matched-path", headers["x-matched-path"]],
    ["header:cf-ray", headers["cf-ray"]],
    ["header:cf-cache-status", headers["cf-cache-status"]],
    ["header:x-served-by", headers["x-served-by"]],
    ["header:x-amz-cf-pop", headers["x-amz-cf-pop"]],
    ["header:x-amz-cf-id", headers["x-amz-cf-id"]],
    ["header-blob", JSON.stringify(headers)]
  ]);
  return inferByRules(signals, [
    { label: "Vercel", confidence: 0.74, confidenceStrong: 0.93, matchers: [includesMatcher("vercel"), presentMatcher("header:x-vercel-id"), presentMatcher("header:x-vercel-cache")] },
    { label: "Sitecore", confidence: 0.74, confidenceStrong: 0.93, matchers: [includesMatcher("sitecore"), presentMatcher("header:x-sc-rewrite"), presentMatcher("header:x-matched-path")] },
    { label: "Cloudflare", confidence: 0.74, confidenceStrong: 0.93, matchers: [includesMatcher("cloudflare"), presentMatcher("header:cf-ray"), presentMatcher("header:cf-cache-status")] },
    { label: "Fastly", confidence: 0.74, confidenceStrong: 0.93, matchers: [includesMatcher("fastly"), presentMatcher("header:x-served-by")] },
    { label: "Akamai", confidence: 0.74, matchers: [includesMatcher("akamai")] },
    { label: "Amazon CloudFront", confidence: 0.74, confidenceStrong: 0.93, matchers: [presentMatcher("header:x-amz-cf-pop"), presentMatcher("header:x-amz-cf-id"), includesMatcher("cloudfront")] }
  ])[0] ?? null;
}

function inferDeliveryNetwork(headers) {
  const signals = buildSignalsFromObject([
    ["header:cf-ray", headers["cf-ray"]],
    ["header:cf-cache-status", headers["cf-cache-status"]],
    ["header:x-served-by", headers["x-served-by"]],
    ["header:x-amz-cf-pop", headers["x-amz-cf-pop"]],
    ["header:x-amz-cf-id", headers["x-amz-cf-id"]],
    ["header-blob", JSON.stringify(headers)]
  ]);
  return inferByRules(signals, [
    { label: "Cloudflare", confidence: 0.78, confidenceStrong: 0.95, matchers: [includesMatcher("cloudflare"), presentMatcher("header:cf-ray"), presentMatcher("header:cf-cache-status")] },
    { label: "Fastly", confidence: 0.78, confidenceStrong: 0.95, matchers: [includesMatcher("fastly"), presentMatcher("header:x-served-by")] },
    { label: "Akamai", confidence: 0.78, matchers: [includesMatcher("akamai")] },
    { label: "Amazon CloudFront", confidence: 0.78, confidenceStrong: 0.95, matchers: [presentMatcher("header:x-amz-cf-pop"), presentMatcher("header:x-amz-cf-id"), includesMatcher("cloudfront")] }
  ])[0] ?? null;
}

function inferServerStack(headers) {
  const stack = [];
  if (headers.server) {
    stack.push(makeInference(headers.server, 0.88, [evidence("header:server", `observed value "${headers.server}"`)]));
  }
  if (headers["x-powered-by"]) {
    stack.push(makeInference(headers["x-powered-by"], 0.82, [evidence("header:x-powered-by", `observed value "${headers["x-powered-by"]}"`)]));
  }
  if (headers["x-aspnet-version"]) {
    stack.push(makeInference(`ASP.NET ${headers["x-aspnet-version"]}`, 0.84, [evidence("header:x-aspnet-version", `observed value "${headers["x-aspnet-version"]}"`)]));
  }
  return mergeInferences(stack);
}

function buildFootprint(domain, tlsInfo, httpInfo, whoisInfo, dnsInfo) {
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
    relatedDomains: deriveRelatedDomains(domain, {
      hosts: dedupedHosts,
      nameservers,
      mail,
      certificateNames: flattenTlsSubjectAltNames(tlsInfo)
    })
  };
}

function deriveRelatedDomains(targetDomain, inputs) {
  const targetRoot = registrableGuess(targetDomain) ?? targetDomain;
  const related = new Set();

  for (const host of [
    ...(inputs.hosts ?? []),
    ...(inputs.nameservers ?? []),
    ...(inputs.mail ?? []),
    ...(inputs.certificateNames ?? [])
  ]) {
    const root = registrableGuess(host);
    if (root && root !== targetRoot) {
      related.add(root);
    }
  }

  return [...related].slice(0, MAX_DISCOVERED_HOSTS);
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
  const spfAnalysis = report.dns.txt.spfAnalysis ?? {};
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

  const dmarcAnalysis = report.dns.txt.dmarcAnalysis ?? {};
  if (dmarcAnalysis.flags?.includes("monitoring-only")) {
    findings.push({
      severity: "medium",
      category: "email-security",
      title: "DMARC is monitoring-only",
      description: "The DMARC policy is set to p=none, so it reports but does not enforce against spoofing."
    });
  }
  if (dmarcAnalysis.present && dmarcAnalysis.flags?.includes("missing-aggregate-reporting")) {
    findings.push({
      severity: "low",
      category: "email-security",
      title: "DMARC aggregate reporting is not configured",
      description: "The DMARC record does not declare any rua destinations."
    });
  }

  const mtaStsAnalysis = report.dns.txt.mtaStsAnalysis ?? {};
  if (!mtaStsAnalysis.present && (report.dns.mx ?? []).length > 0) {
    findings.push({
      severity: "low",
      category: "email-security",
      title: "MTA-STS not detected",
      description: "Mail exchangers were observed, but no _mta-sts TXT policy was found."
    });
  }

  const tlsRptAnalysis = report.dns.txt.tlsRptAnalysis ?? {};
  if (!tlsRptAnalysis.present && (report.dns.mx ?? []).length > 0) {
    findings.push({
      severity: "low",
      category: "email-security",
      title: "SMTP TLS reporting not detected",
      description: "Mail exchangers were observed, but no _smtp._tls TLS-RPT record was found."
    });
  }

  if ((report.dns.dkim?.discovered ?? []).length === 0 && (report.dns.mx ?? []).length > 0) {
    findings.push({
      severity: "low",
      category: "email-security",
      title: "No common DKIM selectors detected",
      description: "The scanner checked common DKIM selectors but did not discover a DKIM1 record."
    });
  }

  if (spfAnalysis.flags?.includes("allow-all")) {
    findings.push({
      severity: "high",
      category: "email-security",
      title: "SPF allows all senders",
      description: "The SPF record contains +all, which effectively authorizes any sender."
    });
  } else if (spfAnalysis.flags?.includes("neutral-all")) {
    findings.push({
      severity: "medium",
      category: "email-security",
      title: "SPF uses neutral all",
      description: "The SPF record ends in ?all, which does not provide strong enforcement guidance."
    });
  } else if (spfAnalysis.flags?.includes("lookup-limit-risk")) {
    findings.push({
      severity: "medium",
      category: "email-security",
      title: "SPF may exceed DNS lookup guidance",
      description: `The SPF record appears to require about ${spfAnalysis.lookupCount} DNS-driven mechanisms, which risks evaluation failures.`
    });
  } else if (spfAnalysis.flags?.includes("lookup-pressure")) {
    findings.push({
      severity: "low",
      category: "email-security",
      title: "SPF is lookup-heavy",
      description: `The SPF record appears to require about ${spfAnalysis.lookupCount} DNS-driven mechanisms.`
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

  if (report.services?.active) {
    const openServices = (report.services.entries ?? []).filter((entry) => entry.state === "open");
    for (const service of openServices) {
      if (["telnet", "mysql", "postgres", "redis", "mongodb", "rdp", "elasticsearch"].includes(service.service)) {
        findings.push({
          severity: service.severity ?? "medium",
          category: "network-service",
          title: `${service.service.toUpperCase()} exposed`,
          description: `Active probing observed ${describeServiceObservation(service)}.`
        });
      }
    }
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

  const observedAsns = [...new Set((report.ip?.entries ?? []).map((entry) => entry.asn).filter(Boolean))];
  if (report.footprint.ips.length > 0 && !report.ip?.availability?.ipWhois) {
    findings.push({
      severity: "low",
      category: "observation-gap",
      title: "IP ownership enrichment unavailable",
      description: "The scanner resolved IPs but could not enrich them with PTR or IP WHOIS ownership details in the current environment."
    });
  } else if (observedAsns.length > 1) {
    findings.push({
      severity: "low",
      category: "infrastructure-spread",
      title: "IPs span multiple autonomous systems",
      description: `Resolved infrastructure maps to multiple ASNs: ${observedAsns.join(", ")}.`
    });
  }

  const deliveryProvider = report.delivery?.edgeProvider;
  const cloudProvider = report.infrastructure?.cloudProvider;
  if (deliveryProvider && cloudProvider && deliveryProvider !== cloudProvider) {
    findings.push({
      severity: "low",
      category: "delivery-topology",
      title: "Edge and cloud providers differ",
      description: `Traffic appears to be delivered by ${deliveryProvider} while infrastructure ownership points to ${cloudProvider}.`
    });
  }

  const certificateClusters = report.relationships?.certificateClusters ?? [];
  if (certificateClusters.length > 1) {
    findings.push({
      severity: "low",
      category: "shared-infrastructure",
      title: "Certificate spans multiple registrable domains",
      description: `Certificate SAN coverage crosses multiple registrable domains: ${certificateClusters.map((entry) => `${entry.domain} (${entry.count})`).join(", ")}.`
    });
  }

  const mailProviders = report.email?.providerInferences ?? [];
  if ((report.dns.mx ?? []).length > 0 && !mailProviders.length && !report.dns.txt?.spf) {
    findings.push({
      severity: "low",
      category: "email-security",
      title: "Mail stack attribution is limited",
      description: "MX records were observed, but there was not enough SPF or DKIM evidence to confidently attribute the mail platform."
    });
  }

  return findings;
}

function buildScorecard(report) {
  const buckets = new Map([
    ["web", { label: "Web Security", score: 100, positives: [], negatives: [] }],
    ["email", { label: "Email Security", score: 100, positives: [], negatives: [] }],
    ["infrastructure", { label: "Infrastructure", score: 100, positives: [], negatives: [] }],
    ["exposure", { label: "Exposure", score: 100, positives: [], negatives: [] }],
    ["services", { label: "Network Services", score: 100, positives: [], negatives: [] }]
  ]);

  const penalties = { high: 20, medium: 10, low: 4 };
  const categoryMap = {
    "security-header": "web",
    "transport-security": "web",
    "tls": "web",
    "cors": "web",
    "csp": "web",
    "cookie-posture": "web",
    "security-contact": "web",
    "email-security": "email",
    "certificate-governance": "infrastructure",
    "infrastructure-spread": "infrastructure",
    "delivery-topology": "infrastructure",
    "shared-infrastructure": "infrastructure",
    "network-service": "services",
    "technology-disclosure": "exposure",
    "banner-disclosure": "exposure"
  };

  for (const finding of report.findings) {
    const bucketKey = categoryMap[finding.category] ?? "infrastructure";
    const bucket = buckets.get(bucketKey);
    const deduction = penalties[finding.severity] ?? 0;
    bucket.score = Math.max(0, bucket.score - deduction);
    bucket.negatives.push(finding.title);
  }

  applyPositiveControl(buckets.get("web"), Boolean(report.http.effectiveUrl?.startsWith("https://")), "HTTPS observed", 8);
  applyPositiveControl(buckets.get("web"), report.http.securityHeaders?.["strict-transport-security"] === "present", "HSTS present", 4);
  applyPositiveControl(buckets.get("web"), report.http.csp?.grade === "strong", "Strong CSP present", 6);
  applyPositiveControl(buckets.get("email"), report.dns.txt?.spfAnalysis?.flags?.includes("hardfail"), "SPF hardfail policy", 8);
  applyPositiveControl(buckets.get("email"), report.dns.txt?.dmarcAnalysis?.flags?.includes("strong-enforcement"), "DMARC reject/quarantine posture", 10);
  applyPositiveControl(buckets.get("infrastructure"), (report.dns.caa ?? []).length > 0, "CAA present", 6);
  applyPositiveControl(buckets.get("services"), report.services?.active && (report.services.summary?.totalOpen ?? 0) === 0, "No probed ports open", 8);

  const bucketList = [...buckets.values()].map((bucket) => ({
    ...bucket,
    score: Math.min(100, bucket.score)
  }));
  const overall = Math.round(bucketList.reduce((total, bucket) => total + bucket.score, 0) / bucketList.length);

  return {
    buckets: bucketList,
    overall
  };
}

function applyPositiveControl(bucket, condition, label, points) {
  if (!condition) {
    return;
  }
  bucket.score = Math.min(100, bucket.score + points);
  bucket.positives.push(label);
}

function buildSummary(report) {
  const severityOrder = ["high", "medium", "low"];
  const counts = { high: 0, medium: 0, low: 0 };
  for (const finding of report.findings) {
    counts[finding.severity] += 1;
  }

  const score = report.scoring?.overall ?? Math.max(0, 100 - (counts.high * 20) - (counts.medium * 10) - (counts.low * 4));
  const rating = score >= 85 ? "good" : score >= 65 ? "watch" : "risk";
  const topSeverity = severityOrder.find((severity) => counts[severity] > 0) ?? "none";

  return {
    score,
    rating,
    topSeverity,
    status: topSeverity === "high" ? "red" : topSeverity === "medium" ? "amber" : "green",
    findingCount: report.findings.length,
    ips: report.footprint.ips.length,
    openServices: (report.services?.entries ?? []).filter((entry) => entry.state === "open").length,
    webStackHosts: report.footprint.webStackHosts.length,
    relatedDomains: report.footprint.relatedDomains.length,
    technologies: report.website?.technologies?.length ?? 0,
    countries: report.infrastructure?.countries?.length ?? 0
  };
}

function buildPageView(report) {
  return {
    apexDomain: report.target,
    effectiveUrl: report.http.effectiveUrl ?? null,
    httpStatus: report.http.status ?? null,
    title: report.http.title ?? null,
    redirected: report.http.redirected ?? false,
    redirectCount: report.http.redirectCount ?? 0,
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
      ...flattenTlsSubjectAltNames(report.tls).map(registrableGuess).filter(Boolean),
      ...(report.http.extractedHosts ?? []).map(registrableGuess).filter(Boolean)
    ])],
    hosts: report.footprint.webStackHosts,
    ips: report.footprint.ips,
    nameservers: report.footprint.nameservers,
    nameServerProviders: report.dns.nsProviderHints ?? [],
    mailServers: report.footprint.mail,
    mailProviders: report.dns.mxProviderHints ?? [],
    dkimSelectors: (report.dns.dkim?.discovered ?? []).map((entry) => entry.selector),
    certificateNames: flattenTlsSubjectAltNames(report.tls)
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
    observedHosts: report.footprint.webStackHosts,
    technologies: report.website?.technologies ?? []
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
    providerInference: report.http.hosting?.providerInference ?? null,
    deliveryHints: report.http.hosting?.indicators ?? [],
    effectiveHostname: report.http.hosting?.effectiveHostname ?? null,
    deliveryNetwork: report.http.hosting?.deliveryNetwork ?? null,
    deliveryInference: report.http.hosting?.deliveryInference ?? null,
    serverStack: report.http.hosting?.stack ?? [],
    serverStackInferences: report.http.hosting?.stackInferences ?? [],
    edgeHeaders: (report.http.hosting?.headerSignals ?? []).filter((entry) =>
      ["via", "x-cache", "x-served-by", "cf-cache-status", "cf-ray", "x-amz-cf-pop", "server"].includes(entry.key)
    )
  };
}

function buildWebsiteView(report) {
  const technologyInferences = mergeInferences([
    ...(report.http.technologyInferences ?? []),
    ...(report.http.hosting?.stackInferences ?? [])
  ]);

  return {
    url: report.http.effectiveUrl ?? null,
    title: report.http.title ?? null,
    status: report.http.status ?? null,
    technologies: inferenceLabels(technologyInferences),
    technologyInferences,
    thirdPartyHosts: report.javascript?.thirdPartyHosts ?? [],
    redirectChain: report.http.redirectChain ?? [],
    redirectHeaderDiffs: report.http.redirectHeaderDiffs ?? [],
    assetFingerprint: report.http.assetFingerprint ?? {}
  };
}

function buildInfrastructureView(report) {
  const entries = report.ip?.entries ?? [];
  const providerInferences = mergeInferences(entries.map((entry) => entry.providerInference).filter(Boolean));
  const providers = inferenceLabels(providerInferences);
  const countries = [...new Set(entries.map((entry) => entry.location?.country || entry.country).filter(Boolean))];
  const asns = [...new Set(entries.map((entry) => entry.asn).filter(Boolean))];
  const regions = [...new Set(entries.map((entry) => entry.location?.region).filter(Boolean))];
  const cities = [...new Set(entries.map((entry) => entry.location?.city).filter(Boolean))];
  const cloudProvider = providers.find((provider) =>
    ["Amazon Web Services", "Microsoft Azure", "Google Cloud", "DigitalOcean", "OVHcloud", "Hetzner", "Oracle Cloud", "Linode"].includes(provider)
  ) ?? providers[0] ?? null;
  const cloudProviderInference = providerInferences.find((entry) => entry.label === cloudProvider) ?? null;

  return {
    ips: entries.map((entry) => entry.ip),
    asns,
    providers,
    cloudProvider,
    providerInferences,
    cloudProviderInference,
    countries,
    regions,
    cities,
    entries
  };
}

function buildDeliveryView(report) {
  const edgeProvider = report.http.hosting?.deliveryNetwork
    ?? (report.infrastructure?.providers ?? []).find((provider) =>
      ["Cloudflare", "Fastly", "Akamai", "Amazon CloudFront"].includes(provider)
    )
    ?? null;
  const edgeProviderInference = report.http.hosting?.deliveryInference
    ?? (report.infrastructure?.providerInferences ?? []).find((entry) => entry.label === edgeProvider)
    ?? null;

  return {
    edgeProvider,
    edgeProviderInference,
    effectiveHostname: report.http.hosting?.effectiveHostname ?? null,
    cacheLayer: report.http.headers?.["x-cache"] ?? report.http.headers?.["cf-cache-status"] ?? null,
    reverseProxy: report.http.headers?.via ?? null,
    serverStack: report.http.hosting?.stack ?? [],
    indicators: report.http.hosting?.indicators ?? []
  };
}

function buildEmailView(report) {
  return {
    mx: report.dns.mx ?? [],
    mxProviders: report.dns.mxProviderHints ?? [],
    mxProviderInferences: report.dns.mxProviderInferences ?? [],
    spf: {
      record: report.dns.txt?.spf ?? null,
      analysis: report.dns.txt?.spfAnalysis ?? {}
    },
    dmarc: {
      record: report.dns.txt?.dmarc ?? null,
      analysis: report.dns.txt?.dmarcAnalysis ?? {}
    },
    dkim: report.dns.dkim ?? { checkedSelectors: [], discovered: [] },
    mtaSts: {
      record: report.dns.txt?.mtaSts ?? null,
      analysis: report.dns.txt?.mtaStsAnalysis ?? {}
    },
    tlsRpt: {
      record: report.dns.txt?.tlsRpt ?? null,
      analysis: report.dns.txt?.tlsRptAnalysis ?? {}
    },
    bimi: {
      record: report.dns.txt?.bimi ?? null,
      analysis: report.dns.txt?.bimiAnalysis ?? {}
    },
    dnsProviders: report.dns.nsProviderHints ?? [],
    dnsProviderInferences: report.dns.nsProviderInferences ?? [],
    providerInferences: mergeInferences([
      ...(report.dns.mxProviderInferences ?? []),
      ...(report.dns.dkim?.providerInferences ?? [])
    ])
  };
}

function evidence(source, detail) {
  return { source, detail };
}

function makeInference(label, confidence, evidenceItems) {
  return {
    label,
    confidence: Number(confidence.toFixed(2)),
    evidence: dedupeEvidence(evidenceItems ?? [])
  };
}

function mergeInferences(inferences) {
  const merged = new Map();

  for (const inference of inferences.filter(Boolean)) {
    const existing = merged.get(inference.label);
    if (!existing) {
      merged.set(inference.label, {
        label: inference.label,
        confidence: inference.confidence ?? 0,
        evidence: [...(inference.evidence ?? [])]
      });
      continue;
    }

    existing.confidence = Math.max(existing.confidence, inference.confidence ?? 0);
    existing.evidence = dedupeEvidence([...existing.evidence, ...(inference.evidence ?? [])]);
  }

  return [...merged.values()].sort((a, b) => b.confidence - a.confidence || a.label.localeCompare(b.label));
}

function dedupeEvidence(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = `${item.source}:${item.detail}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function inferenceLabels(inferences) {
  return (inferences ?? []).map((entry) => entry.label);
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
    sitemapXml: report.http.discovery?.["/sitemap.xml"] ?? null,
    securityTxtPreview: securityTxt?.preview ?? null,
    txtObservations: report.dns.txt?.observations ?? {
      total: 0,
      verificationRecords: [],
      vendorHints: [],
      buckets: [],
      opaqueCount: 0
    }
  };
}

function buildCertificateClusters(report) {
  const domains = flattenTlsSubjectAltNames(report.tls).map(registrableGuess).filter(Boolean);
  const grouped = new Map();
  for (const domain of domains) {
    grouped.set(domain, (grouped.get(domain) ?? 0) + 1);
  }
  return [...grouped.entries()].map(([domain, count]) => ({ domain, count }));
}

function flattenTlsSubjectAltNames(tlsView) {
  return [...new Set(
    (tlsView?.entries ?? [])
      .flatMap((entry) => entry.subjectAltNames ?? [])
      .concat(tlsView?.subjectAltNames ?? [])
  )];
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

function buildRelationshipsView(report) {
  const sharedClusters = buildObservedInfrastructureClusters(report);
  return {
    whoisLinkedDomains: {
      status: "coming-soon",
      rationale: "Reverse WHOIS expansion requires a comparison corpus or external index. The local scanner currently fingerprints ownership data only.",
      candidates: []
    },
    observedInfrastructure: {
      status: sharedClusters.length ? "observed" : "none",
      rationale: sharedClusters.length
        ? "Clusters are derived from certificate SANs, observed hosts, MX targets, and nameservers seen during passive collection."
        : "No cross-domain infrastructure clusters were derived from the passive evidence that was collected.",
      clusters: sharedClusters
    },
    certificateClusters: buildCertificateClusters(report)
  };
}

function buildEvidenceGraph(report) {
  const nodes = [];
  const edges = [];
  const seenNodes = new Set();
  const seenEdges = new Set();

  const addNode = (id, type, label) => {
    if (!id || seenNodes.has(id)) {
      return;
    }
    seenNodes.add(id);
    nodes.push({ id, type, label });
  };

  const addEdge = (from, to, label) => {
    if (!from || !to) {
      return;
    }
    const key = `${from}->${to}:${label}`;
    if (seenEdges.has(key)) {
      return;
    }
    seenEdges.add(key);
    edges.push({ from, to, label });
  };

  const targetId = `domain:${report.target}`;
  addNode(targetId, "domain", report.target);

  for (const ip of report.footprint?.ips ?? []) {
    const id = `ip:${ip}`;
    addNode(id, "ip", ip);
    addEdge(targetId, id, "resolves-to");
  }

  for (const service of (report.services?.entries ?? []).filter((entry) => entry.state === "open")) {
    const ipId = `ip:${service.ip}`;
    const serviceId = `open-service:${service.ip}:${service.port}`;
    const serviceLabel = `${service.service} ${service.port}`;
    addNode(serviceId, "open-service", serviceLabel);
    addEdge(ipId, serviceId, "exposes");
    if (service.fingerprint?.product) {
      const productId = `product:${service.fingerprint.product}`;
      addNode(productId, "service-product", service.fingerprint.product);
      addEdge(serviceId, productId, "fingerprinted-as");
    }
  }

  for (const host of report.footprint?.webStackHosts ?? []) {
    const id = `host:${host}`;
    addNode(id, "host", host);
    addEdge(targetId, id, "observed-host");
  }

  for (const service of report.javascript?.thirdPartyHosts ?? []) {
    const root = registrableGuess(service) ?? service;
    const id = `service:${root}`;
    addNode(id, "service", root);
    addEdge(targetId, id, "third-party");
  }

  for (const vendor of report.discovery?.txtObservations?.vendorHints ?? []) {
    const id = `vendor:${vendor}`;
    addNode(id, "vendor", vendor);
    addEdge(targetId, id, "txt-verification");
  }

  for (const provider of report.email?.providerInferences ?? []) {
    const id = `mail:${provider.label}`;
    addNode(id, "mail-provider", provider.label);
    addEdge(targetId, id, "mail-provider");
  }

  for (const cluster of report.relationships?.observedInfrastructure?.clusters ?? []) {
    const id = `related:${cluster.domain}`;
    addNode(id, "related-domain", cluster.domain);
    addEdge(targetId, id, "shared-infrastructure");
  }

  return {
    nodes,
    edges,
    summary: {
      nodeCount: nodes.length,
      edgeCount: edges.length,
      serviceCount: nodes.filter((node) => ["service", "vendor", "mail-provider", "open-service", "service-product"].includes(node.type)).length,
      relatedCount: nodes.filter((node) => node.type === "related-domain").length
    }
  };
}

function describeServiceObservation(service) {
  const parts = [`${service.service} on ${service.ip}:${service.port}`];
  if (service.fingerprint?.product) {
    parts.push(`fingerprinted as ${service.fingerprint.product}`);
  }
  if (service.fingerprint?.statusCode) {
    parts.push(`HTTP ${service.fingerprint.statusCode}`);
  }
  if (service.fingerprint?.observation) {
    parts.push(`observed "${service.fingerprint.observation}"`);
  }
  return parts.join(", ");
}

function buildObservedInfrastructureClusters(report) {
  const targetRoot = registrableGuess(report.target) ?? report.target;
  const grouped = new Map();
  const sources = [
    ["certificate-san", flattenTlsSubjectAltNames(report.tls)],
    ["observed-host", report.footprint.webStackHosts ?? []],
    ["mail-exchanger", report.footprint.mail ?? []],
    ["nameserver", report.footprint.nameservers ?? []]
  ];

  for (const [source, values] of sources) {
    for (const value of values) {
      const domain = registrableGuess(value);
      if (!domain || domain === targetRoot) {
        continue;
      }

      const existing = grouped.get(domain) ?? {
        domain,
        count: 0,
        sources: new Set(),
        samples: new Set()
      };
      existing.count += 1;
      existing.sources.add(source);
      existing.samples.add(value);
      grouped.set(domain, existing);
    }
  }

  return [...grouped.values()]
    .map((entry) => ({
      domain: entry.domain,
      count: entry.count,
      sources: [...entry.sources],
      samples: [...entry.samples].slice(0, 4)
    }))
    .sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain));
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
