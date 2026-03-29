const reportFile = document.querySelector("#reportFile");
const loadSample = document.querySelector("#loadSample");

reportFile.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) {
    return;
  }

  const content = await file.text();
  renderReport(JSON.parse(content));
});

loadSample.addEventListener("click", async () => {
  const response = await fetch("./samples/example-report.json");
  const data = await response.json();
  renderReport(data);
});

function renderReport(report) {
  document.querySelector("#emptyState").classList.add("hidden");
  document.querySelector("#reportView").classList.remove("hidden");

  text("#targetValue", report.target);
  text("#targetMeta", buildTargetMeta(report));
  paintAssessment(report.summary);
  text("#findingValue", `${report.summary.findingCount} findings / score ${report.summary.score}`);
  text("#ipCountValue", String(report.summary?.ips ?? report.footprint?.ips?.length ?? 0));
  text("#hostCountValue", String(report.summary?.technologies ?? report.website?.technologies?.length ?? 0));
  text(
    "#relatedDomainValue",
    report.relationships?.whoisLinkedDomains?.status === "coming-soon"
      ? "Coming soon"
      : String(report.summary.relatedDomains)
  );

  renderFindingBuckets("#findingsList", report.findings);

  renderRows("#pageList", [
    row("Apex domain", report.page?.apexDomain),
    row("Effective URL", report.page?.effectiveUrl),
    row("HTTP status", report.page?.httpStatus),
    row("Redirected", yesNo(report.page?.redirected)),
    row("Redirect path", formatRedirectChain(report.page?.redirectChain)),
    row("Redirect header diffs", formatRedirectHeaderDiffs(report.website?.redirectHeaderDiffs)),
    row("Page title", report.page?.title),
    row("Redirect hops", report.page?.redirectChain?.length ?? 0),
    row("security.txt", formatDiscovery(report.discovery?.securityTxt)),
    row("security.txt preview", report.discovery?.securityTxtPreview),
    row("robots.txt", formatDiscovery(report.discovery?.robotsTxt)),
    row("sitemap.xml", formatDiscovery(report.discovery?.sitemapXml))
  ]);

  renderList(
    "#headerList",
    Object.entries(report.http.securityHeaders ?? {}).map(([key, value]) => ({
      title: key,
      body: value,
      className: `severity-${value === "present" ? "low" : "high"}`
    })),
    renderEntry
  );

  renderRows("#webStackList", [
    row("Server header", report.webstack?.serverHeader),
    row("X-Powered-By", report.webstack?.poweredBy),
    row("Reverse proxy", report.webstack?.reverseProxy),
    row("Cache layer", report.webstack?.cacheLayer),
    htmlRow("Technologies", formatInferenceListHtml(report.website?.technologyInferences)),
    row("Delivery hints", listOrFallback(report.webstack?.deliveryHints)),
    row("Observed hosts", listOrFallback(report.webstack?.observedHosts)),
    ...(report.webstack?.headerSignals ?? []).map((entry) => row(`Signal ${entry.key}`, entry.value))
  ]);

  renderRows("#hostingList", [
    htmlRow("Provider hint", formatInferenceHtml(report.hosting?.providerInference)),
    htmlRow("Delivery network", formatInferenceHtml(report.hosting?.deliveryInference)),
    row("Delivery hints", listOrFallback(report.hosting?.deliveryHints)),
    row("Effective host", report.hosting?.effectiveHostname),
    htmlRow("Server stack", formatInferenceListHtml(report.hosting?.serverStackInferences)),
    row("Edge headers", formatHeaderSignals(report.hosting?.edgeHeaders))
  ]);

  renderRows("#javascriptList", [
    row("Client hints", listOrFallback(report.javascript?.clientHints)),
    row("Script sources", listOrFallback(report.javascript?.scriptSources)),
    row("Third-party hosts", listOrFallback(report.javascript?.thirdPartyHosts))
  ]);

  renderRows("#assetList", [
    row("Favicon", report.website?.assetFingerprint?.favicon),
    row("Favicon URL", report.website?.assetFingerprint?.faviconUrl),
    row("Favicon SHA-256", report.website?.assetFingerprint?.faviconHash),
    row("Favicon fetch", report.website?.assetFingerprint?.faviconError ?? report.website?.assetFingerprint?.faviconStatus),
    row("Icon links", listOrFallback(report.website?.assetFingerprint?.iconLinks)),
    row("Static asset hints", listOrFallback(report.website?.assetFingerprint?.staticHints)),
    row("Static fingerprint", report.website?.assetFingerprint?.staticHash)
  ]);

  renderRows("#emailList", [
    row("MX records", formatMx(report.email?.mx)),
    htmlRow("Mail platform", formatInferenceListHtml(report.email?.providerInferences)),
    htmlRow("MX providers", formatInferenceListHtml(report.email?.mxProviderInferences)),
    htmlRow("DNS providers", formatInferenceListHtml(report.email?.dnsProviderInferences)),
    row("SPF record", report.email?.spf?.record),
    row("SPF posture", formatSpfAnalysis(report.email?.spf?.analysis)),
    row("DMARC record", report.email?.dmarc?.record),
    row("DMARC posture", formatDmarcAnalysis(report.email?.dmarc?.analysis)),
    row("DKIM selectors checked", listOrFallback(report.email?.dkim?.checkedSelectors)),
    row("DKIM selectors found", formatDkimSelectors(report.email?.dkim?.discovered)),
    row("MTA-STS", formatPolicyRecord(report.email?.mtaSts?.record, report.email?.mtaSts?.analysis?.flags)),
    row("TLS-RPT", formatPolicyRecord(report.email?.tlsRpt?.record, report.email?.tlsRpt?.analysis?.flags)),
    row("BIMI", formatPolicyRecord(report.email?.bimi?.record, report.email?.bimi?.analysis?.flags))
  ]);

  renderRows("#networkList", [
    row("IPv4", listOrFallback(report.dns.a)),
    row("IPv6", listOrFallback(report.dns.aaaa)),
    row("CNAME", listOrFallback(report.dns.cname)),
    row("Nameservers", listOrFallback(report.lists?.nameservers)),
    row("Name server providers", listOrFallback(report.dns.nsProviderHints)),
    row("MX", listOrFallback(report.lists?.mailServers)),
    row("CAA", formatCaa(report.dns.caa)),
    row("TXT verifications", listOrFallback(report.dns.txt?.verifications))
  ]);

  renderRows("#ipList", [
    row("Observed IPs", listOrFallback((report.ip?.entries ?? []).map((entry) => entry.ip))),
    row("PTR", listOrFallback(compactValues((report.ip?.entries ?? []).map((entry) => entry.ptr)))),
    row("ASN", listOrFallback(compactValues((report.ip?.entries ?? []).map((entry) => entry.asn)))),
    row("Provider", listOrFallback(compactValues((report.ip?.entries ?? []).map((entry) => entry.organization || entry.asnName || entry.netName)))),
    htmlRow("Normalized provider", formatInferenceListHtml(report.infrastructure?.providerInferences)),
    htmlRow("Role hint", formatInferenceListHtml(compactInferenceObjects((report.ip?.entries ?? []).map((entry) => entry.roleInference)))),
    row("CIDR / Route", listOrFallback(compactValues((report.ip?.entries ?? []).map((entry) => entry.cidr)))),
    row("Country", listOrFallback(compactValues((report.ip?.entries ?? []).map((entry) => entry.location?.country || entry.country)))),
    row("Region", listOrFallback(compactValues((report.ip?.entries ?? []).map((entry) => entry.location?.region)))),
    row("City", listOrFallback(compactValues((report.ip?.entries ?? []).map((entry) => entry.location?.city))))
  ]);

  renderRows("#tlsList", [
    row("Protocol", report.tls.protocol),
    row("Cipher", report.tls.cipher?.name),
    row("Subject CN", report.tls.subject?.CN),
    row("Issuer CN", report.tls.issuer?.CN),
    row("Valid from", report.tls.validFrom),
    row("Valid to", report.tls.validTo),
    row("Serial", report.tls.serialNumber),
    row("SHA-256 fingerprint", report.tls.fingerprint256),
    row("Certificate SANs", listOrFallback(report.lists?.certificateNames)),
    row("Certificate clusters", formatCertificateClusters(report)),
    row("Certificate chain", formatCertificateChain(report.tls?.chain))
  ]);

  renderRows("#ownershipList", [
    row("Registrar", report.ownership?.registrar),
    row("Registrant org", report.ownership?.registrantOrganization),
    row("Registrant email", report.ownership?.registrantEmail),
    row("Registrant country", report.ownership?.registrantCountry),
    row("Abuse email", report.ownership?.abuseEmail),
    row("WHOIS fingerprint", listOrFallback(report.ownership?.fingerprint))
  ]);

  renderRows("#exposureList", [
    row("Banner disclosures", formatBannerDisclosures(report.exposures?.bannerDisclosures)),
    row("CVE correlation", report.exposures?.cveCorrelation?.status),
    row("CVE note", report.exposures?.cveCorrelation?.rationale)
  ]);

  renderList(
    "#relationshipList",
    (report.relationships?.observedInfrastructure?.clusters ?? []).map((cluster) => ({
      title: `${cluster.domain} (${cluster.count})`,
      body: `${cluster.sources.join(", ")} | ${cluster.samples.join(", ")}`,
      className: "severity-low"
    })),
    renderEntry
  );

  renderList(
    "#whoisLinkedList",
    [{
      title: "WHOIS-linked domains",
      body: report.relationships?.whoisLinkedDomains?.rationale ?? "Coming soon.",
      className: "severity-medium"
    }],
    renderEntry
  );

  renderRawEvidence(report);
}

function paintAssessment(summary) {
  const element = document.querySelector("#scoreValue");
  element.textContent = `${summary.status.toUpperCase()} / ${summary.score}`;
  element.className = `score-value metric-status status-${summary.status}`;
}

function renderRows(selector, rows) {
  const element = document.querySelector(selector);
  const filtered = rows.filter((entry) => entry.value !== null && entry.value !== undefined);
  if (!filtered.length) {
    element.innerHTML = rowTemplate("No data", "No data available.");
    return;
  }

  element.innerHTML = filtered.map((entry) => entry.html ? rowTemplateHtml(entry.label, entry.value) : rowTemplate(entry.label, stringify(entry.value))).join("");
}

function renderList(selector, items, renderer) {
  const element = document.querySelector(selector);
  if (!items.length) {
    element.innerHTML = renderEntry({ title: "No data", body: "No data available." });
    return;
  }

  element.innerHTML = items.map(renderer).join("");
}

function renderEntry(entry) {
  return itemTemplate(entry);
}

function renderFindingBuckets(selector, findings) {
  const element = document.querySelector(selector);
  if (!findings.length) {
    element.innerHTML = renderEntry({ title: "No findings", body: "No findings were generated for this report." });
    return;
  }

  const buckets = new Map();
  for (const finding of findings) {
    const bucket = findingBucket(finding);
    const items = buckets.get(bucket) ?? [];
    items.push(finding);
    buckets.set(bucket, items);
  }

  element.innerHTML = [...buckets.entries()].map(([bucket, items]) => `
    <section class="finding-group">
      <div class="finding-group-head">${escapeHtml(bucket)}</div>
      <div class="finding-group-items">
        ${items.map((finding) => itemTemplate({
          title: `${finding.severity.toUpperCase()} · ${finding.category}`,
          body: `${finding.title} — ${finding.description}`,
          className: `severity-${finding.severity}`
        })).join("")}
      </div>
    </section>
  `).join("");
}

function renderRawEvidence(report) {
  text("#rawWhois", report.raw?.whois || "No WHOIS record captured.");
  text("#rawDns", prettyJson(report.raw?.dns));
  text("#rawIp", prettyJson(report.ip?.entries ?? []));
  text("#rawHttp", prettyJson(report.raw?.http));
  text("#rawTls", prettyJson(report.raw?.tls));
}

function buildTargetMeta(report) {
  const status = report.page?.httpStatus ? `HTTP ${report.page.httpStatus}` : "HTTP unavailable";
  const delivery = report.delivery?.edgeProviderInference?.label ?? report.delivery?.edgeProvider ?? report.hosting?.providerHint ?? "Provider unknown";
  const cloud = report.infrastructure?.cloudProviderInference?.label ?? report.infrastructure?.cloudProvider ?? "Cloud unknown";
  const geo = listOrFallback(report.infrastructure?.countries ?? []);
  return `${status} | edge ${delivery} | cloud ${cloud} | geo ${geo}`;
}

function rowTemplate(label, value) {
  return `<div class="row"><div class="row-label">${escapeHtml(label)}</div><div class="row-value">${escapeHtml(value)}</div></div>`;
}

function rowTemplateHtml(label, value) {
  return `<div class="row"><div class="row-label">${escapeHtml(label)}</div><div class="row-value">${value}</div></div>`;
}

function itemTemplate({ title, body, className = "" }) {
  return `<article class="item ${className}"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(stringify(body))}</span></article>`;
}

function row(label, value) {
  return { label, value };
}

function htmlRow(label, value) {
  return { label, value, html: true };
}

function stringify(value) {
  if (value === null || value === undefined || value === "") {
    return "Unavailable";
  }
  return String(value);
}

function listOrFallback(values) {
  return values?.length ? values.join(", ") : "None detected";
}

function compactValues(values) {
  return [...new Set((values ?? []).filter(Boolean))];
}

function compactInferenceObjects(entries) {
  const byLabel = new Map();
  for (const entry of (entries ?? []).filter(Boolean)) {
    const existing = byLabel.get(entry.label);
    if (!existing || (entry.confidence ?? 0) > (existing.confidence ?? 0)) {
      byLabel.set(entry.label, entry);
    }
  }
  return [...byLabel.values()].sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0));
}

function formatInference(entry) {
  if (!entry?.label) {
    return "Unavailable";
  }

  const confidence = entry.confidence !== undefined ? `${Math.round(entry.confidence * 100)}%` : "n/a";
  const evidenceSummary = (entry.evidence ?? []).slice(0, 2).map((item) => `${item.source}: ${item.detail}`).join(" | ");
  return evidenceSummary ? `${entry.label} (${confidence}) | ${evidenceSummary}` : `${entry.label} (${confidence})`;
}

function formatInferenceList(entries) {
  if (!entries?.length) {
    return "None detected";
  }

  return entries.map(formatInference).join(" ; ");
}

function formatInferenceHtml(entry) {
  if (!entry?.label) {
    return "Unavailable";
  }

  return `
    <div class="inference-block">
      <div class="inference-head">
        <span class="inference-label">${escapeHtml(entry.label)}</span>
        <span class="inference-confidence">${Math.round((entry.confidence ?? 0) * 100)}%</span>
      </div>
      ${(entry.evidence ?? []).slice(0, 3).map((item) => `
        <div class="inference-evidence">
          <span class="inference-source">${escapeHtml(item.source)}</span>
          <span class="inference-detail">${escapeHtml(item.detail)}</span>
        </div>
      `).join("")}
    </div>
  `;
}

function formatInferenceListHtml(entries) {
  if (!entries?.length) {
    return "None detected";
  }

  return `<div class="inference-list">${entries.map(formatInferenceHtml).join("")}</div>`;
}

function formatDiscovery(entry) {
  if (!entry) {
    return "Unavailable";
  }
  if (entry.ok) {
    return `present (${entry.status})`;
  }
  return entry.error ? `error: ${entry.error}` : `missing (${entry.status ?? "n/a"})`;
}

function formatRedirectChain(chain) {
  if (!chain?.length) {
    return "No redirect chain captured";
  }

  return chain.map((hop) => {
    const destination = hop.location ? ` -> ${hop.location}` : "";
    return `${hop.status} ${hop.url}${destination}`;
  }).join(" | ");
}

function formatSpfAnalysis(analysis) {
  if (!analysis?.present) {
    return "No SPF record detected";
  }

  const qualifierMap = {
    "-": "hardfail",
    "~": "softfail",
    "?": "neutral",
    "+": "allow-all"
  };
  const disposition = qualifierMap[analysis.allQualifier] ?? "unspecified";
  const flags = analysis.flags?.length ? analysis.flags.join(", ") : "no notable flags";
  return `${disposition} | includes ${analysis.includeCount} | lookup est ${analysis.lookupCount} | ${flags}`;
}

function formatDmarcAnalysis(analysis) {
  if (!analysis?.present) {
    return "No DMARC record detected";
  }

  const policy = analysis.policy ?? "unknown";
  const subdomain = analysis.subdomainPolicy ? ` | sp=${analysis.subdomainPolicy}` : "";
  const rua = analysis.rua?.length ? ` | rua ${analysis.rua.join(", ")}` : " | no rua";
  const flags = analysis.flags?.length ? ` | ${analysis.flags.join(", ")}` : "";
  return `p=${policy}${subdomain}${rua}${flags}`;
}

function formatPolicyRecord(record, flags) {
  if (!record) {
    return "Not detected";
  }
  const suffix = flags?.length ? ` | ${flags.join(", ")}` : "";
  return `${record}${suffix}`;
}

function formatMx(entries) {
  if (!entries?.length) {
    return "None detected";
  }
  return entries.map((entry) => `${entry.priority} ${entry.exchange}`).join(", ");
}

function formatDkimSelectors(entries) {
  if (!entries?.length) {
    return "None detected";
  }
  return entries.map((entry) => entry.selector).join(", ");
}

function formatRedirectHeaderDiffs(entries) {
  if (!entries?.length) {
    return "No header diffs captured";
  }

  return entries.map((entry) => `hop ${entry.hop}: ${entry.summary}`).join(" | ");
}

function formatCertificateClusters(report) {
  const clusters = report.relationships?.certificateClusters ?? [];
  if (!clusters.length) {
    return "None detected";
  }

  return clusters.map((entry) => `${entry.domain} (${entry.count})`).join(", ");
}

function formatCertificateChain(entries) {
  if (!entries?.length) {
    return "No certificate chain captured";
  }

  return entries.map((entry, index) =>
    `${index + 1}. ${entry.subjectCN || "Unknown subject"} -> ${entry.issuerCN || "Unknown issuer"} (${entry.validTo || "n/a"})`
  ).join(" | ");
}

function findingBucket(finding) {
  const category = finding.category ?? "";
  if (["email-security"].includes(category)) {
    return "Email";
  }
  if (["transport-security", "tls", "csp", "security-header", "cors", "cookie-posture", "security-contact"].includes(category)) {
    return "Web Security";
  }
  if (["certificate-governance", "infrastructure-spread", "delivery-topology", "shared-infrastructure"].includes(category)) {
    return "Infrastructure";
  }
  if (["technology-disclosure", "banner-disclosure"].includes(category)) {
    return "Exposure";
  }
  if (["observation-gap"].includes(category)) {
    return "Coverage Gaps";
  }
  return "General";
}

function prettyJson(value) {
  if (!value || (typeof value === "object" && Object.keys(value).length === 0)) {
    return "No data captured.";
  }
  return JSON.stringify(value, null, 2);
}

function yesNo(value) {
  return value ? "Yes" : "No";
}

function formatCaa(records) {
  if (!records?.length) {
    return "None detected";
  }

  return records.map((record) => record.issue || record.issuewild || record.iodef || "present").join(", ");
}

function formatHeaderSignals(entries) {
  if (!entries?.length) {
    return "None detected";
  }

  return entries.map((entry) => `${entry.key}=${entry.value}`).join("; ");
}

function formatBannerDisclosures(entries) {
  if (!entries?.length) {
    return "None detected";
  }

  return entries.map((entry) => `${entry.source}=${entry.value}`).join("; ");
}

function text(selector, value) {
  document.querySelector(selector).textContent = value;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
