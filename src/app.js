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
  text("#findingValue", `${report.summary.findingCount} findings / ${report.summary.score}`);
  text("#ipCountValue", String(report.summary?.ips ?? report.footprint?.ips?.length ?? 0));
  text("#hostCountValue", String(report.summary?.technologies ?? report.website?.technologies?.length ?? 0));
  text(
    "#relatedDomainValue",
    report.relationships?.whoisLinkedDomains?.status === "coming-soon"
      ? "Coming soon"
      : String(report.summary.relatedDomains)
  );

  renderList(
    "#findingsList",
    report.findings,
    (finding) => itemTemplate({
      title: `${finding.severity.toUpperCase()} · ${finding.category}`,
      body: `${finding.title} — ${finding.description}`,
      className: `severity-${finding.severity}`
    })
  );

  renderRows("#pageList", [
    row("Apex domain", report.page?.apexDomain),
    row("Effective URL", report.page?.effectiveUrl),
    row("HTTP status", report.page?.httpStatus),
    row("Redirected", yesNo(report.page?.redirected)),
    row("Page title", report.page?.title)
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
    row("Technologies", formatInferenceList(report.website?.technologyInferences)),
    row("Delivery hints", listOrFallback(report.webstack?.deliveryHints)),
    row("Observed hosts", listOrFallback(report.webstack?.observedHosts)),
    ...(report.webstack?.headerSignals ?? []).map((entry) => row(`Signal ${entry.key}`, entry.value))
  ]);

  renderRows("#hostingList", [
    row("Provider hint", formatInference(report.hosting?.providerInference)),
    row("Delivery network", formatInference(report.hosting?.deliveryInference)),
    row("Delivery hints", listOrFallback(report.hosting?.deliveryHints)),
    row("Effective host", report.hosting?.effectiveHostname),
    row("Server stack", formatInferenceList(report.hosting?.serverStackInferences)),
    row("Edge headers", formatHeaderSignals(report.hosting?.edgeHeaders))
  ]);

  renderRows("#javascriptList", [
    row("Client hints", listOrFallback(report.javascript?.clientHints)),
    row("Script sources", listOrFallback(report.javascript?.scriptSources)),
    row("Third-party hosts", listOrFallback(report.javascript?.thirdPartyHosts))
  ]);

  renderRows("#networkList", [
    row("IPv4", listOrFallback(report.dns.a)),
    row("IPv6", listOrFallback(report.dns.aaaa)),
    row("CNAME", listOrFallback(report.dns.cname)),
    row("Nameservers", listOrFallback(report.lists?.nameservers)),
    row("MX", listOrFallback(report.lists?.mailServers)),
    row("SPF", report.dns.txt?.spf),
    row("DMARC", report.dns.txt?.dmarc),
    row("CAA", formatCaa(report.dns.caa))
  ]);

  renderRows("#ipList", [
    row("Observed IPs", listOrFallback((report.ip?.entries ?? []).map((entry) => entry.ip))),
    row("PTR", listOrFallback(compactValues((report.ip?.entries ?? []).map((entry) => entry.ptr)))),
    row("ASN", listOrFallback(compactValues((report.ip?.entries ?? []).map((entry) => entry.asn)))),
    row("Provider", listOrFallback(compactValues((report.ip?.entries ?? []).map((entry) => entry.organization || entry.asnName || entry.netName)))),
    row("Normalized provider", formatInferenceList(report.infrastructure?.providerInferences)),
    row("Role hint", formatInferenceList(compactInferenceObjects((report.ip?.entries ?? []).map((entry) => entry.roleInference)))),
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
    row("Certificate SANs", listOrFallback(report.lists?.certificateNames))
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
    "#whoisLinkedList",
    [{
      title: "WHOIS-linked domains",
      body: report.relationships?.whoisLinkedDomains?.rationale ?? "Coming soon.",
      className: "severity-medium"
    }],
    renderEntry
  );
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

  element.innerHTML = filtered.map((entry) => rowTemplate(entry.label, stringify(entry.value))).join("");
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

function itemTemplate({ title, body, className = "" }) {
  return `<article class="item ${className}"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(stringify(body))}</span></article>`;
}

function row(label, value) {
  return { label, value };
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
