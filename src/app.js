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
  paintAssessment(report.summary);
  text("#findingValue", `${report.summary.findingCount} findings`);
  text("#relatedDomainValue", report.relationships?.whoisLinkedDomains?.status === "coming-soon" ? "Coming soon" : String(report.summary.relatedDomains));

  renderList(
    "#findingsList",
    report.findings,
    (finding) => itemTemplate({
      title: `${finding.severity.toUpperCase()} · ${finding.category}`,
      body: `${finding.title} — ${finding.description}`,
      className: `severity-${finding.severity}`
    })
  );

  renderList(
    "#pageList",
    [
      row("Apex domain", report.page?.apexDomain),
      row("Effective URL", report.page?.effectiveUrl),
      row("HTTP status", stringify(report.page?.httpStatus)),
      row("Redirected", yesNo(report.page?.redirected)),
      row("Page title", report.page?.title),
      row("Primary IPs", listOrFallback(report.page?.primaryIPs)),
      row("Server", report.page?.server),
      row("TLS issuer", report.page?.tlsIssuer),
      row("TLS protocol", report.page?.tlsProtocol)
    ],
    renderRow
  );

  renderList(
    "#headerList",
    Object.entries(report.http.securityHeaders ?? {}).map(([key, value]) => ({
      title: key,
      body: value,
      className: `status-${value === "present" ? "green" : "red"}`
    })),
    renderEntry
  );

  renderList(
    "#webStackList",
    [
      row("Server header", report.webstack?.serverHeader),
      row("X-Powered-By", report.webstack?.poweredBy),
      row("Via", report.webstack?.reverseProxy),
      row("Cache layer", report.webstack?.cacheLayer),
      row("Delivery hints", listOrFallback(report.webstack?.deliveryHints)),
      row("Observed hosts", listOrFallback(report.webstack?.observedHosts)),
      ...(report.webstack?.headerSignals ?? []).map((entry) => row(`Signal ${entry.key}`, entry.value))
    ],
    renderRow
  );

  renderList(
    "#networkList",
    [
      row("IPv4", listOrFallback(report.dns.a)),
      row("IPv6", listOrFallback(report.dns.aaaa)),
      row("CNAME", listOrFallback(report.dns.cname)),
      row("Nameservers", listOrFallback(report.lists?.nameservers)),
      row("MX", listOrFallback(report.lists?.mailServers)),
      row("SPF", report.dns.txt?.spf),
      row("DMARC", report.dns.txt?.dmarc),
      row("CAA", formatCaa(report.dns.caa))
    ],
    renderRow
  );

  renderList(
    "#tlsList",
    [
      row("Protocol", report.tls.protocol),
      row("Cipher", report.tls.cipher?.name),
      row("Subject CN", report.tls.subject?.CN),
      row("Issuer CN", report.tls.issuer?.CN),
      row("Valid from", report.tls.validFrom),
      row("Valid to", report.tls.validTo),
      row("Serial", report.tls.serialNumber),
      row("SHA-256 fingerprint", report.tls.fingerprint256),
      row("Certificate SANs", listOrFallback(report.lists?.certificateNames))
    ],
    renderRow
  );

  renderList(
    "#ownershipList",
    [
      row("Registrar", report.ownership?.registrar),
      row("Registrant org", report.ownership?.registrantOrganization),
      row("Registrant email", report.ownership?.registrantEmail),
      row("Registrant country", report.ownership?.registrantCountry),
      row("Abuse email", report.ownership?.abuseEmail),
      row("WHOIS fingerprint", listOrFallback(report.ownership?.fingerprint))
    ],
    renderRow
  );

  renderList(
    "#whoisLinkedList",
    [{
      title: "WHOIS-linked domains",
      body: report.relationships?.whoisLinkedDomains?.rationale ?? "Coming soon.",
      className: "status-amber"
    }],
    renderEntry
  );
}

function paintAssessment(summary) {
  const value = `${summary.status.toUpperCase()} ${summary.score}`;
  const element = document.querySelector("#scoreValue");
  element.textContent = value;
  element.className = `metric-status status-${summary.status}`;
}

function renderList(selector, items, renderer) {
  const element = document.querySelector(selector);
  if (!items.length) {
    element.innerHTML = renderEntry({ title: "No data", body: "No data available." });
    return;
  }

  element.innerHTML = items.map(renderer).join("");
}

function renderRow(entry) {
  return renderEntry({ title: entry.label, body: entry.value });
}

function renderEntry(entry) {
  return itemTemplate(entry);
}

function itemTemplate({ title, body, className = "" }) {
  return `<article class="item ${className}"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(stringify(body))}</span></article>`;
}

function row(label, value) {
  return { label, value: stringify(value) };
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

function yesNo(value) {
  return value ? "Yes" : "No";
}

function formatCaa(records) {
  if (!records?.length) {
    return "None detected";
  }

  return records
    .map((record) => record.issue || record.issuewild || record.iodef || "present")
    .join(", ");
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
