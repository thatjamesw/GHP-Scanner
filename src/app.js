const state = {
  report: null
};

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
  state.report = report;

  document.querySelector("#emptyState").classList.add("hidden");
  document.querySelector("#reportView").classList.remove("hidden");

  text("#targetValue", report.target);
  text("#scoreValue", `${report.summary.score} / 100`);
  text("#findingValue", String(report.summary.findingCount));
  text("#relatedDomainValue", String(report.summary.relatedDomains));

  renderList(
    "#findingsList",
    report.findings,
    (finding) => itemTemplate({
      title: `${finding.severity.toUpperCase()} · ${finding.title}`,
      body: finding.description,
      className: `severity-${finding.severity}`
    })
  );

  renderList(
    "#headerList",
    Object.entries(report.http.securityHeaders ?? {}).map(([key, value]) => ({
      key,
      value
    })),
    (entry) => itemTemplate({
      title: entry.key,
      body: entry.value
    })
  );

  renderList(
    "#infraList",
    [
      { label: "IPs", value: listOrFallback(report.footprint.ips) },
      { label: "Nameservers", value: listOrFallback(report.footprint.nameservers) },
      { label: "MX", value: listOrFallback(report.footprint.mail) },
      { label: "HTTP endpoint", value: report.http.effectiveUrl ?? "Unavailable" },
      { label: "Registrar", value: report.whois.registrar ?? "Unavailable" }
    ],
    (entry) => itemTemplate({
      title: entry.label,
      body: entry.value
    })
  );

  renderList(
    "#footprintList",
    [
      ...((report.footprint.relatedHosts ?? []).map((value) => ({ kind: "Host", value }))),
      ...((report.footprint.relatedDomains ?? []).map((value) => ({ kind: "Domain", value })))
    ],
    (entry) => itemTemplate({
      title: entry.kind,
      body: entry.value
    })
  );
}

function renderList(selector, items, toHtml) {
  const element = document.querySelector(selector);
  if (!items.length) {
    element.innerHTML = itemTemplate({ title: "None", body: "No data available." });
    return;
  }

  element.innerHTML = items.map(toHtml).join("");
}

function itemTemplate({ title, body, className = "" }) {
  return `<article class="item ${className}"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(body)}</span></article>`;
}

function listOrFallback(values) {
  return values?.length ? values.join(", ") : "None detected";
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
