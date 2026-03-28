import { readFile } from "node:fs/promises";

async function main() {
  const report = JSON.parse(await readFile(new URL("../samples/example-report.json", import.meta.url), "utf8"));

  const assertions = [
    report.schemaVersion === 1,
    typeof report.target === "string" && report.target.length > 0,
    Array.isArray(report.findings),
    typeof report.summary?.score === "number",
    Array.isArray(report.footprint?.relatedDomains)
  ];

  if (assertions.some((value) => !value)) {
    throw new Error("Report schema validation failed");
  }

  console.log("Report schema looks valid.");
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
