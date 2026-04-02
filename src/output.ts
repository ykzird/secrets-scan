import chalk, { type ChalkInstance } from "chalk";
import type { Finding } from "./scanner.js";
import type { Severity } from "./rules.js";
import { RULES } from "./rules.js";

// ── Shared helpers ─────────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<Severity, ChalkInstance> = {
  critical: chalk.bgRed.white.bold,
  high:     chalk.red.bold,
  medium:   chalk.yellow,
  low:      chalk.dim,
};

function severityBadge(severity: Severity): string {
  return SEVERITY_COLOR[severity](` ${severity.toUpperCase()} `);
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  return findings.reduce(
    (acc, f) => { acc[f.severity]++; return acc; },
    { critical: 0, high: 0, medium: 0, low: 0 } as Record<Severity, number>
  );
}

// ── Text output ────────────────────────────────────────────────────────────

export function printText(findings: Finding[], targetPath: string): void {
  if (findings.length === 0) {
    console.log(chalk.green(`\n  No secrets found in ${targetPath}\n`));
    return;
  }

  let currentFile = "";

  for (const f of findings) {
    if (f.file !== currentFile) {
      currentFile = f.file;
      console.log(chalk.bold.cyan(`\n  ${f.file}`));
    }

    console.log(
      `    ${chalk.dim(`line ${String(f.line).padStart(4)}`)}  ${severityBadge(f.severity)}  ${chalk.white(f.ruleName)}`
    );
    console.log(`    ${chalk.dim("│")} ${chalk.dim(f.content)}`);
    console.log(`    ${chalk.dim("│")} ${chalk.dim(f.note)}`);
  }

  // Summary
  const counts = countBySeverity(findings);
  console.log(chalk.bold.cyan("\n  ── Summary ──────────────────────────────────"));
  console.log(`  Total findings: ${chalk.bold(String(findings.length))}`);

  for (const [severity, count] of Object.entries(counts) as [Severity, number][]) {
    if (count === 0) continue;
    console.log(`    ${severityBadge(severity)}  ${count}`);
  }

  console.log("");
}

// ── JSON output ────────────────────────────────────────────────────────────

export function printJson(findings: Finding[]): void {
  const counts = countBySeverity(findings);
  console.log(JSON.stringify({ summary: counts, findings }, null, 2));
}

// ── SARIF output ───────────────────────────────────────────────────────────
// SARIF 2.1.0 — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// Compatible with GitHub Code Scanning (upload via upload-sarif action)

type SarifLevel = "error" | "warning" | "note";

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, SarifLevel> = {
  critical: "error",
  high:     "error",
  medium:   "warning",
  low:      "note",
};

export function printSarif(findings: Finding[], targetPath: string): void {
  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "secrets-scan",
            version: "1.0.0",
            informationUri: "https://github.com/ykzird/secrets-scan",
            rules: RULES.map((rule) => ({
              id: rule.id,
              name: rule.name,
              shortDescription: { text: rule.name },
              fullDescription: { text: rule.note },
              defaultConfiguration: {
                level: SEVERITY_TO_SARIF_LEVEL[rule.severity],
              },
              properties: {
                severity: rule.severity,
              },
            })),
          },
        },
        originalUriBaseIds: {
          SRCROOT: { uri: `file:///${targetPath.replace(/\\/g, "/")}` },
        },
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: SEVERITY_TO_SARIF_LEVEL[f.severity],
          message: {
            text: `${f.ruleName}: ${f.note}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.file.replace(/\\/g, "/"),
                  uriBaseId: "SRCROOT",
                },
                region: {
                  startLine: f.line,
                },
              },
            },
          ],
        })),
      },
    ],
  };

  console.log(JSON.stringify(sarif, null, 2));
}
