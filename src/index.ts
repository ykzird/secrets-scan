#!/usr/bin/env node

import path from "path";
import { createCommand } from "commander";
import { scan, type ScanOptions } from "./scanner.js";
import { printText, printJson, printSarif } from "./output.js";
import { type Severity, SEVERITY_RANK } from "./rules.js";

const DEFAULT_EXCLUDES = ["node_modules", ".git", "dist", "build", "coverage", ".next"];
const VALID_FORMATS = ["text", "json", "sarif"] as const;
const VALID_SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

type OutputFormat = typeof VALID_FORMATS[number];

const program = createCommand();

program
  .name("secrets-scan")
  .description("Scan files and directories for leaked secrets and credentials")
  .version("1.0.0")
  .argument("<path>", "file or directory to scan")
  .option("--exclude <pattern...>", "additional path patterns to exclude (stacks with defaults)")
  .option("--no-default-excludes", "disable the default exclude list (node_modules, .git, dist, ...)")
  .option(
    "--severity <level>",
    `minimum severity to report: ${VALID_SEVERITIES.join(" | ")}`,
    "low"
  )
  .option("--format <fmt>", "output format: text | json | sarif", "text")
  .option("--no-redact", "show full secret in output instead of masking it")
  .action(async (targetArg: string, options: {
    exclude?: string[];
    defaultExcludes: boolean;
    severity: string;
    format: string;
    redact: boolean;
  }) => {
    // Validate format
    if (!VALID_FORMATS.includes(options.format as OutputFormat)) {
      console.error(`Error: unknown format '${options.format}' — must be one of: ${VALID_FORMATS.join(", ")}`);
      process.exit(1);
    }

    // Validate severity
    if (!VALID_SEVERITIES.includes(options.severity as Severity)) {
      console.error(`Error: unknown severity '${options.severity}' — must be one of: ${VALID_SEVERITIES.join(", ")}`);
      process.exit(1);
    }

    const excludePatterns = [
      ...(options.defaultExcludes ? DEFAULT_EXCLUDES : []),
      ...(options.exclude ?? []),
    ];

    const scanOptions: ScanOptions = {
      minSeverity: options.severity as Severity,
      excludePatterns,
      redact: options.redact,
    };

    const targetPath = path.resolve(targetArg);

    let findings;
    try {
      findings = await scan(targetPath, scanOptions);
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }

    const format = options.format as OutputFormat;

    if (format === "json") {
      printJson(findings);
    } else if (format === "sarif") {
      printSarif(findings, targetPath);
    } else {
      printText(findings, targetPath);
    }

    // Exit with code 1 if any findings — useful in CI pipelines
    if (findings.length > 0) process.exit(1);
  });

program.parse();
