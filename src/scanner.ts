import { promises as fs } from "fs";
import path from "path";
import { RULES, SEVERITY_RANK, type Rule, type Severity } from "./rules.js";

const MAX_FILE_SIZE = 1 * 1024 * 1024; // 1 MB — skip larger files
const BINARY_CHECK_BYTES = 8192;        // read this many bytes to detect binary

// File extensions we won't bother scanning — compiled artifacts, media, archives
const SKIP_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
  ".mp3", ".mp4", ".wav", ".ogg", ".mov", ".avi",
  ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx",
  ".woff", ".woff2", ".ttf", ".eot",
  ".exe", ".dll", ".so", ".dylib", ".bin",
  ".lock",  // package-lock.json, yarn.lock — lots of hashes, high false-positive rate
]);

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  file: string;
  line: number;
  content: string;  // the matching line, with secret redacted
  match: string;    // the raw matched text
  note: string;
}

export interface ScanOptions {
  minSeverity: Severity;
  excludePatterns: string[];
  redact: boolean;
}

function redactMatch(line: string, match: string): string {
  const visibleChars = Math.min(4, Math.floor(match.length * 0.2));
  const redacted = match.slice(0, visibleChars) + "*".repeat(match.length - visibleChars);
  return line.replace(match, redacted);
}

async function isBinary(filePath: string): Promise<boolean> {
  const fd = await fs.open(filePath, "r");
  try {
    const buffer = Buffer.alloc(BINARY_CHECK_BYTES);
    const { bytesRead } = await fd.read(buffer, 0, BINARY_CHECK_BYTES, 0);
    // Presence of a null byte is a reliable binary indicator for our purposes
    return buffer.subarray(0, bytesRead).includes(0);
  } finally {
    await fd.close();
  }
}

function isExcluded(filePath: string, excludePatterns: string[]): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  return excludePatterns.some((pattern) => {
    // Match against each path segment so "node_modules" catches it at any depth
    return normalized.split("/").includes(pattern) || normalized.includes(pattern);
  });
}

function scanLine(line: string, lineNumber: number, filePath: string, options: ScanOptions): Finding[] {
  const findings: Finding[] = [];

  for (const rule of RULES) {
    if (SEVERITY_RANK[rule.severity] < SEVERITY_RANK[options.minSeverity]) continue;

    // Reset lastIndex before each use — required when reusing regexes with the 'g' flag
    rule.pattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = rule.pattern.exec(line)) !== null) {
      const matchedText = match[0];
      const displayContent = options.redact
        ? redactMatch(line.trim(), matchedText)
        : line.trim();

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        file: filePath,
        line: lineNumber,
        content: displayContent,
        match: matchedText,
        note: rule.note,
      });
    }
  }

  return findings;
}

async function scanFile(filePath: string, options: ScanOptions): Promise<Finding[]> {
  const stat = await fs.stat(filePath);

  if (stat.size === 0 || stat.size > MAX_FILE_SIZE) return [];
  if (SKIP_EXTENSIONS.has(path.extname(filePath).toLowerCase())) return [];
  if (await isBinary(filePath)) return [];

  const content = await fs.readFile(filePath, "utf8");
  const lines = content.split("\n");
  const findings: Finding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const lineFindings = scanLine(lines[i], i + 1, filePath, options);
    findings.push(...lineFindings);
  }

  return findings;
}

async function walkDirectory(
  dirPath: string,
  options: ScanOptions,
  allFindings: Finding[]
): Promise<void> {
  let entries;
  try {
    entries = await fs.readdir(dirPath, { withFileTypes: true });
  } catch {
    // Permission errors etc. — skip silently
    return;
  }

  await Promise.all(
    entries.map(async (entry) => {
      const fullPath = path.join(dirPath, entry.name);

      if (isExcluded(fullPath, options.excludePatterns)) return;

      if (entry.isDirectory()) {
        await walkDirectory(fullPath, options, allFindings);
      } else if (entry.isFile()) {
        const findings = await scanFile(fullPath, options);
        allFindings.push(...findings);
      }
    })
  );
}

export async function scan(targetPath: string, options: ScanOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  const stat = await fs.stat(targetPath);

  if (stat.isDirectory()) {
    await walkDirectory(targetPath, options, findings);
  } else {
    const fileFindings = await scanFile(targetPath, options);
    findings.push(...fileFindings);
  }

  // Sort by severity (highest first), then by file path, then by line number
  findings.sort((a, b) => {
    const severityDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (severityDiff !== 0) return severityDiff;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

  return findings;
}
