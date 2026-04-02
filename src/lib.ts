// Library entry point — import this when using secrets-scan as a package.
// The CLI entry point (src/index.ts) is separate.

export { scan } from "./scanner.js";
export { RULES, SEVERITY_RANK } from "./rules.js";
export type { Finding, ScanOptions } from "./scanner.js";
export type { Rule, Severity } from "./rules.js";
