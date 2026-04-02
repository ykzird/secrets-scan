<div style="text-align: center"><img src="https://cdn.ykzird.cloud/secrets-scan.svg" alt="secrets-scan" /> </div>

# @ykzird/secrets-scan

Scan files and directories for leaked secrets — API keys, tokens, connection strings, private keys, and more. Works as a CLI or as a Node.js library. Exits with code `1` when findings are present, making it easy to integrate into CI pipelines.

## Installation

```sh
# CLI — install globally
npm install -g @ykzird/secrets-scan

# Library — add to a project
npm install @ykzird/secrets-scan
```

## CLI usage

```sh
secrets-scan <path>                         # scan a file or directory
secrets-scan <path> --severity high         # report only high and critical findings
secrets-scan <path> --format json           # machine-readable JSON output
secrets-scan <path> --format sarif          # SARIF 2.1.0 for GitHub Code Scanning
secrets-scan <path> --no-redact            # show full secret values in output
secrets-scan <path> --exclude vendor temp  # add extra exclude patterns
secrets-scan <path> --no-default-excludes  # disable built-in exclude list
```

### Example output — text

```
  src/config.js
    line    4   CRITICAL   AWS Access Key ID
    │ const key = "AKIAIOSFODNN7EXAMPLE"
    │ AWS access key ID — pair with a secret key to authenticate API calls

  ── Summary ──────────────────────────────────
  Total findings: 1
     CRITICAL   1
```

### Example output — JSON

```json
{
  "summary": { "critical": 1, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "ruleId": "aws-access-key-id",
      "ruleName": "AWS Access Key ID",
      "severity": "critical",
      "file": "src/config.js",
      "line": 4,
      "content": "const key = \"AKIA**********************MPLE\"",
      "match": "AKIAIOSFODNN7EXAMPLE",
      "note": "AWS access key ID — pair with a secret key to authenticate API calls"
    }
  ]
}
```

### Excluded by default

`node_modules`, `.git`, `dist`, `build`, `coverage`, `.next`

Add patterns with `--exclude`, or remove all defaults with `--no-default-excludes`.

### Skipped automatically

- Files larger than 1 MB
- Binary files (detected by null-byte scan)
- Lock files (`.lock` extension — high false-positive rate from hashes)
- Common media, archive, and compiled binary extensions

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--severity <level>` | Minimum severity: `critical` \| `high` \| `medium` \| `low` | `low` |
| `--format <fmt>` | Output format: `text` \| `json` \| `sarif` | `text` |
| `--exclude <pattern...>` | Extra path patterns to exclude | — |
| `--no-default-excludes` | Disable the built-in exclude list | — |
| `--no-redact` | Show full secret values instead of masking | — |

### Redaction

By default, matched secrets are partially masked in output: the first few characters are preserved (up to 4, or 20% of the match length) and the remainder replaced with `*`. The raw match is always present in JSON output for programmatic use.

## Detected patterns

| Rule ID | Name | Severity |
|---------|------|----------|
| `aws-access-key-id` | AWS Access Key ID | critical |
| `aws-secret-access-key` | AWS Secret Access Key | critical |
| `private-key-block` | Private Key Block (RSA, EC, DSA, OpenSSH) | critical |
| `github-pat-classic` | GitHub Personal Access Token (classic) | high |
| `github-pat-fine-grained` | GitHub Personal Access Token (fine-grained) | high |
| `github-oauth-token` | GitHub OAuth Token | high |
| `connection-string` | Database / Service Connection String | high |
| `dotenv-secret` | `.env`-style secret assignment | medium |
| `generic-api-key` | Generic API key assignment | medium |

## Library usage

### Scan a path

```ts
import { scan, type ScanOptions } from '@ykzird/secrets-scan';

const findings = await scan('./src', {
  minSeverity: 'high',
  excludePatterns: ['vendor', 'fixtures'],
  redact: true,
});
```

`ScanOptions`:

```ts
{
  minSeverity:     Severity;      // 'critical' | 'high' | 'medium' | 'low'
  excludePatterns: string[];      // path segments or substrings to skip
  redact:          boolean;       // mask secrets in the content field
}
```

`Finding`:

```ts
{
  ruleId:   string;    // e.g. 'aws-access-key-id'
  ruleName: string;    // human-readable rule name
  severity: Severity;
  file:     string;    // absolute path to the file
  line:     number;    // 1-based line number
  content:  string;    // the matching line (redacted if options.redact is true)
  match:    string;    // raw matched text
  note:     string;    // explanation of the finding
}
```

Findings are sorted by severity (highest first), then by file path, then by line number.

### Access rules directly

```ts
import { RULES, SEVERITY_RANK, type Rule, type Severity } from '@ykzird/secrets-scan';

// RULES — array of all Rule objects
for (const rule of RULES) {
  console.log(rule.id, rule.severity, rule.pattern);
}

// SEVERITY_RANK — numeric rank for comparison (critical=3, high=2, medium=1, low=0)
const isCritical = SEVERITY_RANK[finding.severity] === SEVERITY_RANK['critical'];
```

`Rule`:

```ts
{
  id:       string;    // unique identifier
  name:     string;    // human-readable name
  pattern:  RegExp;    // must have the 'g' flag
  severity: Severity;
  note:     string;    // explanation shown in output
}
```

### Exported types

```ts
import type { Finding, ScanOptions, Rule, Severity } from '@ykzird/secrets-scan';
```

## SARIF support

The `--format sarif` output is compatible with SARIF 2.1.0 and can be uploaded to GitHub Code Scanning via the `upload-sarif` action:

```yaml
- name: Scan for secrets
  run: npx @ykzird/secrets-scan . --format sarif > results.sarif || true

- name: Upload results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## License

MIT
