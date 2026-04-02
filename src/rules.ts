export type Severity = "critical" | "high" | "medium" | "low";

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0,
};

export interface Rule {
  id: string;
  name: string;
  // Must use the 'g' flag so repeated calls to exec() advance through the line
  pattern: RegExp;
  severity: Severity;
  note: string;
}

export const RULES: Rule[] = [
  // ── AWS ────────────────────────────────────────────────────────────────────
  {
    id: "aws-access-key-id",
    name: "AWS Access Key ID",
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: "critical",
    note: "AWS access key ID — pair with a secret key to authenticate API calls",
  },
  {
    id: "aws-secret-access-key",
    name: "AWS Secret Access Key",
    pattern: /(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: "critical",
    note: "AWS secret access key — combined with an access key ID grants AWS API access",
  },

  // ── Private keys ───────────────────────────────────────────────────────────
  {
    id: "private-key-block",
    name: "Private Key Block",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: "critical",
    note: "Private key material — exposure allows impersonation and decryption of traffic",
  },

  // ── GitHub ─────────────────────────────────────────────────────────────────
  {
    id: "github-pat-classic",
    name: "GitHub Personal Access Token (classic)",
    pattern: /ghp_[A-Za-z0-9]{36}/g,
    severity: "high",
    note: "GitHub classic PAT — scopes vary but can include repo read/write",
  },
  {
    id: "github-pat-fine-grained",
    name: "GitHub Personal Access Token (fine-grained)",
    pattern: /github_pat_[A-Za-z0-9_]{82,}/g,
    severity: "high",
    note: "GitHub fine-grained PAT — repository-scoped access token",
  },
  {
    id: "github-oauth-token",
    name: "GitHub OAuth Token",
    pattern: /gho_[A-Za-z0-9]{36}/g,
    severity: "high",
    note: "GitHub OAuth access token",
  },

  // ── Connection strings ─────────────────────────────────────────────────────
  {
    id: "connection-string",
    name: "Database / Service Connection String",
    pattern: /(?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^:]+:[^@\s'"]+@/gi,
    severity: "high",
    note: "Connection string with embedded credentials — grants direct database access",
  },

  // ── .env-style assignments ─────────────────────────────────────────────────
  {
    id: "dotenv-secret",
    name: ".env Secret Assignment",
    // Match KEY=value where KEY strongly implies it is a secret.
    // The optional (?:\w+_)? prefix allows compound names like JWT_SECRET or APP_PASSWORD
    // while the \b after the keyword prevents matching substrings (e.g. PASSWORDS, PASSPORT).
    pattern: /(?:^|[\s;])(?:\w+_)?(?:SECRET|PASSWORD|PASSWD|PASS|API_KEY|API_SECRET|AUTH_TOKEN|ACCESS_TOKEN|PRIVATE_KEY|ENCRYPTION_KEY|SIGNING_KEY)\b\s*=\s*['"]?[A-Za-z0-9!@#$%^&*()\-_+={}\[\]|;:,.<>?/]{8,}['"]?/gim,
    severity: "medium",
    note: "Credential-like environment variable assignment",
  },

  // ── Generic API key patterns ───────────────────────────────────────────────
  {
    id: "generic-api-key",
    name: "Generic API Key Assignment",
    pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9\-_]{20,})['"]?/gi,
    severity: "medium",
    note: "Generic API key assignment — review to determine actual sensitivity",
  },
];
