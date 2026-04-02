# Additional Rules Reference

Patterns not included in the default ruleset but worth adding depending on your stack.
Each entry follows the same `Rule` shape used in `src/rules.ts`.

---

## Cloud Providers

### Azure

```typescript
// Azure Storage Account Key (88-char base64)
{
  id: "azure-storage-key",
  name: "Azure Storage Account Key",
  pattern: /(?:AccountKey|storageKey)\s*[=:]\s*['"]?([A-Za-z0-9+/]{88}==)['"]?/gi,
  severity: "critical",
  note: "Azure Storage Account key grants full access to the storage account",
}

// Azure SAS Token
{
  id: "azure-sas-token",
  name: "Azure SAS Token",
  pattern: /sv=\d{4}-\d{2}-\d{2}&s[sco]=\w+&sp=[rwdlacuptfx]+/gi,
  severity: "high",
  note: "Azure Shared Access Signature token — grants scoped access to Azure resources",
}

// Azure Service Principal Client Secret (GUID + secret pattern)
{
  id: "azure-client-secret",
  name: "Azure Client Secret",
  pattern: /(?:client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9~._\-]{34,40})['"]?/gi,
  severity: "critical",
  note: "Azure Service Principal credential — can be used to authenticate as an app identity",
}
```

### GCP

```typescript
// GCP Service Account JSON key file (look for the type field)
{
  id: "gcp-service-account",
  name: "GCP Service Account Key",
  pattern: /"type"\s*:\s*"service_account"/g,
  severity: "critical",
  note: "Presence of 'type: service_account' indicates a GCP service account key file",
}

// GCP API Key
{
  id: "gcp-api-key",
  name: "GCP API Key",
  pattern: /AIza[0-9A-Za-z\-_]{35}/g,
  severity: "high",
  note: "GCP API key — scope depends on what APIs it is enabled for",
}
```

---

## Payment Processors

### Stripe

```typescript
// Stripe Live Secret Key
{
  id: "stripe-secret-key",
  name: "Stripe Secret Key (live)",
  pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
  severity: "critical",
  note: "Stripe live secret key — full API access including charges and refunds",
}

// Stripe Restricted Key
{
  id: "stripe-restricted-key",
  name: "Stripe Restricted Key",
  pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
  severity: "high",
  note: "Stripe restricted key — scoped access but still a live credential",
}

// Stripe Publishable Key (lower severity — public by design, but worth flagging in server-side code)
{
  id: "stripe-publishable-key",
  name: "Stripe Publishable Key",
  pattern: /pk_live_[0-9a-zA-Z]{24,}/g,
  severity: "low",
  note: "Stripe publishable key — public by design, but flag if found in server-side or backend config",
}

// Stripe Webhook Secret
{
  id: "stripe-webhook-secret",
  name: "Stripe Webhook Secret",
  pattern: /whsec_[0-9a-zA-Z]{32,}/g,
  severity: "high",
  note: "Stripe webhook signing secret — allows forging webhook events",
}
```

---

## Communication Platforms

### Slack

```typescript
// Slack Bot Token
{
  id: "slack-bot-token",
  name: "Slack Bot Token",
  pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g,
  severity: "high",
  note: "Slack bot token — can read messages and post as the bot",
}

// Slack User Token
{
  id: "slack-user-token",
  name: "Slack User Token",
  pattern: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}/g,
  severity: "critical",
  note: "Slack user token — acts with full user privileges in the workspace",
}

// Slack App-Level Token
{
  id: "slack-app-token",
  name: "Slack App-Level Token",
  pattern: /xapp-\d-[A-Z0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{64}/g,
  severity: "high",
  note: "Slack app-level token for Socket Mode connections",
}

// Slack Webhook URL
{
  id: "slack-webhook",
  name: "Slack Incoming Webhook URL",
  pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
  severity: "medium",
  note: "Slack webhook URL — allows posting messages to a channel without auth",
}
```

### Twilio

```typescript
// Twilio Account SID
{
  id: "twilio-account-sid",
  name: "Twilio Account SID",
  pattern: /AC[a-f0-9]{32}/g,
  severity: "medium",
  note: "Twilio Account SID — identifier, not secret on its own, but flag alongside auth tokens",
}

// Twilio Auth Token
{
  id: "twilio-auth-token",
  name: "Twilio Auth Token",
  pattern: /(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/gi,
  severity: "critical",
  note: "Twilio auth token — full API access including sending SMS/calls",
}
```

---

## Email Services

### SendGrid

```typescript
{
  id: "sendgrid-api-key",
  name: "SendGrid API Key",
  pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
  severity: "high",
  note: "SendGrid API key — can send email as your domain",
}
```

### Mailgun

```typescript
{
  id: "mailgun-api-key",
  name: "Mailgun API Key",
  pattern: /key-[0-9a-f]{32}/g,
  severity: "high",
  note: "Mailgun private API key — can send and read email",
}
```

---

## Source Control & CI

### npm

```typescript
{
  id: "npm-token",
  name: "npm Access Token",
  pattern: /(?:npm_)[A-Za-z0-9]{36}/g,
  severity: "high",
  note: "npm access token — can publish packages under your account",
}
```

### CircleCI

```typescript
{
  id: "circleci-token",
  name: "CircleCI Personal API Token",
  pattern: /(?:CIRCLE_TOKEN|circleci_token)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?/gi,
  severity: "high",
  note: "CircleCI personal API token — can trigger builds and read env vars",
}
```

---

## Cryptographic Material

### PGP

```typescript
{
  id: "pgp-private-key",
  name: "PGP Private Key Block",
  pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
  severity: "critical",
  note: "PGP private key — allows decrypting messages and forging signatures",
}
```

### Generic high-entropy strings

High-entropy string detection catches secrets that don't match known patterns but are statistically
unlikely to be human-written text. Prone to false positives (minified JS, base64 assets, hashes).
Recommended only with strict file extension filtering.

```typescript
// Not a regex — requires a Shannon entropy calculation helper:
// H = -sum(p(c) * log2(p(c))) for each unique character c
// Flag strings over ~4.5 bits/char that are 20+ chars long
// See: https://en.wikipedia.org/wiki/Entropy_(information_theory)
```

---

## Notes on adding rules

1. Copy the object literal into the `RULES` array in `src/rules.ts`
2. Give it a unique `id` — used in SARIF output as `ruleId`
3. Test with a known example before committing — overly broad patterns produce noisy output
4. For patterns with capture groups, make sure the regex still matches the full secret (the scanner
   uses `.test()` for detection and captures the full `.match()` for display)
