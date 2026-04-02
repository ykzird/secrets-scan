import { describe, it, expect } from 'vitest';
import { RULES, SEVERITY_RANK, type Rule } from './rules.js';

// Helper: find a rule by its ID
function getRule(id: string): Rule {
  const rule = RULES.find((r) => r.id === id);
  if (!rule) throw new Error(`Rule '${id}' not found`);
  return rule;
}

// Helper: test whether a pattern matches a string (resets lastIndex each call)
function matches(rule: Rule, input: string): boolean {
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(input);
}

// Helper: get first match string
function firstMatch(rule: Rule, input: string): string | null {
  rule.pattern.lastIndex = 0;
  const m = rule.pattern.exec(input);
  return m ? m[0] : null;
}

// ────────────────────────────────────────────────────────────────────────────
// RULES array shape
// ────────────────────────────────────────────────────────────────────────────

describe('RULES array', () => {
  it('exports a non-empty array', () => {
    expect(RULES).toBeInstanceOf(Array);
    expect(RULES.length).toBeGreaterThan(0);
  });

  it('every rule has required fields', () => {
    for (const rule of RULES) {
      expect(rule.id, `rule ${rule.id} missing id`).toBeTruthy();
      expect(rule.name, `rule ${rule.id} missing name`).toBeTruthy();
      expect(rule.pattern, `rule ${rule.id} missing pattern`).toBeInstanceOf(RegExp);
      expect(rule.severity, `rule ${rule.id} missing severity`).toMatch(/^(critical|high|medium|low)$/);
      expect(rule.note, `rule ${rule.id} missing note`).toBeTruthy();
    }
  });

  it('every rule pattern has the g flag', () => {
    for (const rule of RULES) {
      expect(rule.pattern.flags, `rule ${rule.id} missing g flag`).toContain('g');
    }
  });

  it('rule IDs are unique', () => {
    const ids = RULES.map((r) => r.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// SEVERITY_RANK
// ────────────────────────────────────────────────────────────────────────────

describe('SEVERITY_RANK', () => {
  it('critical > high > medium > low', () => {
    expect(SEVERITY_RANK.critical).toBeGreaterThan(SEVERITY_RANK.high);
    expect(SEVERITY_RANK.high).toBeGreaterThan(SEVERITY_RANK.medium);
    expect(SEVERITY_RANK.medium).toBeGreaterThan(SEVERITY_RANK.low);
  });

  it('low has rank 0', () => {
    expect(SEVERITY_RANK.low).toBe(0);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// aws-access-key-id
// ────────────────────────────────────────────────────────────────────────────

describe('rule: aws-access-key-id', () => {
  const rule = getRule('aws-access-key-id');

  it('matches a valid 20-char AKIA key', () => {
    expect(matches(rule, 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE')).toBe(true);
  });

  it('matches AKIA key embedded mid-string', () => {
    expect(matches(rule, 'key: AKIAIOSFODNN7EXAMPLE, region: us-east-1')).toBe(true);
  });

  it('captures all 20 characters (AKIA + 16)', () => {
    const m = firstMatch(rule, 'AKIAIOSFODNN7EXAMPLE');
    expect(m).toHaveLength(20);
    expect(m).toMatch(/^AKIA[0-9A-Z]{16}$/);
  });

  it('does not match AKIA with only 15 trailing chars', () => {
    expect(matches(rule, 'AKIAIOSFODNN7EXAM')).toBe(false);
  });

  it('does not match wrong prefix BKIA', () => {
    expect(matches(rule, 'BKIAIOSFODNN7EXAMPLE')).toBe(false);
  });

  it('does not match lowercase letters in the key body', () => {
    // Pattern requires [0-9A-Z] — lowercase is invalid
    expect(matches(rule, 'AKIAiosfodnn7example')).toBe(false);
  });

  it('has severity critical', () => {
    expect(rule.severity).toBe('critical');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// aws-secret-access-key
// ────────────────────────────────────────────────────────────────────────────

describe('rule: aws-secret-access-key', () => {
  const rule = getRule('aws-secret-access-key');

  const VALID_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';   // 40 chars

  it('matches aws_secret_access_key = <40-char value>', () => {
    expect(matches(rule, `aws_secret_access_key = ${VALID_SECRET}`)).toBe(true);
  });

  it('matches aws_secret: <40-char value>', () => {
    expect(matches(rule, `aws_secret: ${VALID_SECRET}`)).toBe(true);
  });

  it('matches with quoted value', () => {
    expect(matches(rule, `aws_secret_access_key = '${VALID_SECRET}'`)).toBe(true);
  });

  it('is case-insensitive on key name', () => {
    expect(matches(rule, `AWS_SECRET_ACCESS_KEY = ${VALID_SECRET}`)).toBe(true);
    expect(matches(rule, `AWS_SECRET = ${VALID_SECRET}`)).toBe(true);
  });

  it('does not match a 39-char value (too short)', () => {
    const short = VALID_SECRET.slice(0, 39);
    expect(matches(rule, `aws_secret_access_key = ${short}`)).toBe(false);
  });

  it('matches AWS_SECRET_KEY = <40-char value>', () => {
    expect(matches(rule, `AWS_SECRET_KEY = ${VALID_SECRET}`)).toBe(true);
  });

  it('does not match a generic line without the keyword', () => {
    expect(matches(rule, `secret = ${VALID_SECRET}`)).toBe(false);
  });

  it('has severity critical', () => {
    expect(rule.severity).toBe('critical');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// private-key-block
// ────────────────────────────────────────────────────────────────────────────

describe('rule: private-key-block', () => {
  const rule = getRule('private-key-block');

  it('matches RSA private key header', () => {
    expect(matches(rule, '-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
  });

  it('matches EC private key header', () => {
    expect(matches(rule, '-----BEGIN EC PRIVATE KEY-----')).toBe(true);
  });

  it('matches DSA private key header', () => {
    expect(matches(rule, '-----BEGIN DSA PRIVATE KEY-----')).toBe(true);
  });

  it('matches OPENSSH private key header', () => {
    expect(matches(rule, '-----BEGIN OPENSSH PRIVATE KEY-----')).toBe(true);
  });

  it('matches generic PRIVATE KEY header (no algorithm prefix)', () => {
    expect(matches(rule, '-----BEGIN PRIVATE KEY-----')).toBe(true);
  });

  it('does not match public key header', () => {
    expect(matches(rule, '-----BEGIN PUBLIC KEY-----')).toBe(false);
  });

  it('does not match certificate header', () => {
    expect(matches(rule, '-----BEGIN CERTIFICATE-----')).toBe(false);
  });

  it('has severity critical', () => {
    expect(rule.severity).toBe('critical');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// github-pat-classic
// ────────────────────────────────────────────────────────────────────────────

describe('rule: github-pat-classic', () => {
  const rule = getRule('github-pat-classic');

  // 36 alphanumeric chars after "ghp_"
  const VALID_TOKEN = 'ghp_' + 'A'.repeat(36);

  it('matches a valid classic PAT', () => {
    expect(matches(rule, `token = ${VALID_TOKEN}`)).toBe(true);
  });

  it('captures the full 40-char token', () => {
    const m = firstMatch(rule, VALID_TOKEN);
    expect(m).toHaveLength(40);
  });

  it('does not match with only 35 chars after prefix', () => {
    expect(matches(rule, 'ghp_' + 'A'.repeat(35))).toBe(false);
  });

  it('does not match wrong prefix ghs_', () => {
    expect(matches(rule, 'ghs_' + 'A'.repeat(36))).toBe(false);
  });

  it('has severity high', () => {
    expect(rule.severity).toBe('high');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// github-pat-fine-grained
// ────────────────────────────────────────────────────────────────────────────

describe('rule: github-pat-fine-grained', () => {
  const rule = getRule('github-pat-fine-grained');

  // 82 chars (alphanumeric + underscore) after "github_pat_"
  const VALID_TOKEN = 'github_pat_' + 'A'.repeat(82);

  it('matches a valid fine-grained PAT', () => {
    expect(matches(rule, VALID_TOKEN)).toBe(true);
  });

  it('captures the full token', () => {
    const m = firstMatch(rule, VALID_TOKEN);
    expect(m).toHaveLength(11 + 82); // "github_pat_" = 11 chars
  });

  it('matches a token longer than 82 chars after prefix (variable-length PATs)', () => {
    // Real GitHub fine-grained PATs can be longer; pattern now uses {82,}
    expect(matches(rule, 'github_pat_' + 'A'.repeat(93))).toBe(true);
  });

  it('does not match with only 81 chars after prefix', () => {
    expect(matches(rule, 'github_pat_' + 'A'.repeat(81))).toBe(false);
  });

  it('does not match wrong prefix github_tok_', () => {
    expect(matches(rule, 'github_tok_' + 'A'.repeat(82))).toBe(false);
  });

  it('has severity high', () => {
    expect(rule.severity).toBe('high');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// github-oauth-token
// ────────────────────────────────────────────────────────────────────────────

describe('rule: github-oauth-token', () => {
  const rule = getRule('github-oauth-token');

  const VALID_TOKEN = 'gho_' + 'A'.repeat(36);

  it('matches a valid OAuth token', () => {
    expect(matches(rule, VALID_TOKEN)).toBe(true);
  });

  it('does not match with 35 chars after prefix', () => {
    expect(matches(rule, 'gho_' + 'A'.repeat(35))).toBe(false);
  });

  it('does not match wrong prefix ghp_', () => {
    // ghp_ belongs to classic PAT rule, not oauth rule
    expect(matches(rule, 'ghp_' + 'A'.repeat(36))).toBe(false);
  });

  it('has severity high', () => {
    expect(rule.severity).toBe('high');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// connection-string
// ────────────────────────────────────────────────────────────────────────────

describe('rule: connection-string', () => {
  const rule = getRule('connection-string');

  it('matches a postgres connection string', () => {
    expect(matches(rule, 'postgres://myuser:mypassword@localhost:5432/db')).toBe(true);
  });

  it('matches a postgresql connection string', () => {
    expect(matches(rule, 'postgresql://user:pass@host/db')).toBe(true);
  });

  it('matches a mysql connection string', () => {
    expect(matches(rule, 'mysql://root:secret@127.0.0.1:3306/mydb')).toBe(true);
  });

  it('matches a mongodb connection string', () => {
    expect(matches(rule, 'mongodb://admin:hunter2@mongo.example.com:27017/db')).toBe(true);
  });

  it('matches a redis connection string', () => {
    expect(matches(rule, 'redis://default:redispass@redis.example.com:6379')).toBe(true);
  });

  it('matches an amqp connection string', () => {
    expect(matches(rule, 'amqp://guest:guest@rabbitmq:5672/')).toBe(true);
  });

  it('is case-insensitive on scheme', () => {
    expect(matches(rule, 'POSTGRES://user:pass@host/db')).toBe(true);
  });

  it('does not match a connection string without a password (no colon before @)', () => {
    // The pattern requires [^:]+:[^@\s'"]+ so user@host with no colon won't match
    expect(matches(rule, 'postgres://user@host/db')).toBe(false);
  });

  it('does not match an http URL', () => {
    expect(matches(rule, 'http://user:pass@example.com')).toBe(false);
  });

  it('has severity high', () => {
    expect(rule.severity).toBe('high');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// dotenv-secret
// ────────────────────────────────────────────────────────────────────────────

describe('rule: dotenv-secret', () => {
  const rule = getRule('dotenv-secret');

  it('matches SECRET=value (8+ chars)', () => {
    expect(matches(rule, 'SECRET=mysecret1')).toBe(true);
  });

  it('matches PASSWORD=value', () => {
    expect(matches(rule, 'PASSWORD=hunter2!')).toBe(true);
  });

  it('matches API_KEY=value', () => {
    expect(matches(rule, 'API_KEY=abc12345678')).toBe(true);
  });

  it('matches ACCESS_TOKEN=value', () => {
    expect(matches(rule, 'ACCESS_TOKEN=tok_ABCDEFGH')).toBe(true);
  });

  it('matches SIGNING_KEY=value', () => {
    expect(matches(rule, 'SIGNING_KEY=supersecretvalue')).toBe(true);
  });

  it('matches ENCRYPTION_KEY=value', () => {
    expect(matches(rule, 'ENCRYPTION_KEY=aeskey12345678')).toBe(true);
  });

  it('matches PRIVATE_KEY=value', () => {
    expect(matches(rule, 'PRIVATE_KEY=myPrivKey1234')).toBe(true);
  });

  it('matches AUTH_TOKEN=value', () => {
    expect(matches(rule, 'AUTH_TOKEN=bearertoken123')).toBe(true);
  });

  it('matches API_SECRET=value', () => {
    expect(matches(rule, 'API_SECRET=someApiSecret')).toBe(true);
  });

  it('is case-insensitive on the key name', () => {
    expect(matches(rule, 'secret=mysecret1')).toBe(true);
    expect(matches(rule, 'password=abc12345')).toBe(true);
  });

  it('matches JWT_SECRET=value (prefixed compound name)', () => {
    expect(matches(rule, 'JWT_SECRET=somesecretvalue')).toBe(true);
  });

  it('matches APP_PASSWORD=value (prefixed compound name)', () => {
    expect(matches(rule, 'APP_PASSWORD=hunter21234')).toBe(true);
  });

  it('matches MY_API_KEY=value (nested prefix)', () => {
    expect(matches(rule, 'MY_API_KEY=abc12345678')).toBe(true);
  });

  it('does not match PASSPORT=value (keyword embedded mid-word)', () => {
    expect(matches(rule, 'PASSPORT=hunter21234')).toBe(false);
  });

  it('does not match a value shorter than 8 characters', () => {
    // Pattern requires {8,} characters in the value
    expect(matches(rule, 'SECRET=short')).toBe(false);
  });

  it('does not match a non-secret variable name', () => {
    expect(matches(rule, 'NODE_ENV=production')).toBe(false);
    expect(matches(rule, 'PORT=3000')).toBe(false);
  });

  it('has severity medium', () => {
    expect(rule.severity).toBe('medium');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// generic-api-key
// ────────────────────────────────────────────────────────────────────────────

describe('rule: generic-api-key', () => {
  const rule = getRule('generic-api-key');

  it('matches api_key: <20+ char value> in quotes', () => {
    expect(matches(rule, 'api_key: "abcdefghijklmnopqrstu"')).toBe(true);
  });

  it('matches apikey= <20+ char value>', () => {
    expect(matches(rule, "apikey= 'abcdefghijklmnopqrstu'")).toBe(true);
  });

  it('matches api-key: <20+ char value>', () => {
    expect(matches(rule, 'api-key: "abcdefghijklmnopqrstu"')).toBe(true);
  });

  it('matches APIKEY= assignment', () => {
    expect(matches(rule, 'APIKEY = "my-long-api-key-value-here"')).toBe(true);
  });

  it('is case-insensitive', () => {
    expect(matches(rule, 'API_KEY="abcdefghijklmnopqrstu"')).toBe(true);
  });

  it('matches unquoted api_key = <20+ char value>', () => {
    expect(matches(rule, 'api_key = abcdefghijklmnopqrstu')).toBe(true);
  });

  it('does not match a value shorter than 20 chars', () => {
    expect(matches(rule, 'api_key: "short_key"')).toBe(false);
  });

  it('does not match an unrelated line', () => {
    expect(matches(rule, 'const x = 42')).toBe(false);
  });

  it('has severity medium', () => {
    expect(rule.severity).toBe('medium');
  });
});
