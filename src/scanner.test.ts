import { describe, it, expect, afterEach } from 'vitest';
import os from 'os';
import fs from 'fs';
import path from 'path';
import { scan, type ScanOptions } from './scanner.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

const DEFAULT_OPTIONS: ScanOptions = {
  minSeverity: 'low',
  excludePatterns: [],
  redact: false,
};

const tmpDirs: string[] = [];

function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secrets-scan-test-'));
  tmpDirs.push(dir);
  return dir;
}

function writeFile(dir: string, name: string, content: string | Buffer): string {
  const filePath = path.join(dir, name);
  if (typeof content === 'string') {
    fs.writeFileSync(filePath, content, 'utf8');
  } else {
    fs.writeFileSync(filePath, content);
  }
  return filePath;
}

afterEach(() => {
  // Clean up all temp dirs created during the test
  for (const dir of tmpDirs.splice(0)) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
});

// ── scan() — single file ──────────────────────────────────────────────────────

describe('scan() — single file with secret', () => {
  it('detects an AWS access key ID in a plain text file', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'config.txt', 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n');

    const findings = await scan(filePath, DEFAULT_OPTIONS);

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('aws-access-key-id');
    expect(findings[0].file).toBe(filePath);
    expect(findings[0].line).toBe(1);
  });

  it('returns no findings for a clean file', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'clean.ts', 'export const PORT = 3000;\nexport const HOST = "localhost";\n');

    const findings = await scan(filePath, DEFAULT_OPTIONS);

    expect(findings).toHaveLength(0);
  });

  it('returns no findings for an empty file', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'empty.txt', '');

    const findings = await scan(filePath, DEFAULT_OPTIONS);

    expect(findings).toHaveLength(0);
  });

  it('skips binary files (buffer with null bytes)', async () => {
    const dir = makeTmpDir();
    const binaryContent = Buffer.alloc(100);
    binaryContent[10] = 0x00; // null byte triggers binary detection
    // Embed a fake secret so we confirm it's the binary check stopping it
    const secretPart = Buffer.from('AKIAIOSFODNN7EXAMPLE');
    secretPart.copy(binaryContent, 20);
    const filePath = writeFile(dir, 'binary.dat', binaryContent);

    const findings = await scan(filePath, DEFAULT_OPTIONS);

    expect(findings).toHaveLength(0);
  });

  it('skips files with excluded extensions (.png)', async () => {
    const dir = makeTmpDir();
    // Write text content with a secret but a .png extension
    const filePath = writeFile(dir, 'image.png', 'AKIAIOSFODNN7EXAMPLE');

    const findings = await scan(filePath, DEFAULT_OPTIONS);

    expect(findings).toHaveLength(0);
  });

  it('skips .lock files', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'package-lock.json.lock', 'AKIAIOSFODNN7EXAMPLE');

    const findings = await scan(filePath, DEFAULT_OPTIONS);

    expect(findings).toHaveLength(0);
  });

  it('includes correct line numbers for multi-line files', async () => {
    const dir = makeTmpDir();
    const content = [
      'const a = 1;',
      'const b = 2;',
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
    ].join('\n');
    const filePath = writeFile(dir, 'multi.env', content);

    const findings = await scan(filePath, DEFAULT_OPTIONS);

    const awsFindings = findings.filter((f) => f.ruleId === 'aws-access-key-id');
    expect(awsFindings.length).toBeGreaterThan(0);
    expect(awsFindings[0].line).toBe(3);
  });
});

// ── scan() — finding fields ───────────────────────────────────────────────────

describe('scan() — finding fields', () => {
  it('finding has all required fields', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'creds.env', 'AKIAIOSFODNN7EXAMPLE');

    const findings = await scan(filePath, DEFAULT_OPTIONS);

    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0];
    expect(f).toHaveProperty('ruleId');
    expect(f).toHaveProperty('ruleName');
    expect(f).toHaveProperty('severity');
    expect(f).toHaveProperty('file');
    expect(f).toHaveProperty('line');
    expect(f).toHaveProperty('content');
    expect(f).toHaveProperty('match');
    expect(f).toHaveProperty('note');
  });

  it('match field contains the raw secret text', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'creds.env', 'AKIAIOSFODNN7EXAMPLE');

    const findings = await scan(filePath, DEFAULT_OPTIONS);
    const f = findings.find((x) => x.ruleId === 'aws-access-key-id');

    expect(f?.match).toBe('AKIAIOSFODNN7EXAMPLE');
  });

  it('content is redacted when redact option is true', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'creds.env', 'AKIAIOSFODNN7EXAMPLE');

    const findings = await scan(filePath, { ...DEFAULT_OPTIONS, redact: true });
    const f = findings.find((x) => x.ruleId === 'aws-access-key-id');

    // Content should contain stars — the match is partially masked
    expect(f?.content).toContain('*');
    // The raw match field is still the unmasked value
    expect(f?.match).toBe('AKIAIOSFODNN7EXAMPLE');
  });

  it('content is the full line (trimmed) when redact is false', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'creds.env', '  key: AKIAIOSFODNN7EXAMPLE  ');

    const findings = await scan(filePath, { ...DEFAULT_OPTIONS, redact: false });
    const f = findings.find((x) => x.ruleId === 'aws-access-key-id');

    expect(f?.content).toBe('key: AKIAIOSFODNN7EXAMPLE');
  });
});

// ── scan() — minSeverity filtering ───────────────────────────────────────────

describe('scan() — minSeverity filtering', () => {
  // We need a file that triggers both a critical and a medium rule.
  // AWS access key (critical) + dotenv SECRET assignment (medium)
  const MULTI_SECRET =
    'AKIAIOSFODNN7EXAMPLE\nSECRET=hunter2123456\n';

  it('returns all findings when minSeverity is low', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'secrets.env', MULTI_SECRET);

    const findings = await scan(filePath, { ...DEFAULT_OPTIONS, minSeverity: 'low' });

    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('aws-access-key-id');
    // medium-severity dotenv-secret should be included too
    expect(ruleIds).toContain('dotenv-secret');
  });

  it('excludes medium findings when minSeverity is critical', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'secrets.env', MULTI_SECRET);

    const findings = await scan(filePath, { ...DEFAULT_OPTIONS, minSeverity: 'critical' });

    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('aws-access-key-id');
    expect(ruleIds).not.toContain('dotenv-secret');
  });

  it('excludes all findings when minSeverity is critical and file has only medium findings', async () => {
    const dir = makeTmpDir();
    const filePath = writeFile(dir, 'medium.env', 'SECRET=hunter2123456\n');

    const findings = await scan(filePath, { ...DEFAULT_OPTIONS, minSeverity: 'critical' });

    expect(findings).toHaveLength(0);
  });
});

// ── scan() — directory traversal ─────────────────────────────────────────────

describe('scan() — directory traversal', () => {
  it('finds secrets in nested subdirectories', async () => {
    const dir = makeTmpDir();
    const subDir = path.join(dir, 'sub', 'nested');
    fs.mkdirSync(subDir, { recursive: true });
    writeFile(subDir, 'secret.env', 'AKIAIOSFODNN7EXAMPLE');

    const findings = await scan(dir, DEFAULT_OPTIONS);

    expect(findings.some((f) => f.ruleId === 'aws-access-key-id')).toBe(true);
  });

  it('finds secrets in multiple files across the directory', async () => {
    const dir = makeTmpDir();
    writeFile(dir, 'fileA.env', 'AKIAIOSFODNN7EXAMPLE\n');
    writeFile(dir, 'fileB.env', 'github_pat_' + 'A'.repeat(82) + '\n');

    const findings = await scan(dir, DEFAULT_OPTIONS);

    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('aws-access-key-id');
    expect(ruleIds).toContain('github-pat-fine-grained');
  });

  it('returns empty array for a directory with no secrets', async () => {
    const dir = makeTmpDir();
    writeFile(dir, 'clean.ts', 'const x = 1;\n');
    writeFile(dir, 'clean2.ts', 'const y = "hello";\n');

    const findings = await scan(dir, DEFAULT_OPTIONS);

    expect(findings).toHaveLength(0);
  });
});

// ── scan() — excludePatterns ──────────────────────────────────────────────────

describe('scan() — excludePatterns', () => {
  it('skips a directory named node_modules when excluded', async () => {
    const dir = makeTmpDir();
    const nmDir = path.join(dir, 'node_modules');
    fs.mkdirSync(nmDir);
    writeFile(nmDir, 'secret.env', 'AKIAIOSFODNN7EXAMPLE');

    const findings = await scan(dir, { ...DEFAULT_OPTIONS, excludePatterns: ['node_modules'] });

    expect(findings).toHaveLength(0);
  });

  it('skips a .git directory when excluded', async () => {
    const dir = makeTmpDir();
    const gitDir = path.join(dir, '.git');
    fs.mkdirSync(gitDir);
    writeFile(gitDir, 'config', 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

    const findings = await scan(dir, { ...DEFAULT_OPTIONS, excludePatterns: ['.git'] });

    expect(findings).toHaveLength(0);
  });

  it('does not skip the directory if excludePatterns is empty', async () => {
    const dir = makeTmpDir();
    const subDir = path.join(dir, 'node_modules');
    fs.mkdirSync(subDir);
    writeFile(subDir, 'secret.env', 'AKIAIOSFODNN7EXAMPLE');

    // No excludePatterns — should find the secret
    const findings = await scan(dir, { ...DEFAULT_OPTIONS, excludePatterns: [] });

    expect(findings.some((f) => f.ruleId === 'aws-access-key-id')).toBe(true);
  });

  it('skips files matching a custom pattern', async () => {
    const dir = makeTmpDir();
    writeFile(dir, 'safe.env', 'AKIAIOSFODNN7EXAMPLE');

    const findings = await scan(dir, { ...DEFAULT_OPTIONS, excludePatterns: ['safe.env'] });

    expect(findings).toHaveLength(0);
  });
});

// ── scan() — sort order ───────────────────────────────────────────────────────

describe('scan() — sort order', () => {
  it('sorts findings by severity descending (critical before medium)', async () => {
    const dir = makeTmpDir();
    // Put medium severity first in the file, critical second
    const content = 'SECRET=hunter2123456\nAKIAIOSFODNN7EXAMPLE\n';
    writeFile(dir, 'mixed.env', content);

    const findings = await scan(dir, DEFAULT_OPTIONS);

    const severities = findings.map((f) => f.severity);
    // critical (rank 3) should appear before medium (rank 1)
    const criticalIdx = severities.indexOf('critical');
    const mediumIdx = severities.indexOf('medium');
    if (criticalIdx !== -1 && mediumIdx !== -1) {
      expect(criticalIdx).toBeLessThan(mediumIdx);
    }
  });
});

// ── scan() — multiple matches on one line ─────────────────────────────────────

describe('scan() — multiple matches on one line', () => {
  it('emits separate findings for two secrets on the same line', async () => {
    const dir = makeTmpDir();
    // Two AWS access key IDs on the same line
    const content = 'key1=AKIAIOSFODNN7EXAMPLE key2=AKIAIOSFODNN7EXAMPLE\n';
    const filePath = writeFile(dir, 'two.env', content);

    const findings = await scan(filePath, DEFAULT_OPTIONS);

    const awsFindings = findings.filter((f) => f.ruleId === 'aws-access-key-id');
    expect(awsFindings.length).toBe(2);
  });
});
