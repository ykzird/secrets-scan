import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Finding } from './scanner.js';
import { printJson, printSarif, printText } from './output.js';
import { RULES } from './rules.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'aws-access-key-id',
    ruleName: 'AWS Access Key ID',
    severity: 'critical',
    file: '/project/src/config.ts',
    line: 42,
    content: 'AWS_ACCESS_KEY_ID=AKIA***',
    match: 'AKIAIOSFODNN7EXAMPLE',
    note: 'AWS access key ID — pair with a secret key to authenticate API calls',
    ...overrides,
  };
}

// Capture console output without actually printing during tests
function captureConsoleLog(fn: () => void): string {
  const output: string[] = [];
  const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    output.push(args.map(String).join(' '));
  });
  try {
    fn();
  } finally {
    spy.mockRestore();
  }
  return output.join('\n');
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ── printJson ─────────────────────────────────────────────────────────────────

describe('printJson()', () => {
  it('outputs valid JSON', () => {
    const findings = [makeFinding()];
    let output = '';
    vi.spyOn(console, 'log').mockImplementation((str: string) => { output = str; });

    printJson(findings);

    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('JSON contains a summary field with severity counts', () => {
    const findings = [makeFinding({ severity: 'critical' }), makeFinding({ severity: 'high' })];
    let parsed: ReturnType<typeof JSON.parse> | null = null;
    vi.spyOn(console, 'log').mockImplementation((str: string) => { parsed = JSON.parse(str); });

    printJson(findings);

    expect(parsed).not.toBeNull();
    expect(parsed!.summary).toBeDefined();
    expect(parsed!.summary.critical).toBe(1);
    expect(parsed!.summary.high).toBe(1);
    expect(parsed!.summary.medium).toBe(0);
    expect(parsed!.summary.low).toBe(0);
  });

  it('JSON contains a findings array with all fields', () => {
    const finding = makeFinding();
    let parsed: ReturnType<typeof JSON.parse> | null = null;
    vi.spyOn(console, 'log').mockImplementation((str: string) => { parsed = JSON.parse(str); });

    printJson([finding]);

    expect(parsed!.findings).toBeInstanceOf(Array);
    expect(parsed!.findings).toHaveLength(1);

    const f = parsed!.findings[0];
    expect(f.ruleId).toBe(finding.ruleId);
    expect(f.ruleName).toBe(finding.ruleName);
    expect(f.severity).toBe(finding.severity);
    expect(f.file).toBe(finding.file);
    expect(f.line).toBe(finding.line);
    expect(f.content).toBe(finding.content);
    expect(f.match).toBe(finding.match);
    expect(f.note).toBe(finding.note);
  });

  it('handles zero findings gracefully', () => {
    let parsed: ReturnType<typeof JSON.parse> | null = null;
    vi.spyOn(console, 'log').mockImplementation((str: string) => { parsed = JSON.parse(str); });

    printJson([]);

    expect(parsed!.findings).toHaveLength(0);
    expect(parsed!.summary.critical).toBe(0);
    expect(parsed!.summary.high).toBe(0);
  });
});

// ── printText ─────────────────────────────────────────────────────────────────

describe('printText()', () => {
  it('prints "No secrets found" for empty findings', () => {
    const output = captureConsoleLog(() => printText([], '/some/path'));
    expect(output).toContain('No secrets found');
  });

  it('includes the file path in the output', () => {
    const findings = [makeFinding()];
    const output = captureConsoleLog(() => printText(findings, '/project'));
    expect(output).toContain('/project/src/config.ts');
  });

  it('includes the line number in the output', () => {
    const findings = [makeFinding({ line: 42 })];
    const output = captureConsoleLog(() => printText(findings, '/project'));
    expect(output).toContain('42');
  });

  it('includes the rule name in the output', () => {
    const findings = [makeFinding()];
    const output = captureConsoleLog(() => printText(findings, '/project'));
    expect(output).toContain('AWS Access Key ID');
  });

  it('includes the content (possibly redacted) in the output', () => {
    const findings = [makeFinding({ content: 'AWS_ACCESS_KEY_ID=AKIA***' })];
    const output = captureConsoleLog(() => printText(findings, '/project'));
    expect(output).toContain('AWS_ACCESS_KEY_ID=AKIA***');
  });

  it('includes the severity badge in the output', () => {
    const findings = [makeFinding({ severity: 'critical' })];
    const output = captureConsoleLog(() => printText(findings, '/project'));
    // severity badge text is uppercased
    expect(output.toUpperCase()).toContain('CRITICAL');
  });

  it('includes a summary line with total count', () => {
    const findings = [makeFinding(), makeFinding()];
    const output = captureConsoleLog(() => printText(findings, '/project'));
    expect(output).toContain('2');
  });

  it('groups findings by file — each file path appears once as header', () => {
    const findings = [
      makeFinding({ file: '/project/fileA.ts', line: 1 }),
      makeFinding({ file: '/project/fileA.ts', line: 5 }),
      makeFinding({ file: '/project/fileB.ts', line: 3 }),
    ];
    const output = captureConsoleLog(() => printText(findings, '/project'));

    // fileA.ts should appear as a header exactly once (not duplicated per finding)
    const fileACount = (output.match(/fileA\.ts/g) || []).length;
    expect(fileACount).toBe(1);
    expect(output).toContain('fileB.ts');
  });

  it('includes the note in the output', () => {
    const findings = [makeFinding()];
    const output = captureConsoleLog(() => printText(findings, '/project'));
    expect(output).toContain('pair with a secret key');
  });
});

// ── printSarif ────────────────────────────────────────────────────────────────

describe('printSarif()', () => {
  function getSarifOutput(findings: Finding[], targetPath = '/project'): ReturnType<typeof JSON.parse> {
    let parsed: ReturnType<typeof JSON.parse> | null = null;
    vi.spyOn(console, 'log').mockImplementation((str: string) => { parsed = JSON.parse(str); });
    printSarif(findings, targetPath);
    return parsed!;
  }

  it('outputs valid JSON', () => {
    let output = '';
    vi.spyOn(console, 'log').mockImplementation((str: string) => { output = str; });
    printSarif([makeFinding()], '/project');
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('has a version field of "2.1.0"', () => {
    const sarif = getSarifOutput([makeFinding()]);
    expect(sarif.version).toBe('2.1.0');
  });

  it('has a $schema field pointing to the SARIF schema', () => {
    const sarif = getSarifOutput([makeFinding()]);
    expect(sarif.$schema).toContain('sarif');
  });

  it('has a runs array with at least one entry', () => {
    const sarif = getSarifOutput([makeFinding()]);
    expect(sarif.runs).toBeInstanceOf(Array);
    expect(sarif.runs.length).toBeGreaterThan(0);
  });

  it('run[0].tool.driver.name is "secrets-scan"', () => {
    const sarif = getSarifOutput([makeFinding()]);
    expect(sarif.runs[0].tool.driver.name).toBe('secrets-scan');
  });

  it('run[0].tool.driver.rules contains all RULES', () => {
    const sarif = getSarifOutput([makeFinding()]);
    const ruleIds = sarif.runs[0].tool.driver.rules.map((r: { id: string }) => r.id);
    for (const rule of RULES) {
      expect(ruleIds).toContain(rule.id);
    }
  });

  it('results array has one entry per finding', () => {
    const findings = [makeFinding(), makeFinding({ ruleId: 'github-pat-classic', line: 10 })];
    const sarif = getSarifOutput(findings);
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it('each result has ruleId, level, message, and locations', () => {
    const sarif = getSarifOutput([makeFinding()]);
    const result = sarif.runs[0].results[0];
    expect(result.ruleId).toBeDefined();
    expect(result.level).toBeDefined();
    expect(result.message?.text).toBeDefined();
    expect(result.locations).toBeInstanceOf(Array);
    expect(result.locations.length).toBeGreaterThan(0);
  });

  it('critical severity maps to level "error"', () => {
    const sarif = getSarifOutput([makeFinding({ severity: 'critical' })]);
    expect(sarif.runs[0].results[0].level).toBe('error');
  });

  it('high severity maps to level "error"', () => {
    const sarif = getSarifOutput([makeFinding({ severity: 'high' })]);
    expect(sarif.runs[0].results[0].level).toBe('error');
  });

  it('medium severity maps to level "warning"', () => {
    const sarif = getSarifOutput([makeFinding({ severity: 'medium' })]);
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });

  it('low severity maps to level "note"', () => {
    const sarif = getSarifOutput([makeFinding({ severity: 'low' })]);
    expect(sarif.runs[0].results[0].level).toBe('note');
  });

  it('location startLine matches the finding line number', () => {
    const sarif = getSarifOutput([makeFinding({ line: 42 })]);
    const region = sarif.runs[0].results[0].locations[0].physicalLocation.region;
    expect(region.startLine).toBe(42);
  });

  it('handles zero findings — results array is empty', () => {
    const sarif = getSarifOutput([]);
    expect(sarif.runs[0].results).toHaveLength(0);
  });

  it('originalUriBaseIds SRCROOT contains the target path', () => {
    const sarif = getSarifOutput([makeFinding()], '/my/project');
    const srcRoot = sarif.runs[0].originalUriBaseIds?.SRCROOT?.uri;
    expect(srcRoot).toContain('my/project');
  });
});
