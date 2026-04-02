import { describe, it, expect } from 'vitest';

// lib.ts is the public library entry point. Verify that everything it should
// re-export is actually exported and has the expected shape.
import * as lib from './lib.js';

describe('lib.ts re-exports', () => {
  it('exports scan as a function', () => {
    expect(typeof lib.scan).toBe('function');
  });

  it('exports RULES as a non-empty array', () => {
    expect(Array.isArray(lib.RULES)).toBe(true);
    expect(lib.RULES.length).toBeGreaterThan(0);
  });

  it('exports SEVERITY_RANK as an object with the four levels', () => {
    expect(typeof lib.SEVERITY_RANK).toBe('object');
    expect(lib.SEVERITY_RANK).toHaveProperty('critical');
    expect(lib.SEVERITY_RANK).toHaveProperty('high');
    expect(lib.SEVERITY_RANK).toHaveProperty('medium');
    expect(lib.SEVERITY_RANK).toHaveProperty('low');
  });

  it('RULES items exported from lib have all required fields', () => {
    for (const rule of lib.RULES) {
      expect(rule.id).toBeTruthy();
      expect(rule.name).toBeTruthy();
      expect(rule.pattern).toBeInstanceOf(RegExp);
      expect(rule.severity).toMatch(/^(critical|high|medium|low)$/);
      expect(rule.note).toBeTruthy();
    }
  });

  it('SEVERITY_RANK values are numbers in ascending order low → critical', () => {
    const { low, medium, high, critical } = lib.SEVERITY_RANK;
    expect(critical).toBeGreaterThan(high);
    expect(high).toBeGreaterThan(medium);
    expect(medium).toBeGreaterThan(low);
    expect(low).toBeGreaterThanOrEqual(0);
  });
});
