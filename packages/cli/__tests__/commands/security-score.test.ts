import { describe, it, expect } from 'vitest';
import { calculateSecurityScore } from '../../src/commands/init.js';

describe('calculateSecurityScore', () => {
  const cleanChecks = [
    { label: 'Credential scan', status: 'pass' as const, detail: 'no findings' },
    { label: '.gitignore', status: 'pass' as const, detail: 'present' },
    { label: '.env protection', status: 'pass' as const, detail: 'in .gitignore' },
    { label: 'Lock file', status: 'pass' as const, detail: 'package-lock.json' },
    { label: 'Security config', status: 'pass' as const, detail: '.opena2a.yaml' },
  ];

  it('returns 100 + bonus for clean project with security config', () => {
    const { score, grade } = calculateSecurityScore({}, cleanChecks);
    expect(score).toBe(100);
    expect(grade).toBe('A');
  });

  it('applies diminishing returns for critical findings', () => {
    const { score: score1 } = calculateSecurityScore({ critical: 1 }, cleanChecks);
    const { score: score2 } = calculateSecurityScore({ critical: 2 }, cleanChecks);
    const { score: score3 } = calculateSecurityScore({ critical: 5 }, cleanChecks);

    // First critical = -20, each subsequent = -8
    expect(score1).toBe(100 - 20 + 5); // 85 (with +5 config bonus)
    expect(score2).toBe(100 - 20 - 8 + 5); // 77
    // 5 critical: 20 + 4*8 = 52, but cap additional at 24, so 20+24=44
    expect(score3).toBe(100 - 44 + 5); // 61
  });

  it('caps credential deduction at 60', () => {
    // Many findings across all severities
    const { score, breakdown } = calculateSecurityScore(
      { critical: 10, high: 10, medium: 20, low: 10 },
      cleanChecks,
    );
    expect(breakdown.credentials.deduction).toBeLessThanOrEqual(60);
    expect(score).toBeGreaterThanOrEqual(40); // 100 - 60 + 5 config bonus = 45
  });

  it('caps environment deduction at 25', () => {
    const checksWithEnvIssues = [
      ...cleanChecks.filter(c => c.label !== '.env protection' && c.label !== 'LLM server exposure'),
      { label: '.env protection', status: 'warn' as const, detail: 'NOT in .gitignore' },
      { label: 'LLM server exposure', status: 'warn' as const, detail: 'Ollama on :11434' },
    ];
    const { breakdown } = calculateSecurityScore({}, checksWithEnvIssues);
    expect(breakdown.environment.deduction).toBeLessThanOrEqual(25);
  });

  it('caps configuration deduction at 15', () => {
    const poorChecks = [
      { label: 'Credential scan', status: 'pass' as const, detail: 'no findings' },
      { label: '.gitignore', status: 'warn' as const, detail: 'missing' },
      { label: '.env protection', status: 'pass' as const, detail: 'in .gitignore' },
      { label: 'Lock file', status: 'warn' as const, detail: 'none found' },
      { label: 'Security config', status: 'info' as const, detail: 'none' },
    ];
    const { breakdown } = calculateSecurityScore({}, poorChecks);
    expect(breakdown.configuration.deduction).toBeLessThanOrEqual(15);
  });

  it('assigns correct grades', () => {
    expect(calculateSecurityScore({}, cleanChecks).grade).toBe('A');
    expect(calculateSecurityScore({ critical: 1 }, cleanChecks).grade).toBe('B');
    expect(calculateSecurityScore({ critical: 2 }, cleanChecks).grade).toBe('C');
    expect(calculateSecurityScore({ critical: 3, high: 2 }, cleanChecks).grade).toBe('F');
  });

  it('includes HMA findings in environment deduction', () => {
    const { breakdown: without } = calculateSecurityScore({}, cleanChecks);
    const { breakdown: with_ } = calculateSecurityScore({}, cleanChecks, { high: 2 });
    expect(with_.environment.deduction).toBeGreaterThan(without.environment.deduction);
  });

  it('score never goes below 0 or above 100', () => {
    const { score: low } = calculateSecurityScore(
      { critical: 10, high: 10, medium: 20 },
      [
        { label: '.gitignore', status: 'warn' as const, detail: 'missing' },
        { label: '.env protection', status: 'warn' as const, detail: 'NOT in .gitignore' },
        { label: 'Lock file', status: 'warn' as const, detail: 'none found' },
        { label: 'Security config', status: 'info' as const, detail: 'none' },
        { label: 'LLM server exposure', status: 'warn' as const, detail: 'Ollama' },
      ],
      { critical: 5 },
    );
    expect(low).toBeGreaterThanOrEqual(0);
    expect(low).toBeLessThanOrEqual(100);
  });

  it('returns breakdown with detail strings', () => {
    const { breakdown } = calculateSecurityScore(
      { critical: 2, high: 1 },
      [
        { label: '.gitignore', status: 'warn' as const, detail: 'missing' },
        { label: '.env protection', status: 'warn' as const, detail: 'NOT in .gitignore' },
        { label: 'Lock file', status: 'pass' as const, detail: 'package-lock.json' },
        { label: 'Security config', status: 'info' as const, detail: 'none' },
      ],
    );
    expect(breakdown.credentials.detail).toContain('critical');
    expect(breakdown.credentials.detail).toContain('high');
    expect(breakdown.environment.detail).toContain('.env unprotected');
    expect(breakdown.configuration.detail).toContain('no .gitignore');
  });
});
