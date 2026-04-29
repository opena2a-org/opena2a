import { describe, it, expect } from 'vitest';
import {
  calculateSecurityScore,
  scoreToRiskLevel,
  formatCredCount,
  type HygieneCheck,
} from '../../src/util/scoring.js';

describe('calculateSecurityScore (shared module)', () => {
  const cleanChecks: HygieneCheck[] = [
    { label: 'Credential scan', status: 'pass', detail: 'no findings' },
    { label: '.gitignore', status: 'pass', detail: 'present' },
    { label: '.env protection', status: 'pass', detail: 'in .gitignore' },
    { label: 'Lock file', status: 'pass', detail: 'package-lock.json' },
    { label: 'Security config', status: 'pass', detail: '.opena2a.yaml' },
  ];

  it('returns 100 for clean project with security config', () => {
    const { score, grade } = calculateSecurityScore({}, cleanChecks);
    expect(score).toBe(100);
    expect(grade).toBe('strong');
  });

  it('applies diminishing returns for critical findings', () => {
    const { score: s1 } = calculateSecurityScore({ critical: 1 }, cleanChecks);
    const { score: s2 } = calculateSecurityScore({ critical: 2 }, cleanChecks);
    // Per #116: security-config bonus is suppressed when CRITICAL/HIGH
    // findings exist (a signed signatures.json doesn't compensate for a
    // private key in source). Pre-#116 these returned 85 and 77 with
    // a +5 bonus included.
    expect(s1).toBe(80); // 100 - 20
    expect(s2).toBe(72); // 100 - 20 - 8
  });

  it('caps credential deduction at 60', () => {
    const { breakdown } = calculateSecurityScore(
      { critical: 10, high: 10, medium: 20, low: 10 },
      cleanChecks,
    );
    expect(breakdown.credentials.deduction).toBeLessThanOrEqual(60);
  });

  it('caps environment deduction at 30 (was 25 pre-#116)', () => {
    const heavy: HygieneCheck[] = [
      ...cleanChecks.filter(c => c.label !== '.env protection'),
      { label: '.env protection', status: 'warn', detail: 'NOT in .gitignore' },
      { label: 'LLM server exposure', status: 'warn', detail: 'Ollama on :11434' },
      { label: 'MCP high-risk tools', status: 'warn', detail: '1 server' },
      { label: 'MCP credentials', status: 'warn', detail: 'hardcoded' },
      { label: 'AI config exposure', status: 'warn', detail: '3 files' },
      { label: 'Skill files', status: 'warn', detail: '5 unsigned skill files' },
      { label: 'Soul file', status: 'warn', detail: 'override patterns' },
    ];
    const { breakdown } = calculateSecurityScore({}, heavy);
    expect(breakdown.environment.deduction).toBeLessThanOrEqual(30);
  });

  it('score never goes below 0 or above 100', () => {
    const { score } = calculateSecurityScore(
      { critical: 10, high: 10, medium: 20 },
      [
        { label: '.gitignore', status: 'warn', detail: 'missing' },
        { label: '.env protection', status: 'warn', detail: 'NOT in .gitignore' },
        { label: 'Lock file', status: 'warn', detail: 'none found' },
        { label: 'Security config', status: 'info', detail: 'none' },
        { label: 'LLM server exposure', status: 'warn', detail: 'Ollama' },
      ],
      { critical: 5 },
    );
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });
});

describe('scoreToRiskLevel', () => {
  it('maps score ranges to risk levels', () => {
    expect(scoreToRiskLevel(95)).toBe('SECURE');
    expect(scoreToRiskLevel(75)).toBe('LOW');
    expect(scoreToRiskLevel(55)).toBe('MEDIUM');
    expect(scoreToRiskLevel(35)).toBe('HIGH');
    expect(scoreToRiskLevel(10)).toBe('CRITICAL');
  });
});

describe('formatCredCount', () => {
  it('formats credential counts', () => {
    expect(formatCredCount(1, 2, 0, 0)).toBe('1 critical, 2 high');
    expect(formatCredCount(0, 0, 0, 0)).toBe('none');
    expect(formatCredCount(0, 0, 3, 1)).toBe('3 medium, 1 low');
  });
});
