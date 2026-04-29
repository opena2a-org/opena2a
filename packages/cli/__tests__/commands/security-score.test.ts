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
    expect(grade).toBe('strong');
  });

  it('applies diminishing returns for critical findings', () => {
    const { score: score1 } = calculateSecurityScore({ critical: 1 }, cleanChecks);
    const { score: score2 } = calculateSecurityScore({ critical: 2 }, cleanChecks);
    const { score: score3 } = calculateSecurityScore({ critical: 5 }, cleanChecks);

    // First critical = -20, each subsequent = -8.
    // Per #116: security-config bonus is suppressed when CRITICAL
    // findings exist (a signed signatures.json doesn't compensate).
    // Pre-#116 these returned 85 / 77 / 61 with the +5 bonus.
    expect(score1).toBe(100 - 20); // 80
    expect(score2).toBe(100 - 20 - 8); // 72
    // 5 critical: 20 + 4*8 = 52, but cap additional at 24, so 20+24=44
    expect(score3).toBe(100 - 44); // 56
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
    expect(calculateSecurityScore({}, cleanChecks).grade).toBe('strong');
    expect(calculateSecurityScore({ critical: 1 }, cleanChecks).grade).toBe('good');
    expect(calculateSecurityScore({ critical: 2 }, cleanChecks).grade).toBe('moderate');
    expect(calculateSecurityScore({ critical: 3, high: 2 }, cleanChecks).grade).toBe('needs-attention');
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
        { label: 'Lock file', status: 'warn' as const, detail: 'none found' },
        { label: 'Security config', status: 'info' as const, detail: 'none' },
      ],
    );
    expect(breakdown.credentials.detail).toContain('critical');
    expect(breakdown.credentials.detail).toContain('high');
    expect(breakdown.environment.detail).toContain('.env unprotected');
    expect(breakdown.configuration.detail).toContain('no lock file');
  });

  it('missing .gitignore does not deduct (HMA covers this at LOW, 0.8.24)', () => {
    const withGitignore = [
      { label: 'Credential scan', status: 'pass' as const, detail: 'no findings' },
      { label: '.gitignore', status: 'pass' as const, detail: 'present' },
      { label: '.env protection', status: 'pass' as const, detail: 'in .gitignore' },
      { label: 'Lock file', status: 'pass' as const, detail: 'package-lock.json' },
      { label: 'Security config', status: 'pass' as const, detail: '.opena2a.yaml' },
    ];
    const withoutGitignore = [
      ...withGitignore.filter(c => c.label !== '.gitignore' && c.label !== '.env protection'),
      { label: '.gitignore', status: 'warn' as const, detail: 'missing' },
      { label: '.env protection', status: 'pass' as const, detail: 'in .gitignore' },
    ];
    const a = calculateSecurityScore({}, withGitignore);
    const b = calculateSecurityScore({}, withoutGitignore);
    expect(b.breakdown.configuration.deduction).toBe(a.breakdown.configuration.deduction);
    expect(b.breakdown.configuration.detail).not.toContain('.gitignore');
  });

  it('includes MCP high-risk tools in environment deduction (-3 per server, post-#116)', () => {
    const checksWithMcp = [
      ...cleanChecks,
      { label: 'MCP high-risk tools', status: 'warn' as const, detail: '1 server with filesystem access' },
    ];
    const { breakdown } = calculateSecurityScore({}, checksWithMcp);
    // Pre-#116 was a flat -5 regardless of server count. Post-#116 the
    // per-server scale is -3 with a sub-cap of -15.
    expect(breakdown.environment.deduction).toBeGreaterThanOrEqual(3);
    expect(breakdown.environment.detail).toContain('MCP high-risk tools');
  });

  it('scales MCP-tools deduction by server count across multiple configs (#116)', () => {
    const checksMultiMcp = [
      ...cleanChecks,
      { label: 'MCP high-risk tools', status: 'warn' as const, detail: '4 servers with filesystem/shell access in mcp.json' },
      { label: 'MCP high-risk tools', status: 'warn' as const, detail: '1 server with filesystem/shell access in .cursor/mcp.json' },
    ];
    const { breakdown } = calculateSecurityScore({}, checksMultiMcp);
    // 5 servers × 3 = 15 (sub-cap of 15)
    expect(breakdown.environment.deduction).toBeGreaterThanOrEqual(15);
    expect(breakdown.environment.detail).toContain('5 server');
  });

  it('includes MCP credentials in environment deduction (+5)', () => {
    const checksWithMcpCred = [
      ...cleanChecks,
      { label: 'MCP credentials', status: 'warn' as const, detail: 'hardcoded credentials in mcp.json' },
    ];
    const { breakdown } = calculateSecurityScore({}, checksWithMcpCred);
    expect(breakdown.environment.deduction).toBeGreaterThanOrEqual(5);
    expect(breakdown.environment.detail).toContain('MCP credentials');
  });

  it('includes AI config exposure in environment deduction (+3)', () => {
    const checksWithAiConfig = [
      ...cleanChecks,
      { label: 'AI config exposure', status: 'warn' as const, detail: '2 AI config files not excluded' },
    ];
    const { breakdown } = calculateSecurityScore({}, checksWithAiConfig);
    expect(breakdown.environment.deduction).toBeGreaterThanOrEqual(3);
    expect(breakdown.environment.detail).toContain('AI config exposed');
  });

  it('caps environment at 30 even with MCP + AI + LLM + env + skill + soul issues (#116)', () => {
    const heavyChecks = [
      { label: 'Credential scan', status: 'pass' as const, detail: 'no findings' },
      { label: '.gitignore', status: 'pass' as const, detail: 'present' },
      { label: '.env protection', status: 'warn' as const, detail: 'NOT in .gitignore' },
      { label: 'Lock file', status: 'pass' as const, detail: 'package-lock.json' },
      { label: 'Security config', status: 'pass' as const, detail: '.opena2a.yaml' },
      { label: 'LLM server exposure', status: 'warn' as const, detail: 'Ollama on :11434' },
      { label: 'MCP high-risk tools', status: 'warn' as const, detail: '5 servers' },
      { label: 'MCP credentials', status: 'warn' as const, detail: 'hardcoded' },
      { label: 'AI config exposure', status: 'warn' as const, detail: '3 files' },
      { label: 'Skill files', status: 'warn' as const, detail: '4 unsigned' },
      { label: 'Soul file', status: 'warn' as const, detail: 'override patterns' },
    ];
    const { breakdown } = calculateSecurityScore({}, heavyChecks);
    expect(breakdown.environment.deduction).toBeLessThanOrEqual(30);
  });

  it('suppresses security-config bonus when CRITICAL/HIGH findings exist (#116)', () => {
    const cleanChecks = [
      { label: 'Credential scan', status: 'pass' as const, detail: 'no findings' },
      { label: '.gitignore', status: 'pass' as const, detail: 'present' },
      { label: '.env protection', status: 'pass' as const, detail: 'in .gitignore' },
      { label: 'Lock file', status: 'pass' as const, detail: 'package-lock.json' },
      { label: 'Security config', status: 'pass' as const, detail: '.opena2a/guard/signatures.json' },
    ];
    const { score: scoreWithBonus } = calculateSecurityScore({}, cleanChecks);
    expect(scoreWithBonus).toBe(100);

    // With a CRITICAL credential, the +5 bonus must NOT apply.
    const { score: scoreWithCrit } = calculateSecurityScore({ critical: 1 }, cleanChecks);
    expect(scoreWithCrit).toBe(80); // 100 - 20, no bonus
  });
});
