import { describe, it, expect } from 'vitest';
import {
  isHmaEvidence,
  isHmaRationale,
  mapRawHmaFinding,
} from '../../src/commands/review.js';
import { generateReviewHtml } from '../../src/report/review-html.js';
import type { ReviewReport } from '../../src/commands/review.js';

// HMA Finding v2 schema landed in hackmyagent commit dc8d344
// (`src/types/finding-evidence.ts`). opena2a-cli is a wrapper consumer:
// it must pass `evidence`, `rationale`, `concept`, and `attackClass`
// through to the HTML report unchanged, falling back gracefully when
// older HMA builds emit the legacy v1 shape.

describe('isHmaEvidence', () => {
  it('accepts positive evidence', () => {
    expect(isHmaEvidence({ kind: 'positive', lines: [] })).toBe(true);
  });
  it('accepts absence-of-defense evidence', () => {
    expect(
      isHmaEvidence({ kind: 'absence', observed: { lines: [], summary: 's' }, expected: [] }),
    ).toBe(true);
  });
  it('accepts mixed evidence', () => {
    expect(
      isHmaEvidence({ kind: 'mixed', positive: { lines: [] }, absence: { observed: { lines: [], summary: 's' }, expected: [] } }),
    ).toBe(true);
  });
  it('rejects unknown discriminator', () => {
    expect(isHmaEvidence({ kind: 'unknown' })).toBe(false);
  });
  it('rejects non-object values', () => {
    expect(isHmaEvidence('positive')).toBe(false);
    expect(isHmaEvidence(42)).toBe(false);
    expect(isHmaEvidence(null)).toBe(false);
    expect(isHmaEvidence(undefined)).toBe(false);
  });
});

describe('isHmaRationale', () => {
  it('accepts non-empty plainEnglish', () => {
    expect(isHmaRationale({ plainEnglish: 'Detector matched a hardcoded AKIA prefix.' })).toBe(true);
  });
  it('rejects empty plainEnglish (falls back to legacy guidance render)', () => {
    expect(isHmaRationale({ plainEnglish: '' })).toBe(false);
  });
  it('rejects non-string plainEnglish', () => {
    expect(isHmaRationale({ plainEnglish: 42 })).toBe(false);
    expect(isHmaRationale({ plainEnglish: null })).toBe(false);
  });
  it('rejects null and primitives', () => {
    expect(isHmaRationale(null)).toBe(false);
    expect(isHmaRationale('plainEnglish')).toBe(false);
  });
});

describe('mapRawHmaFinding — Finding v2 propagation', () => {
  const v2Raw = {
    checkId: 'CRED-001',
    name: 'Hardcoded AWS access key',
    description: 'AKIA prefix detected in source.',
    category: 'credentials',
    severity: 'critical',
    passed: false,
    message: 'AKIAIOSFODNN7EXAMPLE on line 42',
    file: 'src/config.ts',
    line: 42,
    fixable: true,
    fix: 'opena2a protect',
    guidance: 'legacy guidance text',
    evidence: {
      kind: 'positive',
      lines: [{ n: 42, content: 'const KEY = "AKIA…"', why: 'Plaintext AWS key.' }],
    },
    rationale: { plainEnglish: 'AKIA prefix + 16-char body matches the AWS Access Key ID format.' },
    concept: 'secretless-vault',
    attackClass: 'data_extraction',
  };

  it('preserves all v2 fields when valid', () => {
    const out = mapRawHmaFinding(v2Raw);
    expect(out.evidence).toEqual(v2Raw.evidence);
    expect(out.rationale).toEqual(v2Raw.rationale);
    expect(out.concept).toBe('secretless-vault');
    expect(out.attackClass).toBe('data_extraction');
  });

  it('omits malformed evidence (unknown kind)', () => {
    const raw = { ...v2Raw, evidence: { kind: 'bogus' } };
    expect(mapRawHmaFinding(raw).evidence).toBeUndefined();
  });

  it('omits empty rationale (falls through to legacy guidance render)', () => {
    const raw = { ...v2Raw, rationale: { plainEnglish: '' } };
    expect(mapRawHmaFinding(raw).rationale).toBeUndefined();
  });

  it('omits non-string concept and attackClass', () => {
    const raw = { ...v2Raw, concept: 42, attackClass: { foo: 'bar' } };
    const out = mapRawHmaFinding(raw);
    expect(out.concept).toBeUndefined();
    expect(out.attackClass).toBeUndefined();
  });

  it('handles legacy v1 finding (no v2 fields) without throwing', () => {
    const v1Raw = {
      checkId: 'CRED-001',
      name: 'Hardcoded AWS access key',
      description: 'd',
      category: 'credentials',
      severity: 'critical',
      passed: false,
      message: 'm',
      file: 'src/config.ts',
      line: 42,
      fixable: true,
      fix: 'opena2a protect',
      guidance: 'legacy guidance',
    };
    const out = mapRawHmaFinding(v1Raw);
    expect(out.evidence).toBeUndefined();
    expect(out.rationale).toBeUndefined();
    expect(out.concept).toBeUndefined();
    expect(out.attackClass).toBeUndefined();
    expect(out.guidance).toBe('legacy guidance');
  });
});

// Build a minimal ReviewReport fixture sufficient for the HTML renderer.
// Only the fields the renderer touches need realistic shapes.
function buildReport(topFindings: ReviewReport['hmaData']['topFindings']): ReviewReport {
  return {
    timestamp: '2026-04-29T00:00:00Z',
    targetDir: '/tmp/x',
    projectType: 'node',
    durationMs: 100,
    phases: [],
    findings: [],
    actionItems: [],
    compositeScore: 65,
    recoverySummary: { totalRecoverable: 0, opportunities: [], potentialScore: 100 },
    initData: {
      trustScore: 80,
      postureScore: 75,
      riskLevel: 'LOW' as never,
      activeTools: 1,
      totalTools: 5,
      hygieneChecks: [],
      advisoryCount: 0,
      projectName: 't',
      projectType: 'node',
      projectVersion: '1.0',
      matchedPackages: [],
    },
    credentialData: {
      totalFindings: 0,
      bySeverity: {},
      matches: [],
      driftFindings: [],
    } as never,
    shieldData: {
      eventCount: 0,
      classifiedFindings: [],
      arpStats: {
        totalEvents: 0,
        anomalies: 0,
        violations: 0,
        threats: 0,
        processEvents: 0,
        networkEvents: 0,
        filesystemEvents: 0,
        enforcements: 0,
      } as never,
      postureScore: 75,
      policyLoaded: false,
      policyMode: null,
      integrityStatus: 'healthy',
    },
    hmaData: {
      available: true,
      score: 60,
      maxScore: 100,
      totalChecks: 100,
      passed: 70,
      failed: 30,
      bySeverity: { critical: 1 },
      byCategory: { credentials: 1 },
      topFindings,
      allFailedFindings: topFindings,
    },
    detectData: {
      governanceScore: 100,
      agents: [],
      mcpServers: [],
      aiConfigs: [],
      findings: [],
      recoverablePoints: 0,
    } as never,
    guardData: {
      filesMonitored: 0,
      tamperedFiles: [],
      signatureStatus: 'unsigned',
    } as never,
  } as ReviewReport;
}

describe('generateReviewHtml — Finding v2 wiring (renderer source assertions)', () => {
  // The HMA tab content is rendered client-side via `renderHma()` inside the
  // bundled JS. Server-side we can only verify that the renderer source
  // contains the expected v2 helpers and field references — the actual visual
  // output is covered by the new-user walkthrough.

  it('embeds the whyAndEvidence helper definition', () => {
    const html = generateReviewHtml(buildReport([]));
    expect(html.includes('function whyAndEvidence(f)')).toBe(true);
  });

  it('the renderer prefers rationale.plainEnglish over guidance', () => {
    const html = generateReviewHtml(buildReport([]));
    // Helper logic: `(f.rationale&&f.rationale.plainEnglish)||f.guidance||legacyRiskKb[f.checkId]`
    expect(html).toContain('f.rationale.plainEnglish');
    expect(html).toContain('legacyRiskKb[f.checkId]');
  });

  it('the renderer renders positive evidence lines when present', () => {
    const html = generateReviewHtml(buildReport([]));
    expect(html).toContain("f.evidence.kind==='positive'");
    expect(html).toContain('f.evidence.lines');
  });

  it('the renderer renders absence-of-defense evidence when present', () => {
    const html = generateReviewHtml(buildReport([]));
    expect(html).toContain("f.evidence.kind==='absence'");
    expect(html).toContain('f.evidence.observed');
  });

  it('the renderer surfaces attackClass next to category', () => {
    const html = generateReviewHtml(buildReport([]));
    expect(html).toContain('f.attackClass');
  });

  it('drops the legacy inline guidance ternary (replaced by whyAndEvidence)', () => {
    const html = generateReviewHtml(buildReport([]));
    expect(html).not.toContain("((f.guidance||legacyRiskKb[f.checkId])?'<div");
  });

  it('embeds Finding v2 fields in the report data block', () => {
    const finding = mapRawHmaFinding({
      checkId: 'SKILL-022',
      name: 'Environment Variable Exfiltration Risk',
      description: 'd',
      category: 'skill',
      severity: 'high',
      passed: false,
      message: 'm',
      fixable: true,
      fix: 'hackmyagent check ./skill',
      guidance: '',
      evidence: { kind: 'positive', lines: [{ n: 12, content: 'cat $HOME/.aws/credentials', why: 'reads AWS creds' }] },
      rationale: { plainEnglish: 'Skill reads AWS credentials path.' },
      attackClass: 'exfiltration_pattern',
    });
    const html = generateReviewHtml(buildReport([finding]));
    // The report data is embedded as JSON; assert the v2 fields survived
    // serialization end-to-end.
    expect(html).toContain('exfiltration_pattern');
    expect(html).toContain('Skill reads AWS credentials path.');
    expect(html).toContain('cat $HOME/.aws/credentials');
  });
});
