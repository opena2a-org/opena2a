import { describe, it, expect } from 'vitest';
import {
  deriveHmaCounts, emptyHmaData, formatFindingCounts, hmaChecksRun, hmaSemanticArtifacts, type HmaPhaseData,
} from '../../src/commands/review.js';

// Regression guard for the 2026-04-29 audit finding (B3):
// `opena2a review` HMA tab displayed "60 Total Checks / 60 Failed / 0 Passed"
// because the count derivation read `parsed.findings` (failed-only) for both
// totalChecks and passed. The fix reads `parsed.allFindings` when present.

describe('deriveHmaCounts', () => {
  it('uses parsed.allFindings when present (modern HMA build)', () => {
    const parsed = {
      allFindings: [
        { checkId: 'A', passed: true },
        { checkId: 'B', passed: true },
        { checkId: 'C', passed: false },
        { checkId: 'D', passed: false },
      ],
    } as unknown as Record<string, unknown>;
    expect(deriveHmaCounts(parsed, 2)).toEqual({ totalChecks: 4, passed: 2 });
  });

  it('falls back to failed count when allFindings is missing (legacy HMA)', () => {
    const parsed = { findings: [{ passed: false }] } as unknown as Record<string, unknown>;
    expect(deriveHmaCounts(parsed, 1)).toEqual({ totalChecks: 1, passed: 0 });
  });

  it('falls back when allFindings is not an array', () => {
    const parsed = { allFindings: 'oops' } as unknown as Record<string, unknown>;
    expect(deriveHmaCounts(parsed, 5)).toEqual({ totalChecks: 5, passed: 0 });
  });

  it('treats only strict-true passed as passed (defensive)', () => {
    const parsed = {
      allFindings: [
        { passed: true },
        { passed: 1 },        // truthy but not === true
        { passed: 'yes' },    // truthy but not === true
        { passed: false },
      ],
    } as unknown as Record<string, unknown>;
    expect(deriveHmaCounts(parsed, 1)).toEqual({ totalChecks: 2, passed: 1 });
  });

  it('Passed and Failed add up to Total when allFindings carries failures findings left out (#500)', () => {
    // HMA's allFindings keeps failed records its findings list drops (the
    // noise floor, suppressions). The tab's Failed is the findings list, so a
    // Total read from allFindings left the parts short of it.
    const parsed = {
      allFindings: [
        { checkId: 'A', passed: true },
        { checkId: 'B', passed: true },
        { checkId: 'C', passed: false },
        { checkId: 'D', passed: false },
        { checkId: 'E', passed: false },
      ],
    } as unknown as Record<string, unknown>;
    const failed = 1;
    const { totalChecks, passed } = deriveHmaCounts(parsed, failed);
    expect(passed + failed).toBe(totalChecks);
    expect({ totalChecks, passed }).toEqual({ totalChecks: 3, passed: 2 });
  });

  it('reproduces the audit scenario: HMA returns 60 failures, 44 passes -> 104/44/60 not 60/0/60', () => {
    // Mirrors the exact bug surface: failed-only `findings` array would make
    // the renderer show 60/60/0; the new derivation reflects what HMA actually ran.
    const allFindings = [
      ...Array.from({ length: 44 }, (_, i) => ({ checkId: `P${i}`, passed: true })),
      ...Array.from({ length: 60 }, (_, i) => ({ checkId: `F${i}`, passed: false })),
    ];
    const parsed = { allFindings } as unknown as Record<string, unknown>;
    expect(deriveHmaCounts(parsed, 60)).toEqual({ totalChecks: 104, passed: 44 });
  });

  it('empty allFindings yields totalChecks=0, passed=0', () => {
    expect(deriveHmaCounts({ allFindings: [] }, 0)).toEqual({ totalChecks: 0, passed: 0 });
  });
});

describe('formatFindingCounts (#500)', () => {
  it('lists every severity, so the parts add up to the total', () => {
    const list = ['critical', 'high', 'high', 'medium', 'low', 'low', 'low'].map(severity => ({ severity }));
    expect(formatFindingCounts(list)).toBe('7 findings (1 critical, 2 high, 1 medium, 3 low)');
  });

  it('names a severity outside the four instead of dropping it', () => {
    const list = ['high', 'info', 'info'].map(severity => ({ severity }));
    expect(formatFindingCounts(list)).toBe('3 findings (0 critical, 1 high, 0 medium, 0 low, 2 info)');
  });

  it('keeps control characters of a reported severity off the terminal', () => {
    expect(formatFindingCounts([{ severity: 'in\x1b[2Jfo' }])).toBe('1 findings (0 critical, 0 high, 0 medium, 0 low, 1 in[2Jfo)');
  });

  it('reads zero findings as zero of each', () => {
    expect(formatFindingCounts([])).toBe('0 findings (0 critical, 0 high, 0 medium, 0 low)');
  });
});

describe('Checks line counts from the engine run (#500)', () => {
  it('reads the semantic count HMA reports, as scan prints it', () => {
    expect(hmaSemanticArtifacts({ coverage: { semanticFamilyCoverage: { artifactsCompiled: 12 } } })).toBe(12);
  });

  it('reads 0 when the report carries no semantic count or a malformed one', () => {
    expect(hmaSemanticArtifacts({})).toBe(0);
    expect(hmaSemanticArtifacts({ coverage: null })).toBe(0);
    expect(hmaSemanticArtifacts({ coverage: { semanticFamilyCoverage: { artifactsCompiled: '12' } } })).toBe(0);
    expect(hmaSemanticArtifacts({ coverage: { semanticFamilyCoverage: { artifactsCompiled: -1 } } })).toBe(0);
  });

  it('uses the run\'s counts when HMA ran, and zero when it produced no result', () => {
    const ran = { ...emptyHmaData({ status: 'ran', reason: null, version: '0.30.0', durationMs: 1 }),
      available: true, staticChecks: 310, semanticArtifacts: 4 } as HmaPhaseData;
    expect(hmaChecksRun(ran)).toEqual({ staticCount: 310, semanticCount: 4 });
    const skipped = emptyHmaData({ status: 'skipped', reason: '--skip-hma', version: null, durationMs: 0 });
    expect(hmaChecksRun(skipped)).toEqual({ staticCount: 0, semanticCount: 0 });
  });
});
