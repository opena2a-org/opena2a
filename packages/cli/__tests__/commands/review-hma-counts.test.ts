import { describe, it, expect } from 'vitest';
import { deriveHmaCounts } from '../../src/commands/review.js';

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
    expect(deriveHmaCounts(parsed, 1)).toEqual({ totalChecks: 4, passed: 1 });
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
