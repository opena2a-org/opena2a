import { describe, it, expect } from 'vitest';
import { trustLevelLabel } from '@opena2a/cli-ui';
import {
  describeTrustAnswer,
  loadTrustUi,
  paintTrustAnswer,
  trustNextStep,
  trustNextStepLine,
} from '../../src/util/trust-answer.js';

// The four commands that show a Registry trust answer take its word from
// cli-ui, as `check` does, and name one next step for Blocked and Warning.
describe('trust answer view', () => {
  it('names each level by cli-ui\'s word beside its number', async () => {
    const ui = await loadTrustUi();
    for (const level of [0, 1, 2, 3, 4]) {
      const view = describeTrustAnswer(ui, { trustLevel: level, verdict: '' }, 'pkg');
      expect(view?.word).toBe(trustLevelLabel(level));
      expect(view?.label.startsWith(`${trustLevelLabel(level)} (level ${level} of 4)`)).toBe(true);
    }
  });

  it('gives Blocked and Warning a tone, advice and the next step', async () => {
    const ui = await loadTrustUi();
    expect(describeTrustAnswer(ui, { trustLevel: 0, verdict: 'blocked' }, 'pkg')).toMatchObject({
      word: 'Blocked', tone: 'critical', advice: 'do not use', nextStep: 'opena2a check pkg',
    });
    expect(describeTrustAnswer(ui, { trustLevel: 1, verdict: 'warning' }, 'pkg')).toMatchObject({
      word: 'Warning', tone: 'warning', advice: 'review before use', nextStep: 'opena2a check pkg',
    });
    expect(describeTrustAnswer(ui, { trustLevel: 3, verdict: 'passed' }, 'pkg')).toMatchObject({
      word: 'Scanned', tone: 'good', advice: null, nextStep: null,
    });
  });

  it('never shows a blocked or warning verdict under a better word', async () => {
    const ui = await loadTrustUi();
    expect(describeTrustAnswer(ui, { trustLevel: 3, verdict: 'blocked' }, 'pkg')?.word).toBe('Blocked');
    expect(describeTrustAnswer(ui, { trustLevel: 4, verdict: 'warnings' }, 'pkg')?.word).toBe('Warning');
    expect(describeTrustAnswer(ui, { verdict: 'failed' }, 'pkg')?.word).toBe('Blocked');
  });

  it('shows a listed record as not scanned, dim, with no next step', async () => {
    const ui = await loadTrustUi();
    for (const answer of [{ trustLevel: 2, verdict: 'listed' }, { verdict: 'listed' }, { trustLevel: 2 }]) {
      expect(describeTrustAnswer(ui, answer, 'pkg')).toMatchObject({
        word: 'Listed',
        label: 'Listed (level 2 of 4), not scanned',
        notScanned: true,
        tone: 'dim',
        nextStep: null,
      });
    }
  });

  it('describes nothing when the answer names no level', async () => {
    const ui = await loadTrustUi();
    expect(describeTrustAnswer(ui, { verdict: 'trusted' }, 'pkg')).toBeNull();
    expect(describeTrustAnswer(ui, { trustLevel: 7, verdict: 'passed' }, 'pkg')).toBeNull();
    expect(describeTrustAnswer(ui, {}, 'pkg')).toBeNull();
  });

  it('prints the word with its advice, and the next step on its own line', async () => {
    const ui = await loadTrustUi();
    const view = describeTrustAnswer(ui, { trustLevel: 0, verdict: 'blocked' }, '@scope/pkg')!;
    expect(paintTrustAnswer(view)).toBe('Blocked (level 0 of 4), do not use');
    expect(trustNextStepLine(view)).toBe('Next: opena2a check @scope/pkg');
    expect(trustNextStepLine(null)).toBeNull();
  });

  it('quotes a package name a shell would not read as one plain word', () => {
    expect(trustNextStep('@modelcontextprotocol/server-filesystem')).toBe('opena2a check @modelcontextprotocol/server-filesystem');
    expect(trustNextStep('x$(touch CANARY)')).toBe(`opena2a check 'x$(touch CANARY)'`);
    expect(trustNextStep("a'b c")).toBe(`opena2a check 'a'\\''b c'`);
  });
});
