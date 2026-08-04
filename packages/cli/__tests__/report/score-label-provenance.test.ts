// Regression: two different measurements never share a name, in the type or on
// the page.
//
// `review` computed a Shield runtime posture (active tools + policy + shell
// integration, penalized by findings) and `init` computed a project governance
// posture (credentials, config, environment). Different inputs, different
// formulas, different questions — and both were called `postureScore` and both
// rendered under the label "Posture Score". One report therefore showed
// "Posture Score 52" on Overview and "Posture Score 35" on Shield, and
// `init --json | jq .postureScore` matched whichever the reader happened to
// mean. A number that cannot be traced to what it measured is not a
// measurement.
//
// Two properties are pinned:
//   - the FIELD names are distinct (a consumer reading JSON), and
//   - the visible LABELS are distinct (a human reading the report).
// The second is the one that actually reached users, and a rename alone would
// not have fixed it — the labels were separate string literals.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = join(__dirname, '..', '..', 'src');
const reviewSrc = () => readFileSync(join(SRC, 'commands', 'review.ts'), 'utf-8');
const htmlSrc = () => readFileSync(join(SRC, 'report', 'review-html.ts'), 'utf-8');

describe('score provenance', () => {
  it('the shield posture field names the posture it measures', () => {
    const src = reviewSrc();
    expect(src).toContain('shieldPostureScore');
    // The shield phase must not reintroduce a bare `postureScore` field. Scoped
    // to the ShieldPhaseData block so `InitPhaseData.postureScore` — a
    // different, legitimately-named quantity — does not trip this.
    const shieldBlock = src.slice(
      src.indexOf('export interface ShieldPhaseData'),
      src.indexOf('/** Pass-through mirrors of HMA Finding v2 schema'),
    );
    expect(shieldBlock.length).toBeGreaterThan(100); // non-vacuity: the block was found
    expect(shieldBlock).not.toMatch(/^\s*postureScore\s*:/m);
  });

  /**
   * The QUANTITY a tile expression refers to, independent of how it was reached.
   *
   * Comparing raw expressions is too strict: the same severity count is legitimately
   * rendered on several pages via different accessors (`sevCounts.high`,
   * `data.bySeverity.high||0`, `bs.high||0`) — one measurement, three routes to it.
   * Stripping the object path and the `||0` default leaves the leaf name, which is
   * what actually names the quantity. `postureScore` and `shieldPostureScore` stay
   * distinct under this normalization, which is the case that matters.
   */
  const quantity = (expr: string) =>
    expr
      // Strip only the ACCESSOR noise, never the object path: `data.`/`bs.`/
      // `sevCounts.` are three routes to one severity count, but `init.` and
      // `shield.` are what distinguish two different postures. An earlier
      // version took `.pop()` on the whole dotted path, which deleted the only
      // discriminator — `init.postureScore` and `shield.postureScore` both
      // normalized to `postureScore`, so the guard could not fail on the exact
      // defect it was written for. Red-proofed against main.
      .replace(/\|\|\s*0\s*$/, '')
      .replace(/\?.*$/, '')
      // Drop known ACCESSOR segments wherever they appear, so the three routes
      // to one severity count (`data.bySeverity.high`, `bs.high`,
      // `sevCounts.high`) agree — while `init.` and `shield.` survive, because
      // those name which posture is being measured.
      .split('.')
      .filter(seg => !['data', 'bs', 'sevCounts', 'bySeverity', 'd'].includes(seg.trim()))
      .join('.')
      .trim();

  /**
   * Tiles, parsed with a BALANCED first argument.
   *
   * `([^,]+)` stopped at the first comma, so `statCard(Math.max(a,0),'Findings')`
   * matched nothing at all and the tile became invisible to the guard — a
   * collision could be hidden by wrapping one side in any two-argument call.
   */
  const tiles = () => {
    const src = htmlSrc();
    const out: Array<{ value: string; label: string }> = [];
    for (const m of src.matchAll(/statCard\(/g)) {
      let i = m.index! + m[0].length;
      let depth = 0;
      const start = i;
      while (i < src.length && !(depth === 0 && src[i] === ',')) {
        if ('([{'.includes(src[i])) depth++;
        else if (')]}'.includes(src[i])) depth--;
        i++;
      }
      const value = src.slice(start, i).trim();
      const label = src.slice(i + 1).match(/^\s*['"`]([^'"`]+)['"`]/);
      if (label) out.push({ value, label: label[1] });
    }
    return out;
  };

  it('the normalization still separates the two postures', () => {
    // Guards the guard. A normalization that collapsed these would make the
    // collision test below unable to fail on the very defect it exists for —
    // which is exactly what an earlier `.split('.').pop()` version did.
    expect(quantity('init.postureScore')).not.toBe(quantity('shield.shieldPostureScore'));
    expect(quantity('init.postureScore')).not.toBe(quantity('shield.postureScore'));
    // ...while still collapsing the accessor variants it is meant to collapse.
    expect(quantity('data.bySeverity.high||0')).toBe(quantity('bs.high||0'));
  });

  it('the tile parser survives a wrapped first argument', () => {
    // Non-vacuity for the parser itself: a comma inside the value expression
    // must not make the tile invisible.
    const parsed = tiles();
    expect(parsed.length).toBeGreaterThan(2);
    expect(parsed.every(t => t.label.length > 0)).toBe(true);
  });

  it('no two report tiles claim the same label for different quantities', () => {
    const parsed = tiles();
    expect(parsed.length).toBeGreaterThan(2); // non-vacuity: tiles were actually parsed

    const byLabel = new Map<string, Set<string>>();
    for (const t of parsed) {
      if (!byLabel.has(t.label)) byLabel.set(t.label, new Set());
      byLabel.get(t.label)!.add(quantity(t.value));
    }
    const collisions = [...byLabel.entries()]
      .filter(([, values]) => values.size > 1)
      .map(([label, values]) => `${label}: ${[...values].join(' vs ')}`);
    expect(collisions).toEqual([]);
  });

  it('the two posture tiles say which posture they are', () => {
    const src = htmlSrc();
    expect(src).toContain("'Project Posture'");
    expect(src).toContain("'Shield Posture'");
    // The ambiguous label is gone, not merely supplemented.
    expect(src).not.toContain("'Posture Score'");
  });
});
