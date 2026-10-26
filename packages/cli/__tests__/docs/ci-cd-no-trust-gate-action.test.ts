/**
 * docs/use-cases/ci-cd.md offers no trust-gate-action step.
 *
 * Its "GitHub Actions from OpenA2A" section opened with "Two pre-built GitHub
 * Actions simplify integration:" and then showed a step that used
 * `opena2a-org/trust-gate-action@v1` with `threshold` and `fail-on-unsigned`.
 * No repository of that name exists, and neither input is declared by
 * opena2a-org/trust-gate, at main or at v1. The sentence and the step's
 * section were removed; these checks keep them out of the guide.
 *
 * Only the removed lines that occur nowhere else in the guide are listed: the
 * fences, `with:` and the step name `Trust gate` also belong to other
 * examples. Lines are compared without their indentation, so a copy of one at
 * another depth is caught too.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO_ROOT = resolve(__dirname, '../../../..');
const GUIDE = 'docs/use-cases/ci-cd.md';

const REMOVED_LINES = [
  'Two pre-built GitHub Actions simplify integration:',
  '### trust-gate-action',
  'Blocks merges when the trust score drops below a threshold:',
  'uses: opena2a-org/trust-gate-action@v1',
  'threshold: 0.70',
  'fail-on-unsigned: true',
  'Repository: [opena2a-org/trust-gate-action](https://github.com/opena2a-org/trust-gate-action)',
];

const lines = readFileSync(join(REPO_ROOT, GUIDE), 'utf-8')
  .split(/\r?\n/)
  .map((line) => line.trim());

describe(`${GUIDE} offers no trust-gate-action step`, () => {
  it('names trust-gate-action on no line', () => {
    expect(lines.filter((line) => /trust-gate-action/i.test(line))).toEqual([]);
  });

  it.each(REMOVED_LINES)('carries no line %j', (removed) => {
    expect(lines).not.toContain(removed);
  });
});
