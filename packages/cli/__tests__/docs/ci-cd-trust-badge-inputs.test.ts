/**
 * The trust-badge-action example in docs/use-cases/ci-cd.md passes only inputs
 * the action declares.
 *
 * Its step passed `output-path: .github/badges/trust-score.svg`, an input
 * opena2a-org/trust-badge-action does not declare, and the sentence above it
 * said the action "Generates a trust score badge", as if it wrote an SVG file.
 * The action updates the badge in the README for the package it is named. The
 * step now passes `package-name` and `package-source`, and the sentence says the
 * action updates the README badge.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO_ROOT = resolve(__dirname, '../../../..');
const GUIDE = 'docs/use-cases/ci-cd.md';

const lines = readFileSync(join(REPO_ROOT, GUIDE), 'utf-8').split(/\r?\n/);

/** The lines from `### trust-badge-action` up to the next heading or rule. */
function section(): string[] {
  const start = lines.indexOf('### trust-badge-action');
  expect(start, `${GUIDE} has no "### trust-badge-action" heading`).toBeGreaterThanOrEqual(0);
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => /^(#{1,3} |---$)/.test(line));
  return end === -1 ? rest : rest.slice(0, end);
}

/** The keys under `with:` in the step that uses the action. */
function stepInputs(): string[] {
  const body = section();
  const uses = body.findIndex((line) => line.trim().startsWith('uses: opena2a-org/trust-badge-action@'));
  expect(uses, 'the section has no step that uses opena2a-org/trust-badge-action').toBeGreaterThanOrEqual(0);
  const withAt = body.findIndex((line, i) => i > uses && line.trim() === 'with:');
  expect(withAt, 'the trust-badge-action step passes no inputs').toBeGreaterThan(uses);
  const indent = body[withAt].length - body[withAt].trimStart().length;
  const keys: string[] = [];
  for (const line of body.slice(withAt + 1)) {
    if (line.trim() === '' || line.trim().startsWith('```')) break;
    if (line.length - line.trimStart().length <= indent) break;
    keys.push(line.trim().split(':')[0]);
  }
  return keys;
}

describe(`${GUIDE} trust-badge-action example`, () => {
  it('passes package-name and package-source and no other input', () => {
    expect(stepInputs()).toEqual(['package-name', 'package-source']);
  });

  it('names output-path on no line of the guide', () => {
    expect(lines.filter((line) => /output-path/.test(line))).toEqual([]);
  });

  it('says the action updates the badge in the README', () => {
    const prose = section().filter((line) => line.trim() !== '' && !/^\s*(```|- name:|uses:|with:)/.test(line));
    expect(prose.some((line) => /\bupdates\b.*\bbadge\b.*\bREADME\b/i.test(line))).toBe(true);
    expect(prose.join('\n')).not.toMatch(/Generates a trust score badge/);
  });
});
