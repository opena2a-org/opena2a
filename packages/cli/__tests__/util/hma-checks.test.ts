import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { hmaCheckCount, hmaCheckCounts, hmaChecksPhrase } from '../../src/util/hma-checks';

const CLI_ROOT = path.resolve(__dirname, '..', '..');
const SRC_ROOT = path.join(CLI_ROOT, 'src');

/** The engine's own answer, read independently of the module under test. */
function engineStaticCount(): number {
  const req = createRequire(path.join(CLI_ROOT, 'package.json'));
  const entry = req.resolve('hackmyagent');
  const taxonomy = req(path.join(path.dirname(entry), 'hardening', 'taxonomy.js'));
  return taxonomy.getCheckCounts().static;
}

function listTsFiles(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue;
      listTsFiles(full, out);
    } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
      out.push(full);
    }
  }
  return out;
}

describe('HackMyAgent check count comes from the engine', () => {
  it('equals the static count the engine reports in a scan', () => {
    const expected = engineStaticCount();
    expect(expected).toBeGreaterThan(0);
    expect(hmaCheckCount()).toBe(expected);
    expect(hmaCheckCounts()?.static).toBe(expected);
    expect(hmaChecksPhrase('security checks')).toBe(`${expected} security checks`);
  });

  it('the CLI README quotes the same count as the engine', () => {
    const expected = engineStaticCount();
    const readme = fs.readFileSync(path.join(CLI_ROOT, 'README.md'), 'utf-8');
    const quoted = [...readme.matchAll(/\b(\d+)\+?\s+(?:security\s+)?checks\b/gi)].map(m => Number(m[1]));
    expect(quoted.length).toBeGreaterThan(0);
    expect(quoted, `packages/cli/README.md must quote ${expected} checks, as hackmyagent's getCheckCounts().static reports`)
      .toEqual(quoted.map(() => expected));
  });

  it('no source file hardcodes a check count (use util/hma-checks)', () => {
    const offenders: string[] = [];
    // A literal number directly followed by "checks" in copy. Template
    // interpolations (`${n} checks`) and counts of other things are allowed.
    const copyRegex = /(?<![$\w{])\b\d{3}\+?\s+(?:security\s+)?checks\b/i;
    for (const file of listTsFiles(SRC_ROOT)) {
      const lines = fs.readFileSync(file, 'utf-8').split('\n');
      lines.forEach((line, i) => {
        if (copyRegex.test(line)) offenders.push(`${path.relative(SRC_ROOT, file)}:${i + 1}  ${line.trim()}`);
      });
    }
    expect(offenders, `Hardcoded check-count copy found:\n${offenders.join('\n')}`).toEqual([]);
  });
});
