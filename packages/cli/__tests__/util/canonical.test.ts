import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { HMA_CHECK_COUNT, CANONICAL_NUMBERS_REVISION } from '../../src/util/canonical';

const SRC_ROOT = path.resolve(__dirname, '..', '..', 'src');

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

describe('canonical numbers (#118)', () => {
  it('exposes HMA_CHECK_COUNT and a revision marker', () => {
    expect(typeof HMA_CHECK_COUNT).toBe('number');
    expect(HMA_CHECK_COUNT).toBeGreaterThan(0);
    expect(typeof CANONICAL_NUMBERS_REVISION).toBe('number');
  });

  it('mirrors hmaChecks.value from the website canonical-numbers.json when accessible', () => {
    const candidates = [
      path.resolve(__dirname, '..', '..', '..', '..', '..', 'opena2a-website', 'data', 'canonical-numbers.json'),
      path.resolve(__dirname, '..', '..', '..', '..', '..', '..', 'opena2a-website', 'data', 'canonical-numbers.json'),
    ];
    const found = candidates.find(p => fs.existsSync(p));
    if (!found) {
      // Sibling repo not checked out (CI clone, npm install) — skip.
      return;
    }
    const data = JSON.parse(fs.readFileSync(found, 'utf-8'));
    const websiteValue = data?.hmaChecks?.value;
    if (typeof websiteValue !== 'number') return;
    expect(HMA_CHECK_COUNT).toBe(websiteValue);
  });

  it('no source file embeds the prior or current literal as a check-count copy (must use HMA_CHECK_COUNT)', () => {
    const files = listTsFiles(SRC_ROOT);
    const offenders: { file: string; line: number; text: string }[] = [];
    // Match copy that pairs a number with the word "checks" so unrelated
    // literals (CSS rgba, severity counts, port numbers) don't false-positive.
    const copyRegex = /\b(?:209|238|240)\s+(?:security\s+)?checks?\b/i;
    for (const file of files) {
      // The constants module itself is allowed to declare the number.
      if (file.endsWith(path.join('src', 'util', 'canonical.ts'))) continue;
      const lines = fs.readFileSync(file, 'utf-8').split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (copyRegex.test(lines[i])) {
          offenders.push({ file: path.relative(SRC_ROOT, file), line: i + 1, text: lines[i].trim() });
        }
      }
    }
    expect(offenders, `Hardcoded check-count copy found. Use HMA_CHECK_COUNT from util/canonical.ts:\n${offenders.map(o => `${o.file}:${o.line}  ${o.text}`).join('\n')}`).toEqual([]);
  });
});
