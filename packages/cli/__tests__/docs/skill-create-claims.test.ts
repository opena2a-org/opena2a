/**
 * What the docs say about `opena2a skill create` matches what it produces.
 *
 * The scaffold carries an opena2a-guard hash pin: an unkeyed SHA-256 stored in
 * the file it covers, not a signature. `opena2a scan secure` on a fresh
 * scaffold still reports `Unsigned Heartbeat` (high) and `Not safe as-is`,
 * because the remaining findings need an AIM identity that generated files
 * cannot carry. So neither the command reference nor a changelog entry may
 * describe the scaffold as signed or as passing `scan`.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createSkill } from '../../src/commands/create/skill.js';

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

function read(rel: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, rel), 'utf-8');
}

/**
 * Lines of a file that talk about `skill create` / `create skill`. The
 * changelog entry recording this correction quotes the old claims and names
 * this file, so it is left out.
 */
function skillCreateLines(rel: string): string[] {
  return read(rel)
    .split('\n')
    .filter(l => /`(?:opena2a )?(?:skill create|create skill)\b/.test(l))
    .filter(l => !l.includes('skill-create-claims.test.ts'));
}

const FILES = ['docs/commands.md', 'CHANGELOG.md', 'packages/cli/CHANGELOG.md'];

describe('skill create is not described as signed or as passing scan', () => {
  for (const rel of FILES) {
    it(rel, () => {
      const lines = skillCreateLines(rel);
      expect(lines.length).toBeGreaterThan(0);
      for (const line of lines) {
        expect(line).not.toMatch(/with signing|auto-signing|passes `?scan`?/i);
      }
    });
  }

  it('the command reference names the hash pin and says it is not a signature', () => {
    const row = skillCreateLines('docs/commands.md').find(l => l.startsWith('| `opena2a skill create'));
    expect(row).toBeDefined();
    expect(row).toContain('hash pin');
    expect(row).toContain('not a signature');
  });

  it('the #259 changelog entry says the high finding remains', () => {
    const entry = read('CHANGELOG.md').split('\n').find(l => l.includes('(#259)') && l.startsWith('- `skill create`'));
    expect(entry).toBeDefined();
    expect(entry).toContain('does not pass `scan`');
    expect(entry).toContain('`Unsigned Heartbeat`');
  });
});

describe('skill create output does not call the hash pin a signature', () => {
  it('says what was written and never "signed" or "with signing"', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-skill-claims-'));
    const chunks: Buffer[] = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string | Uint8Array) => {
      chunks.push(Buffer.from(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      await createSkill({ name: 's', template: 'basic', output: path.join(dir, 's'), ci: true, format: 'text' });
    } finally {
      process.stdout.write = origWrite;
      fs.rmSync(dir, { recursive: true, force: true });
    }
    const output = Buffer.concat(chunks).toString('utf-8');
    expect(output).toContain('Hash-pinned SKILL.md and HEARTBEAT.md');
    expect(output).toContain('Not a signature');
    expect(output).not.toMatch(/with signing|\bsigned\b|passes `?scan/i);
  });
});
