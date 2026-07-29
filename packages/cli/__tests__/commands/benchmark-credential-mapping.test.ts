/**
 * Issue #250, second round — the credential mapping, tested end-to-end.
 *
 * The first fix wired `quickCredentialScan` into `benchmark` but recorded a
 * failure only when the finding id was itself an OASB control, so anything
 * outside CRED-002/003/004 was silently discarded. The headline defect survived
 * the rewrite: with a hardcoded Anthropic key, `protect` reported
 * "CRITICAL CRED-001 Anthropic API Key" while `benchmark` printed
 * "Credential Protection: 100% [PASS]" — byte-identical to an empty directory.
 *
 * Every case here drives the REAL `benchmark()` against a REAL temp directory
 * with the REAL credential scanner. The previous round's test hand-built the
 * assessment and re-declared the vocabulary inline, so it could not disagree
 * with the code under test and would not have caught this.
 *
 * Keys are generated at runtime: no credential-shaped literal is committed, and
 * the entropy rules out a placeholder filter explaining a miss.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';

import { benchmark } from '../../src/commands/benchmark.js';

function body(n = 28): string {
  return randomBytes(24).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, n);
}

/** Shapes across the credential vocabulary, only one of which is an OASB control. */
const SHAPES: Array<{ label: string; expectId: string; make: () => string }> = [
  { label: 'OpenAI (CRED-002 — is an OASB control)', expectId: 'CRED-002', make: () => `sk-${body()}` },
  { label: 'Anthropic (CRED-001 — no OASB control)', expectId: 'CRED-001', make: () => `sk-ant-api03-${body()}` },
];

const dirs: string[] = [];

function fixture(secret: string): string {
  const d = fs.mkdtempSync(path.join(tmpdir(), 'bench-cred-'));
  fs.writeFileSync(path.join(d, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
  fs.writeFileSync(path.join(d, 'index.js'), `const k = "${secret}";\n`);
  dirs.push(d);
  return d;
}

async function runJson(targetDir: string): Promise<Record<string, any>> {
  let out = '';
  const spy = vi.spyOn(process.stdout, 'write').mockImplementation((c: any) => { out += c; return true; });
  await benchmark({ targetDir, format: 'json' });
  spy.mockRestore();
  return JSON.parse(out);
}

let empty: string;

beforeAll(() => {
  empty = fs.mkdtempSync(path.join(tmpdir(), 'bench-empty-'));
  fs.writeFileSync(path.join(empty, 'package.json'), '{"name":"e","version":"1.0.0"}\n');
  dirs.push(empty);
});

afterAll(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

describe('benchmark credential mapping (#250)', () => {
  for (const shape of SHAPES) {
    it(`${shape.label}: fails the credential category`, async () => {
      const r = await runJson(fixture(shape.make()));
      const cred = r.categories.find((c: any) => /credential/i.test(c.name));
      expect(cred, 'no Credential Protection category').toBeDefined();
      expect(cred.compliance, `${shape.expectId} scored the category 100%`).not.toBe(100);
      expect(cred.failing.length).toBeGreaterThan(0);
      expect(r.summary.failingControls).toBeGreaterThan(0);
    });

    it(`${shape.label}: does not read identically to an empty project`, async () => {
      // The sharpest form of the defect: same output for "has a critical
      // hardcoded key" and "has nothing at all".
      const dirty = await runJson(fixture(shape.make()));
      const clean = await runJson(empty);
      expect(dirty.summary.failingControls).not.toBe(clean.summary.failingControls);
      expect(dirty.rating).not.toBe(clean.rating);
    });
  }

  it('an unmapped credential id is surfaced, not silently folded', async () => {
    const r = await runJson(fixture(`sk-ant-api03-${body()}`));
    expect(r.summary.unmappedCredentialFindings.map((f: any) => f.id)).toContain('CRED-001');
  });

  it('a failing control yields a negative rating, not a coverage-masked one', async () => {
    // Coverage gating removes unearned affirmative ratings; it must not remove
    // an earned negative one, which made `Partial` the only reachable value.
    const r = await runJson(fixture(`sk-${body()}`));
    expect(r.rating).not.toBe('Partial');
    expect(r.rating).not.toBe('Certified');
    expect(r.rating).not.toBe('Passing');
  });

  it('a clean project is still Partial, not falsely negative', async () => {
    const r = await runJson(empty);
    expect(r.rating).toBe('Partial');
    expect(r.summary.failingControls).toBe(0);
  });

  it('the declared credential vocabulary really is OASB L1', async () => {
    // Drift guard. If OASB adds or renames a credential control, or the local
    // list diverges, coverage is silently under- or over-reported.
    const hma: any = await import('hackmyagent');
    const l1: string[] = hma.getCheckIdsForLevel('L1');
    for (const id of ['CRED-002', 'CRED-003', 'CRED-004']) {
      expect(l1, `${id} is no longer an OASB L1 control`).toContain(id);
    }
  });
});
