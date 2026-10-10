import { describe, it, expect, vi, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { FINDING_CATALOG } from '../../src/shield/findings.js';
import { shield } from '../../src/commands/shield.js';

// "Tamper-evident" claims a record that whoever can change the checked files
// cannot also rewrite. Neither the Shield event log (a keyless SHA-256 chain,
// see the guarantee boundary in src/shield/events.ts) nor MCP signing has
// one, so no source line the CLI ships (help text, finding text, report
// HTML, comments that land in .d.ts files) may use the word for them.
//
// The walk covers every tracked file under src/, not a list of files, so a
// new occurrence anywhere fails it. PENDING names the lines that still carry
// the claim while their replacement wording is outstanding; an entry whose
// line has changed fails as stale, so the list only shrinks.

const CLI_ROOT = path.resolve(__dirname, '..', '..');

const BARRED: RegExp[] = [
  /tamper[- ]?eviden(?:t|ce)/gi,
  /indicates log tampering/gi,
  /An edit, damage to the file/gi,
];

interface Pending {
  file: string;
  fragment: string;
}

const PENDING: Pending[] = [
  { file: 'src/shield/events.ts', fragment: ' * Shield tamper-evident event system.' },
  { file: 'src/shield/events.ts', fragment: ' * an append-only tamper-evident log.' },
  { file: 'src/shield/arp-bridge.ts', fragment: ' * tamper-evident hash chain.' },
  { file: 'src/shield/arp-bridge.ts', fragment: " * Shield's tamper-evident event log." },
  { file: 'src/commands/detect.ts', fragment: 'Signing creates a tamper-evident record of exactly which server version is in use.' },
  { file: 'src/commands/detect.ts', fragment: "Signing creates a tamper-evident record of each server's configuration." },
  { file: 'src/commands/detect.ts', fragment: 'None have verified identities, so there is no tamper-evident record of ' },
  { file: 'src/report/review/assets/client/60-shadowai.js', fragment: 'None have verified identities, so there is no tamper-evident record of which server version is installed.' },
];

function countBarred(text: string): number {
  let n = 0;
  for (const re of BARRED) n += (text.match(re) ?? []).length;
  return n;
}

function countOccurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

/** Tracked files under `<root>/src`, as git sees them. */
function trackedSourceFiles(root: string): string[] {
  return execFileSync('git', ['-C', root, 'ls-files', '-z', '--', 'src'], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).split('\0').filter(Boolean);
}

/**
 * Every barred occurrence not covered by a PENDING fragment on the same line
 * is a violation; every PENDING fragment found nowhere in its file is stale.
 */
function scan(root: string, files: string[], pending: Pending[]): { violations: string[]; stale: string[] } {
  const violations: string[] = [];
  const seen = new Set<Pending>();
  for (const file of files) {
    const lines = fs.readFileSync(path.join(root, file), 'utf-8').split('\n');
    const forFile = pending.filter(p => p.file === file);
    lines.forEach((line, i) => {
      const total = countBarred(line);
      if (total === 0) return;
      let covered = 0;
      for (const p of forFile) {
        const k = countOccurrences(line, p.fragment);
        if (k > 0) seen.add(p);
        covered += k * countBarred(p.fragment);
      }
      if (total > covered) violations.push(`${file}:${i + 1}`);
    });
  }
  const stale = pending.filter(p => !seen.has(p)).map(p => `${p.file}: ${p.fragment}`);
  return { violations, stale };
}

describe('CLI source makes no tamper-evidence claim', () => {
  it('the walk reads the tracked src/ tree', () => {
    const files = trackedSourceFiles(CLI_ROOT);
    expect(files.length).toBeGreaterThan(100);
    expect(files).toContain('src/shield/events.ts');
    expect(files).toContain('src/report/review-html.ts');
    expect(files).toContain('src/report/review/assets/client/40-shield.js');
  });

  it('no tracked source line carries the barred wording outside PENDING, and no PENDING entry is stale', () => {
    const { violations, stale } = scan(CLI_ROOT, trackedSourceFiles(CLI_ROOT), PENDING);
    expect(violations).toEqual([]);
    expect(stale).toEqual([]);
  });

  describe('control: a planted line turns the walk red', () => {
    let dir: string | undefined;
    afterEach(() => {
      if (dir) fs.rmSync(dir, { recursive: true, force: true });
      dir = undefined;
    });

    function plantedTree(files: Record<string, string>): string {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'barred-wording-'));
      for (const [rel, body] of Object.entries(files)) {
        fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
        fs.writeFileSync(path.join(root, rel), body);
      }
      execFileSync('git', ['-C', root, 'init', '-q'], { stdio: 'ignore' });
      execFileSync('git', ['-C', root, 'add', '--', 'src'], { stdio: 'ignore' });
      return root;
    }

    it('flags one planted line in a file PENDING does not name', () => {
      dir = plantedTree({
        'src/clean.ts': '// Query the Shield event log\n',
        'src/unnamed/planted.ts': 'export const x = 1;\n// writes to a tamper-evidence store\n',
      });
      const { violations } = scan(dir, trackedSourceFiles(dir), PENDING);
      expect(violations).toEqual(['src/unnamed/planted.ts:2']);
    });

    it('flags a second occurrence added to a PENDING line', () => {
      const pendingLine = PENDING[4];
      dir = plantedTree({
        [pendingLine.file]: `'${pendingLine.fragment}' + ' A tamper evident log.'\n`,
      });
      const { violations } = scan(dir, trackedSourceFiles(dir), PENDING);
      expect(violations).toEqual([`${pendingLine.file}:1`]);
    });
  });
});

describe('Shield finding text', () => {
  it('SHIELD-INT-002 states the verdict and asserts no cause', () => {
    const def = FINDING_CATALOG['SHIELD-INT-002'];
    expect(def.title).toBe('Event hash chain integrity broken');
    expect(def.severity).toBe('critical');
    expect(def.description).toBe(
      "The Shield event log hash chain is broken: an event's hash, or its link to the previous event, does not match.",
    );
    expect(def.description).not.toMatch(/indicat|tamper|corrupt/i);
  });

  it('SHIELD-INT-001 says what the hash check can and cannot tell', () => {
    const def = FINDING_CATALOG['SHIELD-INT-001'];
    expect(def.title).toBe('Configuration file changed');
    expect(def.severity).toBe('critical');
    expect(def.remediation).toBe('opena2a guard diff');
    expect(def.description).toBe(
      'A monitored configuration file was changed or removed after its SHA-256 hash was recorded. '
        + 'The check cannot tell an authorized change from an unauthorized one.',
    );
  });
});

describe('shield subcommand list', () => {
  it('describes `log` as the Shield event log', async () => {
    const chunks: string[] = [];
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      chunks.push(String(chunk));
      return true;
    });
    try {
      await shield({ subcommand: 'no-such-subcommand' });
    } finally {
      spy.mockRestore();
    }
    const out = chunks.join('');
    expect(out).toContain('  log        Query the Shield event log\n');
    expect(countBarred(out)).toBe(0);
  });
});
