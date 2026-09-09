import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Source-literal guard: the detector test files must never carry a whole
 * provider-shaped credential literal in their committed source. Fixtures are
 * assembled from parts at run time (see slackTestToken above the harness in
 * patterns.test.ts), so the detectors see the assembled string but the tree —
 * and GitHub secret scanning — never see a contiguous shape.
 *
 * The shape set is carried inline as regexes: a regex literal's source never
 * forms a contiguous provider-shape string, so this file stays clean under
 * its own rule.
 */
const PROVIDER_SHAPES: RegExp[] = [
  /(AKIA|ASIA)[0-9A-Z]{16}/,
  /AIza[0-9A-Za-z_-]{35}/,
  /xox[abprs]-[0-9A-Za-z-]{20,}/,
  /ghp_[A-Za-z0-9]{36}/,
  /github_pat_[A-Za-z0-9_]{22,}/,
  /sk-ant-[A-Za-z0-9_-]{20,}/,
  /mongodb\+srv:\/\/[^:/@\s]+:[^@\s]+@[^/\s]+/,
  /live_[A-Za-z0-9_-]{30,}/,
];

// Repo-relative scan population: exactly the detector test files this rule
// covers. protect.test.ts carries no shapes today but stays in scope so a
// regression there fails here, not in GitHub's alert queue.
const SCANNED_FILES = [
  'packages/cli/__tests__/util/ai-config.test.ts',
  'packages/cli/__tests__/commands/protect.test.ts',
  'packages/credential-patterns/src/patterns.test.ts',
];

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

interface ShapeHit {
  file: string;
  line: number;
  shape: string;
}

function scanFileForProviderShapes(filePath: string): ShapeHit[] {
  const source = fs.readFileSync(filePath, 'utf8');
  const hits: ShapeHit[] = [];
  for (const shape of PROVIDER_SHAPES) {
    const re = new RegExp(shape.source, 'g');
    let match: RegExpExecArray | null;
    while ((match = re.exec(source)) !== null) {
      hits.push({
        file: filePath,
        line: source.slice(0, match.index).split('\n').length,
        shape: shape.source,
      });
      if (re.lastIndex === match.index) re.lastIndex++;
    }
  }
  return hits;
}

function guardVerdict(files: string[]): { pass: boolean; hits: ShapeHit[] } {
  const hits = files.flatMap(scanFileForProviderShapes);
  return { pass: hits.length === 0, hits };
}

describe('source-literal guard', () => {
  it('OPA-12.AC1 committed detector test files carry zero contiguous provider-shape literals', () => {
    const targets = SCANNED_FILES.map(rel => path.join(repoRoot, rel));
    for (const target of targets) {
      expect(fs.existsSync(target), `scanned file exists: ${path.relative(repoRoot, target)}`).toBe(true);
    }
    const verdict = guardVerdict(targets);
    const report = verdict.hits.map(h => `${path.relative(repoRoot, h.file)}:${h.line} matches ${h.shape}`);
    expect(report).toEqual([]);
    expect(verdict.pass).toBe(true);
  });

  it('OPA-12.AC2 refuses a scratch copy with a planted provider-shape literal', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opa12-guard-'));
    try {
      // Plant into a copy of a real scanned file; the planted value is itself
      // assembled at plant time so this test's source stays shape-free.
      const original = path.join(repoRoot, 'packages/credential-patterns/src/patterns.test.ts');
      const plantedValue = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
      const plantedFile = path.join(tempDir, 'patterns.test.ts');
      fs.writeFileSync(
        plantedFile,
        fs.readFileSync(original, 'utf8') + `\nconst plantedFixture = '${plantedValue}';\n`,
      );

      const verdict = guardVerdict([plantedFile]);
      expect(verdict.hits.some(h => h.file === plantedFile)).toBe(true);
      expect(verdict.pass).toBe(false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
