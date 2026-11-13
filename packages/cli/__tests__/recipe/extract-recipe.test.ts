/**
 * The recipe workflow runs the Quick Start of docs/use-cases/ci-cd.md as the
 * guide prints it. scripts/ci/extract-recipe.mjs reads that block at run time
 * and makes one edit: the published invocation `npx opena2a-cli` becomes the
 * pull request's own build, `node packages/cli/dist/index.js`. These cases hold
 * the extractor to that:
 *
 *  - the block it reads is the guide's block, byte for byte, and with the one
 *    edit reversed its output is that block again;
 *  - each step script it hands the workflow is what a YAML reader takes from
 *    the block, so the workflow runs the text a reader of the guide copies;
 *  - a guide it cannot reproduce exactly is refused, never approximated.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { load } from 'js-yaml';

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const EXTRACTOR = path.join(REPO_ROOT, 'scripts', 'ci', 'extract-recipe.mjs');
const GUIDE = path.join(REPO_ROOT, 'docs', 'use-cases', 'ci-cd.md');

const DOCUMENTED = 'npx opena2a-cli';
const OWN_BUILD = 'node packages/cli/dist/index.js';

interface RecipeStep {
  name: string | null;
  workingDirectory: string | null;
  run: string;
}

interface Extracted {
  docBlock: string;
  block: string;
  substitutions: number;
  steps: RecipeStep[];
  setup: { uses: string; with: Record<string, string> }[];
}

interface ExtractorModule {
  DOCUMENTED_CLI: string;
  OWN_BUILD_CLI: string;
  extractQuickStart(markdown: string): Extracted;
}

let extractor: ExtractorModule;
let scratch: string;

beforeAll(async () => {
  extractor = (await import(/* @vite-ignore */ pathToFileURL(EXTRACTOR).href)) as ExtractorModule;
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'extract-recipe-'));
});

afterAll(() => {
  if (scratch) fs.rmSync(scratch, { recursive: true, force: true });
});

const readGuide = (): string => fs.readFileSync(GUIDE, 'utf-8');

/**
 * The fenced block under the guide's Quick Start heading, located here
 * without the extractor so the two readings can be compared.
 */
function documentedBlock(markdown: string): string {
  const lines = markdown.split('\n');
  const heading = lines.findIndex((l) => l.startsWith('## Quick Start'));
  const open = lines.findIndex((l, i) => i > heading && l === '```yaml');
  const close = lines.findIndex((l, i) => i > open && l === '```');
  if (heading < 0 || open < 0 || close < 0) throw new Error('no Quick Start yaml block in the guide');
  return lines.slice(open + 1, close).map((l) => `${l}\n`).join('');
}

const count = (text: string, needle: string): number => text.split(needle).length - 1;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** The steps of the one job in a parsed block, checked level by level. */
function parsedSteps(block: string): Record<string, unknown>[] {
  const doc: unknown = load(block);
  const jobs = isRecord(doc) && isRecord(doc.jobs) ? Object.values(doc.jobs) : [];
  expect(jobs).toHaveLength(1);
  const steps = isRecord(jobs[0]) ? jobs[0].steps : undefined;
  if (!Array.isArray(steps)) throw new Error('the block has no steps list');
  return steps.filter(isRecord);
}

describe('extract-recipe on docs/use-cases/ci-cd.md', () => {
  it('substitutes the published invocation with the build of this repository, and nothing else', () => {
    expect(extractor.DOCUMENTED_CLI).toBe(DOCUMENTED);
    expect(extractor.OWN_BUILD_CLI).toBe(OWN_BUILD);
  });

  it('reads the Quick Start block of the guide byte for byte', () => {
    const guide = readGuide();
    const { docBlock } = extractor.extractQuickStart(guide);
    expect(Buffer.from(docBlock).equals(Buffer.from(documentedBlock(guide)))).toBe(true);
  });

  it('with the substitution reversed, the extracted block is the documented block byte for byte', () => {
    const guide = readGuide();
    const doc = documentedBlock(guide);
    const { block, substitutions } = extractor.extractQuickStart(guide);

    expect(count(doc, OWN_BUILD)).toBe(0);
    expect(count(doc, DOCUMENTED)).toBeGreaterThan(0);
    expect(substitutions).toBe(count(doc, DOCUMENTED));
    expect(count(block, DOCUMENTED)).toBe(0);
    expect(Buffer.from(block).equals(Buffer.from(doc.split(DOCUMENTED).join(OWN_BUILD)))).toBe(true);
    expect(Buffer.from(block.split(OWN_BUILD).join(DOCUMENTED)).equals(Buffer.from(doc))).toBe(true);
  });

  it('every step script is the run text a YAML reader takes from the block', () => {
    const { block, steps, setup } = extractor.extractQuickStart(readGuide());
    const parsed = parsedSteps(block);
    const runs = parsed.filter((s) => 'run' in s);
    expect(steps.map((s) => s.run)).toEqual(runs.map((s) => s.run));
    expect(steps.map((s) => s.name)).toEqual(runs.map((s) => s.name ?? null));
    expect(steps.map((s) => s.workingDirectory)).toEqual(runs.map((s) => s['working-directory'] ?? null));

    const uses = parsed.filter((s) => 'uses' in s);
    expect(setup.map((s) => s.uses)).toEqual(uses.map((s) => s.uses));
    expect(setup.map((s) => s.with)).toEqual(
      uses.map((s) =>
        Object.fromEntries(Object.entries(isRecord(s.with) ? s.with : {}).map(([k, v]) => [k, String(v)])),
      ),
    );
  });

  it('steps 1 and 2 run the CLI once each from runner.temp; step 3 is the gate in the workspace', () => {
    const { steps } = extractor.extractQuickStart(readGuide());
    expect(steps).toHaveLength(3);
    expect(steps.map((s) => s.workingDirectory)).toEqual(['${{ runner.temp }}', '${{ runner.temp }}', null]);
    expect(steps.map((s) => count(s.run, OWN_BUILD))).toEqual([1, 1, 0]);
    expect(steps[0].run).toContain(`${OWN_BUILD} detect "$GITHUB_WORKSPACE"`);
    expect(steps[1].run).toContain(`${OWN_BUILD} review "$GITHUB_WORKSPACE"`);
    expect(steps[2].run).toMatch(/^\s*exit 1$/m);
  });
});

/** A guide of the real one's shape, for inputs the real guide does not hold. */
const STEP_1 = [
  '      - name: Detect',
  '        working-directory: ${{ runner.temp }}',
  '        run: npx opena2a-cli detect "$GITHUB_WORKSPACE" --format json --ci > "$GITHUB_WORKSPACE/d.json"',
];
const STEP_2 = [
  '      - name: Review',
  '        working-directory: ${{ runner.temp }}',
  '        run: npx opena2a-cli review "$GITHUB_WORKSPACE" --format json --ci > "$GITHUB_WORKSPACE/r.json"',
];
const STEP_3 = [
  '      - name: Gate',
  '        run: |',
  "          score=$(jq -r '.summary.governanceScore' d.json)",
  '          if ! [ "$score" -ge 60 ]; then',
  '            exit 1',
  '          fi',
];

function guideWith(steps: string[][], heading = '## Quick Start: Three-Step GitHub Actions Workflow'): string {
  return [
    '# A guide',
    '',
    heading,
    '',
    '```yaml',
    'name: Gate',
    'on:',
    '  pull_request:',
    'jobs:',
    '  gate:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: actions/checkout@v4',
    '      - uses: actions/setup-node@v4',
    '        with:',
    '          node-version: 20',
    '',
    ...steps.flatMap((s) => [...s, '']),
    '```',
    '',
  ].join('\n');
}

const replaceLine = (step: string[], index: number, line: string): string[] =>
  step.map((l, i) => (i === index ? line : l));

describe('extract-recipe refuses a guide it cannot reproduce exactly', () => {
  it('reads a guide of the expected shape (calibration for the refusals below)', () => {
    const r = extractor.extractQuickStart(guideWith([STEP_1, STEP_2, STEP_3]));
    expect(r.steps.map((s) => s.name)).toEqual(['Detect', 'Review', 'Gate']);
    expect(r.substitutions).toBe(2);
    expect(r.steps[2].run).toBe(
      "score=$(jq -r '.summary.governanceScore' d.json)\nif ! [ \"$score\" -ge 60 ]; then\n  exit 1\nfi\n",
    );
    const runs = parsedSteps(r.block).filter((s) => 'run' in s);
    expect(r.steps.map((s) => s.run)).toEqual(runs.map((s) => s.run));
  });

  it('no Quick Start heading', () => {
    expect(() => extractor.extractQuickStart(guideWith([STEP_1, STEP_2, STEP_3], '## Getting started'))).toThrow(
      /Quick Start/,
    );
  });

  it('a block that already names the own build, so the edit could not be reversed', () => {
    const step = [...STEP_1.slice(0, 2), `        run: ${OWN_BUILD} detect "$GITHUB_WORKSPACE"`];
    expect(() => extractor.extractQuickStart(guideWith([step, STEP_2, STEP_3]))).toThrow(/already/);
  });

  it('an expression the runner would expand before the shell reads the script', () => {
    const step = [...STEP_3.slice(0, 2), '          echo "${{ github.sha }}"', ...STEP_3.slice(2)];
    expect(() => extractor.extractQuickStart(guideWith([STEP_1, STEP_2, step]))).toThrow(/\$\{\{/);
  });

  it('a gate step that moves out of the workspace', () => {
    const step = [STEP_3[0], '        working-directory: ${{ runner.temp }}', ...STEP_3.slice(1)];
    expect(() => extractor.extractQuickStart(guideWith([STEP_1, STEP_2, step]))).toThrow(/working-directory/);
  });

  it('a scan step that no longer starts from runner.temp', () => {
    const step = [STEP_1[0], STEP_1[2]];
    expect(() => extractor.extractQuickStart(guideWith([step, STEP_2, STEP_3]))).toThrow(/working-directory/);
  });

  it('a scan step that does not run the CLI exactly once', () => {
    const none = replaceLine(STEP_1, 2, '        run: npx other-tool detect "$GITHUB_WORKSPACE"');
    expect(() => extractor.extractQuickStart(guideWith([none, STEP_2, STEP_3]))).toThrow(/exactly once/);
    const twice = replaceLine(STEP_1, 2, `${STEP_1[2]} && npx opena2a-cli status "$GITHUB_WORKSPACE"`);
    expect(() => extractor.extractQuickStart(guideWith([twice, STEP_2, STEP_3]))).toThrow(/exactly once/);
  });

  it('a fourth step script', () => {
    const extra = ['      - name: Extra', '        run: echo extra'];
    expect(() => extractor.extractQuickStart(guideWith([STEP_1, STEP_2, STEP_3, extra]))).toThrow(/three/);
  });

  it('a plain-scalar script holding " #", which YAML cuts as a comment', () => {
    const step = replaceLine(STEP_1, 2, `${STEP_1[2]} # keep`);
    expect(() => extractor.extractQuickStart(guideWith([step, STEP_2, STEP_3]))).toThrow(/comment/);
  });

  it('a quoted or folded script, whose text the extractor does not read', () => {
    const quoted = replaceLine(STEP_1, 2, '        run: "npx opena2a-cli detect ."');
    expect(() => extractor.extractQuickStart(guideWith([quoted, STEP_2, STEP_3]))).toThrow(/not read/);
    const folded = replaceLine(STEP_3, 1, '        run: >');
    expect(() => extractor.extractQuickStart(guideWith([STEP_1, STEP_2, folded]))).toThrow(/not read/);
    const strip = replaceLine(STEP_3, 1, '        run: |-');
    expect(() => extractor.extractQuickStart(guideWith([STEP_1, STEP_2, strip]))).toThrow(/not read/);
  });

  it('a step key the workflow does not reproduce (shell, env, if, continue-on-error)', () => {
    for (const key of ['shell: sh', 'env:', 'if: always()', 'continue-on-error: true']) {
      const step = [STEP_3[0], `        ${key}`, ...STEP_3.slice(1)];
      expect(() => extractor.extractQuickStart(guideWith([STEP_1, STEP_2, step])), key).toThrow(/not reproduced/);
    }
  });
});

describe('extract-recipe command line', () => {
  it('writes the block and each step script byte-equal to what it read, and says so', () => {
    const out = path.join(scratch, 'recipe');
    const res = spawnSync(process.execPath, [EXTRACTOR, GUIDE, out], {
      cwd: REPO_ROOT,
      encoding: 'utf-8',
      env: { PATH: process.env.PATH ?? '' },
    });
    expect(res.status, res.stderr).toBe(0);
    const r = extractor.extractQuickStart(readGuide());
    expect(fs.readFileSync(path.join(out, 'quick-start.yml'), 'utf-8')).toBe(r.block);
    r.steps.forEach((s, i) => {
      expect(fs.readFileSync(path.join(out, `step-${i + 1}.sh`), 'utf-8')).toBe(s.run);
    });
    expect(fs.readdirSync(out).sort()).toEqual(['quick-start.yml', 'step-1.sh', 'step-2.sh', 'step-3.sh']);
    expect(res.stdout).toContain('byte-equal to the guide');
  });

  it('exits 1 and writes nothing for a guide it refuses', () => {
    const guide = path.join(scratch, 'refused.md');
    const step = [...STEP_3.slice(0, 2), '          echo "${{ github.sha }}"', ...STEP_3.slice(2)];
    fs.writeFileSync(guide, guideWith([STEP_1, STEP_2, step]));
    const out = path.join(scratch, 'refused-out');
    const res = spawnSync(process.execPath, [EXTRACTOR, guide, out], {
      cwd: REPO_ROOT,
      encoding: 'utf-8',
      env: { PATH: process.env.PATH ?? '' },
    });
    expect(res.status).toBe(1);
    expect(res.stderr).toContain('${{');
    expect(fs.existsSync(out)).toBe(false);
  });

  it('exits 2 on a usage error', () => {
    const res = spawnSync(process.execPath, [EXTRACTOR, GUIDE], {
      cwd: REPO_ROOT,
      encoding: 'utf-8',
      env: { PATH: process.env.PATH ?? '' },
    });
    expect(res.status).toBe(2);
  });
});
