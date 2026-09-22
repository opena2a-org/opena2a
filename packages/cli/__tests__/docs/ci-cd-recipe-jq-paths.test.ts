import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/**
 * The HackMyAgent recipe in docs/use-cases/ci-cd.md gated on `.summary.critical`,
 * a key the scanner does not emit. `jq -r` prints the literal `null` for a
 * missing key, `[ "null" -gt 0 ]` is a bash arithmetic error that evaluates
 * false, and an `if` whose condition tests false exits zero — so the documented
 * job passed with critical findings present. Anyone who copied the recipe got a
 * gate that could not fail.
 *
 * `.counts.critical` was the next guess and is just as absent: `hackmyagent
 * secure --ci --format json` emits no top-level count object at all. It emits
 * `findings[]`, whose items carry a lowercase `severity` — so the counts are
 * derived, exactly as the `opena2a review` steps elsewhere in the same document
 * already derive theirs.
 *
 * A grep for the right string would not have caught either wrong guess, and
 * would not catch the next drift either: the defect is that a jq path in the doc
 * and the JSON shape the scanner emits disagreed, and only one of those two
 * lives in this repo. So the pin is measured, not restated — the paths are
 * EXTRACTED from the doc and resolved with the same `jq` the recipe runs,
 * against the output of the hackmyagent build packages/cli/package.json pins.
 */

const DOC_REL = 'docs/use-cases/ci-cd.md';
const STEP_NAME = 'HackMyAgent security scan';

/**
 * The severity counts as the recipe derives them: straight out of `findings[]`,
 * naming no top-level count key, because the scanner emits none.
 *
 * This constant is the one place the expressions are written down: AC1 holds the
 * doc to them and AC3 builds its stand-in scan reports to match. Nothing here
 * asserts that the scanner agrees — AC4 measures that against the pinned CLI, so
 * a shape change goes red there rather than being assumed away here.
 */
const COUNT_EXPR = {
  critical: '[.findings[] | select(.severity == "critical")] | length',
  high: '[.findings[] | select(.severity == "high")] | length',
} as const;

/**
 * A jq path that reads a severity count out of a top-level object — `.summary.critical`,
 * `.counts.high`. Both spellings have shipped in this recipe and neither exists in the
 * scanner's output, so naming one is the defect itself, not a stylistic choice.
 *
 * Checked against the paths the doc actually carries rather than against
 * {@link COUNT_EXPR}, and checked before them: the way this recipe went wrong the
 * second time was the doc and the constant agreeing with each other while both
 * disagreed with the scanner, which an equality assertion alone stays green through.
 */
const TOP_LEVEL_COUNT_PATH = /^\s*\.[A-Za-z_]\w*\s*\.\s*(?:critical|high|medium|low)\b/;

/** Repo root: the nearest ancestor whose package.json declares workspaces. */
function repoRoot(): string {
  let dir = __dirname;
  while (dir !== path.parse(dir).root) {
    const manifest = path.join(dir, 'package.json');
    if (fs.existsSync(manifest)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(manifest, 'utf-8'));
        if (Array.isArray(parsed.workspaces)) return dir;
      } catch {
        // Unparseable manifest on the way up: keep walking.
      }
    }
    dir = path.dirname(dir);
  }
  throw new Error('repository root not found (no package.json with "workspaces" above this test)');
}

function readDoc(): string {
  return fs.readFileSync(path.join(repoRoot(), DOC_REL), 'utf-8');
}

/**
 * The `run:` body of the recipe's `- name: HackMyAgent security scan` step,
 * dedented to column zero so it can be handed to bash as written.
 *
 * Located by step name rather than by line number: the doc carries five other
 * `jq` invocations in other steps, and a line-addressed extractor would follow
 * the wrong ones the first time anything above line 294 grows a paragraph.
 */
function hmaScanStepBody(markdown: string): string {
  const lines = markdown.split('\n');
  const start = lines.findIndex((l) => new RegExp(`^\\s*-\\s+name:\\s*${STEP_NAME}\\s*$`).test(l));
  if (start === -1) throw new Error(`${DOC_REL}: no "- name: ${STEP_NAME}" step`);

  let runIdx = -1;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\s*-\s+name:/.test(lines[i])) break;
    if (/^\s*run:\s*\|\s*$/.test(lines[i])) {
      runIdx = i;
      break;
    }
  }
  if (runIdx === -1) throw new Error(`${DOC_REL}: the "${STEP_NAME}" step has no "run: |" body`);

  const body: string[] = [];
  let indent: string | null = null;
  for (let i = runIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '') {
      body.push('');
      continue;
    }
    if (indent === null) indent = /^\s*/.exec(line)?.[0] ?? '';
    if (!line.startsWith(indent)) break;
    body.push(line.slice(indent.length));
  }
  while (body.length > 0 && body[body.length - 1] === '') body.pop();
  if (body.length === 0) throw new Error(`${DOC_REL}: the "${STEP_NAME}" step has an empty run body`);
  return body.join('\n');
}

/** The `<expr>` of every `jq -r '<expr>'` in a run body, in source order. */
function jqRawPaths(body: string): string[] {
  return [...body.matchAll(/jq\s+(?:-r|--raw-output)\s+'([^']*)'/g)].map((m) => m[1]);
}

/** `shellVar -> jq expr` for every `var=$(jq -r '<expr>' ...)` in a run body. */
function jqRawAssignments(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/^\s*(\w+)=\$\(\s*jq\s+(?:-r|--raw-output)\s+'([^']*)'/gm)) {
    out[m[1]] = m[2];
  }
  return out;
}

/** The severity literals the recipe selects on, e.g. `critical` and `high`. */
function selectedSeverities(body: string): string[] {
  return [...new Set([...body.matchAll(/\.severity\s*==\s*"([^"]+)"/g)].map((m) => m[1]))].sort();
}

/**
 * `jq` is the tool the recipe itself runs, so it is what resolves the paths
 * here too — a reimplementation in TypeScript would be a second opinion about
 * jq semantics, and the recipe does not run that one.
 */
const JQ_REQUIRED =
  'jq is required to run the recipe\'s own gate (`apt-get install jq` / `brew install jq`); ' +
  'it is preinstalled on the ubuntu-latest runners this suite runs on';

function haveJq(): boolean {
  return spawnSync('jq', ['--version'], { encoding: 'utf-8' }).status === 0;
}

/**
 * Resolve a jq expression against a JSON document with the real `jq -r`, exactly
 * as the recipe does. A key the document does not carry comes back as the
 * literal string `null`; an array the document does not carry makes jq exit
 * non-zero. Both are the failure this whole file exists to catch, so both are
 * surfaced rather than smoothed over.
 */
function jqResolve(json: string, jqPath: string): string {
  const r = spawnSync('jq', ['-r', jqPath], { input: json, encoding: 'utf-8' });
  if (r.status !== 0) {
    throw new Error(
      `jq -r '${jqPath}' failed against the scan report — the recipe reads a shape the ` +
        `scanner does not emit: ${r.stderr?.trim()}`,
    );
  }
  return r.stdout.trim();
}

/** Like {@link jqResolve} but compact, for reading structure back as JSON. */
function jqCompact(json: string, expr: string): string {
  const r = spawnSync('jq', ['-c', expr], { input: json, encoding: 'utf-8' });
  if (r.status !== 0) throw new Error(`jq -c '${expr}' failed: ${r.stderr?.trim()}`);
  return r.stdout.trim();
}

// --- AC3: driving the gate body ------------------------------------------

/**
 * The gate as bash runs it: the recipe's body with the scanner invocation
 * dropped, because the fixture stands in for that one line's output. The jq
 * reads, the `-gt 0` test and the `exit 1` all run as written in the doc.
 */
function gateScript(body: string): string {
  return body
    .split('\n')
    .filter((l) => !/\bhackmyagent\b/.test(l))
    .join('\n');
}

/**
 * A scan report carrying `criticals` critical findings, in the shape the pinned
 * scanner emits: a `findings[]` of items with a lowercase `severity`, and no
 * top-level count object, because 0.30.0 emits none.
 *
 * Everything outside the critical entries is held identical across both AC3
 * reports — same trailing finding, same scores, same coverage — so a difference
 * in exit code is attributable to the critical count and nothing else. The count
 * now *is* the findings array, which is why the array is what varies.
 */
function scanReport(criticals: number): string {
  const critical = {
    checkId: 'CRED-002',
    name: 'Private Key Files',
    category: 'credentials',
    severity: 'critical',
    passed: false,
    message: 'Private key committed to the repository',
    file: 'deploy/id_rsa',
  };
  return JSON.stringify({
    hackmyagentVersion: '0.0.0-fixture',
    projectType: 'node',
    findings: [
      ...Array.from({ length: criticals }, () => critical),
      {
        checkId: 'GIT-001',
        name: 'Missing .gitignore',
        category: 'git',
        severity: 'low',
        passed: false,
        message: 'Create .gitignore to protect sensitive files',
        file: '.gitignore',
      },
    ],
    score: 71,
    rawScore: 71,
    maxScore: 100,
    coverage: { checksRun: 46, checksPassed: 45 },
  });
}

/** Run the recipe's gate over a scan report; returns its exit code. */
function runGate(report: string): number {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-cd-recipe-gate-'));
  try {
    fs.writeFileSync(path.join(dir, 'hma.json'), report);
    const r = spawnSync('bash', ['-c', gateScript(hmaScanStepBody(readDoc()))], {
      cwd: dir,
      encoding: 'utf-8',
    });
    if (r.error) throw r.error;
    if (r.status === null) throw new Error(`gate did not exit: ${r.signal ?? 'unknown signal'}`);
    return r.status;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// --- AC4/AC5: the pinned scanner -----------------------------------------

/** The hackmyagent version packages/cli/package.json pins, read from the file. */
function pinnedVersion(): string {
  const manifest = path.join(repoRoot(), 'packages', 'cli', 'package.json');
  const pkg = JSON.parse(fs.readFileSync(manifest, 'utf-8'));
  const declared = pkg.dependencies?.hackmyagent;
  if (typeof declared !== 'string') {
    throw new Error(`${manifest} declares no hackmyagent dependency`);
  }
  return declared;
}

/**
 * The installed copy of the scanner. Deliberately fails rather than skips when
 * it is absent: this test is the only thing measuring the JSON shape the doc
 * depends on, and a guard that quietly disappears when a dependency is missing
 * is the same green-that-measured-nothing the recipe already shipped once.
 * Every environment that can run this suite has run `npm ci`, which installs it.
 */
function installedScannerDir(): string {
  const candidates = [
    path.join(repoRoot(), 'packages', 'cli', 'node_modules', 'hackmyagent'),
    path.join(repoRoot(), 'node_modules', 'hackmyagent'),
  ];
  const found = candidates.find((d) => fs.existsSync(path.join(d, 'package.json')));
  if (!found) {
    throw new Error(
      `hackmyagent is not installed (looked in ${candidates.join(', ')}). ` +
        'Run `npm ci` — this test measures the pinned build\'s JSON output and must not be skipped.',
    );
  }
  return found;
}

function scannerManifest(dir: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf-8'));
}

function scannerEntry(dir: string): string {
  const bin = scannerManifest(dir).bin;
  const rel =
    typeof bin === 'string'
      ? bin
      : ((bin as Record<string, string> | undefined)?.hackmyagent ??
        Object.values((bin as Record<string, string> | undefined) ?? {})[0]);
  if (typeof rel !== 'string') throw new Error(`${dir}/package.json declares no bin entry`);
  return path.join(dir, rel);
}

/**
 * `hackmyagent secure --ci --format json` over a throwaway project, run with the
 * recipe's own argv (no path argument, scanning the working directory) so the
 * output being measured is the output the documented command produces.
 */
function scanFixture(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-cd-recipe-scan-'));
  try {
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({ name: 'ci-cd-recipe-fixture', version: '0.0.0', private: true }, null, 2),
    );
    fs.writeFileSync(
      path.join(dir, 'agent.js'),
      "const cp = require('node:child_process');\n" +
        'function run(userInput) {\n' +
        "  return cp.exec('ls ' + userInput);\n" +
        '}\n' +
        'module.exports = { run };\n',
    );
    const argv = [scannerEntry(installedScannerDir()), 'secure', '--ci', '--format', 'json'];
    const r = spawnSync(process.execPath, argv, {
      cwd: dir,
      encoding: 'utf-8',
      timeout: 150_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    if (r.error) throw r.error;
    // A non-zero status is allowed — `--ci` is free to fail the run on findings.
    // Only the absence of parseable JSON on stdout is a problem here.
    const stdout = r.stdout ?? '';
    const first = stdout.indexOf('{');
    const last = stdout.lastIndexOf('}');
    if (first === -1 || last <= first) {
      throw new Error(
        `hackmyagent secure --ci --format json printed no JSON (exit ${r.status}).\n` +
          `stdout: ${stdout.slice(0, 500)}\nstderr: ${(r.stderr ?? '').slice(0, 500)}`,
      );
    }
    return stdout.slice(first, last + 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe(`${DOC_REL} — the HackMyAgent gate counts the findings the scanner emits`, () => {
  it('OPA-05.AC1 the scan step derives the counts from .findings[], naming no top-level count key', () => {
    const body = hmaScanStepBody(readDoc());

    for (const jqPath of jqRawPaths(body)) {
      expect(
        jqPath,
        'the step reads its counts from a top-level object; the scanner emits none, so this ' +
          'resolves to the literal "null" and the gate stops being able to fail',
      ).not.toMatch(TOP_LEVEL_COUNT_PATH);
    }
    expect(body).not.toContain('.counts');
    expect(body).not.toContain('.summary');

    expect(jqRawPaths(body)).toEqual([COUNT_EXPR.critical, COUNT_EXPR.high]);
    expect(jqRawAssignments(body)).toEqual({
      critical: COUNT_EXPR.critical,
      high: COUNT_EXPR.high,
    });
  });

  it('OPA-05.AC2 no .summary.critical or .summary.high anywhere in the doc', () => {
    const markdown = readDoc();
    expect(markdown).not.toContain('.summary.critical');
    expect(markdown).not.toContain('.summary.high');
  });

  it('OPA-05.AC3 the gate exits non-zero on a scan report with one critical finding', () => {
    expect(haveJq(), JQ_REQUIRED).toBe(true);
    expect(
      runGate(scanReport(1)),
      'the gate passed a scan report carrying a critical finding — a copied recipe would ship it',
    ).not.toBe(0);
  });

  it('OPA-05.AC3 the gate exits zero on the same report with no critical findings', () => {
    expect(haveJq(), JQ_REQUIRED).toBe(true);
    expect(runGate(scanReport(0))).toBe(0);
  });

  it(
    'OPA-05.AC4 every jq path the recipe reads resolves in the pinned scanner\'s --ci --format json output',
    () => {
      expect(haveJq(), JQ_REQUIRED).toBe(true);
      const body = hmaScanStepBody(readDoc());
      const paths = jqRawPaths(body);
      expect(paths.length).toBeGreaterThan(0);

      const report = scanFixture();

      for (const jqPath of paths) {
        const resolved = jqResolve(report, jqPath);
        expect(
          resolved,
          `hackmyagent@${pinnedVersion()} secure --ci --format json does not carry ${jqPath} ` +
            '— the recipe would read the literal "null" and the gate could not fail',
        ).not.toBe('null');
        expect(resolved).not.toBe('');
      }

      // Resolving is not enough on its own: `[…] | length` counts zero just as
      // happily over findings whose severity is spelled some other way, which is
      // the same gate-that-cannot-fail wearing a number instead of a `null`. So
      // the severity vocabulary the recipe selects on is measured too.
      const emitted: string[] = JSON.parse(
        jqCompact(
          report,
          '[(.findings[]? | .severity), (.allFindings[]? | .severity)] | map(select(. != null)) | unique',
        ),
      );
      expect(
        emitted,
        `hackmyagent@${pinnedVersion()} emitted no finding carrying a "severity" field`,
      ).not.toHaveLength(0);
      for (const severity of selectedSeverities(body)) {
        expect(
          emitted,
          `the recipe selects findings with severity "${severity}", which hackmyagent@${pinnedVersion()} ` +
            `never emits (it emits ${emitted.join(', ')}) — the count would sit at 0 forever`,
        ).toContain(severity);
      }
    },
    180_000,
  );

  it('OPA-05.AC5 the scanner under test is the exact build packages/cli/package.json pins', () => {
    const pinned = pinnedVersion();
    // An exact pin, not a range: a caret would let the measured build drift away
    // from the declared one without the declaration changing.
    expect(pinned).toMatch(/^\d+\.\d+\.\d+(?:-[\w.]+)?$/);
    expect(scannerManifest(installedScannerDir()).version).toBe(pinned);
  });
});
