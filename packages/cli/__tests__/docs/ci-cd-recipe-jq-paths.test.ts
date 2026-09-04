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
 * A grep for the right string would not have caught that, and would not catch
 * the next drift either: the defect is that a jq path in the doc and the JSON
 * shape the scanner emits disagreed, and only one of those two lives in this
 * repo. So the pin is measured, not restated — the paths are EXTRACTED from the
 * doc and resolved with the same `jq` the recipe runs, against the output of the
 * hackmyagent build packages/cli/package.json pins.
 */

const DOC_REL = 'docs/use-cases/ci-cd.md';
const STEP_NAME = 'HackMyAgent security scan';

/**
 * Severity counts as `hackmyagent secure --ci --format json` emits them.
 *
 * This constant is the one place the shape is written down: AC1 holds the doc
 * to it, AC3 builds its stand-in scan JSON from it, and AC4 checks it against
 * what the pinned CLI actually prints. If the scanner ever moves the counts,
 * AC4 goes red first — the constant is pinned to a measurement, not trusted.
 */
const COUNTS = { critical: '.counts.critical', high: '.counts.high' } as const;

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

/** The `<path>` of every `jq -r '<path>'` in a run body, in source order. */
function jqRawPaths(body: string): string[] {
  return [...body.matchAll(/jq\s+(?:-r|--raw-output)\s+'([^']*)'/g)].map((m) => m[1]);
}

/** `shellVar -> jq path` for every `var=$(jq -r '<path>' ...)` in a run body. */
function jqRawAssignments(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/^\s*(\w+)=\$\(\s*jq\s+(?:-r|--raw-output)\s+'([^']*)'/gm)) {
    out[m[1]] = m[2];
  }
  return out;
}

/** Write `value` at a dotted jq path, creating the objects on the way down. */
function setJqPath(root: Record<string, unknown>, jqPath: string, value: unknown): void {
  const keys = jqPath.replace(/^\./, '').split('.');
  let cur = root;
  for (const key of keys.slice(0, -1)) {
    if (typeof cur[key] !== 'object' || cur[key] === null) cur[key] = {};
    cur = cur[key] as Record<string, unknown>;
  }
  cur[keys[keys.length - 1]] = value;
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
 * Resolve a jq path against a JSON document with the real `jq`, exactly as the
 * recipe does. Returns jq's raw stdout, so a missing key comes back as the
 * literal string `null` — which is the failure this whole file exists to catch.
 */
function jqResolve(json: string, jqPath: string): string {
  const r = spawnSync('jq', ['-r', jqPath], { input: json, encoding: 'utf-8' });
  if (r.status !== 0) throw new Error(`jq -r '${jqPath}' failed: ${r.stderr?.trim()}`);
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
 * A scan report with `critical` criticals. The findings array is held identical
 * across both AC3 fixtures on purpose: the only thing that may differ between
 * the passing and failing run is the count the gate reads, so a difference in
 * exit code is attributable to that number and nothing else.
 */
function scanJson(critical: number): string {
  const json: Record<string, unknown> = {
    score: 0,
    maxScore: 100,
    findings: [
      {
        checkId: 'CRED-002',
        severity: 'critical',
        passed: false,
        message: 'Hardcoded API key',
        file: 'src/config.ts',
      },
    ],
  };
  setJqPath(json, COUNTS.critical, critical);
  setJqPath(json, COUNTS.high, 0);
  return JSON.stringify(json);
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
      "const client = createClient({ apiKey: process.env.API_KEY });\nmodule.exports = { client };\n",
    );
    const argv = [scannerEntry(installedScannerDir()), 'secure', '--ci', '--format', 'json'];
    const r = spawnSync(process.execPath, argv, {
      cwd: dir,
      encoding: 'utf-8',
      timeout: 150_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    if (r.error) throw r.error;
    // A non-zero status is expected — `--ci` fails the run on findings. Only
    // the absence of parseable JSON on stdout is a problem here.
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

describe(`${DOC_REL} — the HackMyAgent gate reads the counts the scanner emits`, () => {
  it('OPA-05.AC1 the scan step reads .counts.critical and .counts.high', () => {
    const body = hmaScanStepBody(readDoc());
    expect(jqRawPaths(body)).toEqual([COUNTS.critical, COUNTS.high]);
    expect(jqRawAssignments(body)).toEqual({ critical: COUNTS.critical, high: COUNTS.high });
  });

  it('OPA-05.AC2 no .summary.critical or .summary.high anywhere in the doc', () => {
    const markdown = readDoc();
    expect(markdown).not.toContain('.summary.critical');
    expect(markdown).not.toContain('.summary.high');
  });

  it('OPA-05.AC3 the gate exits non-zero on a scan report with one critical', () => {
    expect(haveJq(), JQ_REQUIRED).toBe(true);
    expect(
      runGate(scanJson(1)),
      'the gate passed a scan report carrying a critical finding — a copied recipe would ship it',
    ).not.toBe(0);
  });

  it('OPA-05.AC3 the gate exits zero on the same report with no criticals', () => {
    expect(haveJq(), JQ_REQUIRED).toBe(true);
    expect(runGate(scanJson(0))).toBe(0);
  });

  it(
    'OPA-05.AC4 every jq path the recipe reads resolves in the pinned scanner\'s --ci --format json output',
    () => {
      expect(haveJq(), JQ_REQUIRED).toBe(true);
      const paths = jqRawPaths(hmaScanStepBody(readDoc()));
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
