import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/**
 * docs/use-cases/mcp-server-author.md described a different tool from the
 * ai-trust that `npx ai-trust` runs. Its CI recipe ran
 * `ai-trust check . --format json`: ai-trust registers no `--format` option, so
 * the step died on `unknown option '--format'` before it read a score. ai-trust
 * takes `.` as a package name, not a directory, and the registry has no record
 * of it: with `--no-scan` it is reported not found; without `--no-scan`
 * ai-trust hands it to `npm pack`, which packs the current directory and runs
 * its `prepack` script if it has one, and then exits 1 because the packed
 * package is not named `.`. Step 4 said the rating was "calculated locally"
 * from six weighted factors with "no data uploaded". The rating ai-trust prints
 * is the OpenA2A Registry's record of the published package, or the score of a
 * fresh scan of that package, and a scan reports its verdict and score to the
 * registry.
 *
 * The options are measured, not restated: every `npx ai-trust` invocation is
 * extracted from the doc, and each option it passes is looked up in the help
 * that the installed ai-trust prints. A help-derived set is a second opinion
 * about the parser, so it is held to agree with the real parser on the option
 * this recipe shipped with. The gate itself runs as bash runs it, with a
 * stand-in for `npx` that prints a result in the `check --json` shape, because
 * the real command needs the network.
 */

const DOC_REL = 'docs/use-cases/mcp-server-author.md';
const GATE_STEP = 'Trust score gate';

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

/** The text from a `## ` heading that starts with `prefix` up to the next `## ` heading. */
function section(markdown: string, prefix: string): string {
  const lines = markdown.split('\n');
  const start = lines.findIndex((l) => l.startsWith(prefix));
  if (start === -1) throw new Error(`${DOC_REL}: no heading starting with "${prefix}"`);
  const end = lines.findIndex((l, i) => i > start && l.startsWith('## '));
  return lines.slice(start, end === -1 ? lines.length : end).join('\n');
}

// --- the documented invocations ------------------------------------------

/** One documented `npx ai-trust` command line, as the words after the binary. */
interface Invocation {
  line: number;
  words: string[];
}

const NPX_AI_TRUST = /npx (?:-y )?ai-trust(?=$|[\s`"'|])/g;

// Tokens that end the invocation on a documented line: shell operators,
// comments, and markdown table borders.
const TERMINATOR = /^[|>#;&)]/;

function invocations(markdown: string): Invocation[] {
  const out: Invocation[] = [];
  markdown.split('\n').forEach((text, i) => {
    for (const m of text.matchAll(NPX_AI_TRUST)) {
      const rest = text.slice((m.index ?? 0) + m[0].length);
      const words: string[] = [];
      for (const raw of rest.split(/\s+/)) {
        if (!raw) continue;
        if (TERMINATOR.test(raw)) break;
        // A closing backtick ends an inline-code invocation: prose after the
        // code span is never part of the command.
        const backtick = raw.indexOf('`');
        const word = backtick === -1 ? raw : raw.slice(0, backtick);
        if (word) words.push(word);
        if (backtick !== -1) break;
      }
      out.push({ line: i + 1, words });
    }
  });
  return out;
}

/** The package the guide registers in Step 5, which is the package it publishes. */
function claimedPackage(markdown: string): string {
  const m = /npx opena2a-cli claim (\S+)/.exec(markdown);
  if (!m) throw new Error(`${DOC_REL}: no \`npx opena2a-cli claim <package>\` line`);
  return m[1];
}

// --- the installed ai-trust ----------------------------------------------

/**
 * The installed copy of ai-trust. Fails rather than skips when it is absent:
 * this test is the only thing measuring the options the doc passes, and a guard
 * that disappears with a missing dependency measures nothing. Every environment
 * that runs this suite has run `npm ci`, which installs it.
 */
function aiTrustDir(): string {
  const candidates = [
    path.join(repoRoot(), 'packages', 'cli', 'node_modules', 'ai-trust'),
    path.join(repoRoot(), 'node_modules', 'ai-trust'),
  ];
  const found = candidates.find((d) => fs.existsSync(path.join(d, 'package.json')));
  if (!found) {
    throw new Error(
      `ai-trust is not installed (looked in ${candidates.join(', ')}). ` +
        'Run `npm ci` — this test reads the installed build\'s options and must not be skipped.',
    );
  }
  return found;
}

function aiTrustManifest(): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(path.join(aiTrustDir(), 'package.json'), 'utf-8'));
}

function aiTrustEntry(): string {
  const bin = aiTrustManifest().bin;
  const rel =
    typeof bin === 'string'
      ? bin
      : ((bin as Record<string, string> | undefined)?.['ai-trust'] ??
        Object.values((bin as Record<string, string> | undefined) ?? {})[0]);
  if (typeof rel !== 'string') throw new Error(`${aiTrustDir()}/package.json declares no bin entry`);
  return path.join(aiTrustDir(), rel);
}

function aiTrustLabel(): string {
  return `ai-trust@${String(aiTrustManifest().version)}`;
}

function runAiTrust(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [aiTrustEntry(), ...args], {
    encoding: 'utf-8',
    env: { ...process.env, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
    timeout: 30_000,
  });
  if (r.error) throw r.error;
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

interface HelpSections {
  options: Set<string>;
  commands: Set<string>;
}

/**
 * The option flags and command names a commander help screen lists. Option
 * rows start two spaces in with a dash (`  -t, --type <type>  …`), command rows
 * two spaces in with a name; description lines wrap deeper and match neither.
 */
function helpFor(args: string[]): HelpSections {
  const r = runAiTrust([...args, '--help']);
  if (r.status !== 0) {
    throw new Error(`${aiTrustLabel()} ${[...args, '--help'].join(' ')} exited ${r.status}: ${r.stderr.slice(0, 500)}`);
  }
  const options = new Set<string>();
  const commands = new Set<string>();
  let block = '';
  for (const line of r.stdout.split('\n')) {
    const header = /^(\w[\w ]*):\s*$/.exec(line);
    if (header) {
      block = header[1];
      continue;
    }
    if (block === 'Options') {
      const m = /^ {2}(-\S.*?)(?: {2,}|$)/.exec(line);
      if (!m) continue;
      for (const part of m[1].split(/,\s*/)) {
        const flag = part.trim().split(/\s/)[0];
        if (/^--?[A-Za-z]/.test(flag)) options.add(flag);
      }
    } else if (block === 'Commands') {
      const m = /^ {2}([a-z][\w-]*)\b/.exec(line);
      if (m) commands.add(m[1]);
    }
  }
  return { options, commands };
}

/** Every option `ai-trust <sub>` accepts: its own plus the program-level ones. */
function optionsFor(sub: string): Set<string> {
  return new Set([...helpFor([]).options, ...helpFor([sub]).options]);
}

// --- driving the gate body -----------------------------------------------

/**
 * The `run:` body of the recipe's `- name: Trust score gate` step, dedented to
 * column zero so it can be handed to bash as written. Located by step name, not
 * by line number, so a paragraph added above it does not move the target.
 */
function gateStepBody(markdown: string): string {
  const lines = markdown.split('\n');
  const start = lines.findIndex((l) => new RegExp(`^\\s*-\\s+name:\\s*${GATE_STEP}\\s*$`).test(l));
  if (start === -1) throw new Error(`${DOC_REL}: no "- name: ${GATE_STEP}" step`);

  let runIdx = -1;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\s*-\s+name:/.test(lines[i])) break;
    if (/^\s*run:\s*\|\s*$/.test(lines[i])) {
      runIdx = i;
      break;
    }
  }
  if (runIdx === -1) throw new Error(`${DOC_REL}: the "${GATE_STEP}" step has no "run: |" body`);

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
  if (body.length === 0) throw new Error(`${DOC_REL}: the "${GATE_STEP}" step has an empty run body`);
  return body.join('\n');
}

const JQ_REQUIRED =
  'jq is required to run the recipe\'s own gate (`apt-get install jq` / `brew install jq`); ' +
  'it is preinstalled on the ubuntu-latest runners this suite runs on';

function haveJq(): boolean {
  return spawnSync('jq', ['--version'], { encoding: 'utf-8' }).status === 0;
}

/**
 * A registry answer in the shape `ai-trust check <package> --no-scan --json`
 * prints for a package the registry holds (measured against ai-trust 0.7.6 on
 * @modelcontextprotocol/server-filesystem): no factor breakdown, one
 * `trustScore` between 0 and 1.
 */
function registryAnswer(trustScore: number, verdict: string): Record<string, unknown> {
  return {
    name: '@myorg/mcp-server-tools',
    source: 'registry',
    found: true,
    packageType: 'mcp_server',
    verdict,
    trustLevel: 3,
    trustScore,
  };
}

/** The not-found shape the same command prints for a package the registry has no record of. */
const NOT_FOUND = {
  name: '@myorg/mcp-server-tools',
  found: false,
  error: 'Package "@myorg/mcp-server-tools" not found in the OpenA2A Registry.',
  nextSteps: ['ai-trust check @myorg/mcp-server-tools --scan-if-missing'],
  ecosystem: 'npm',
};

/**
 * Run the recipe's gate under `bash -e`, the shell GitHub Actions uses for a
 * `run:` step that names none, with `npx` replaced by a stand-in that prints
 * `stdout` and exits `exitCode`. Returns the gate's exit code and the argv the
 * stand-in received.
 */
function runGate(stdout: string, exitCode: number): { status: number; argv: string[] } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-author-gate-'));
  try {
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(dir, 'result.out'), stdout);
    fs.writeFileSync(
      path.join(bin, 'npx'),
      '#!/bin/sh\n' +
        'for a in "$@"; do printf \'%s\\n\' "$a"; done > "$STANDIN_DIR/argv"\n' +
        'cat "$STANDIN_DIR/result.out"\n' +
        'exit "$STANDIN_EXIT"\n',
      { mode: 0o755 },
    );
    const r = spawnSync('bash', ['-e', '-c', gateStepBody(readDoc())], {
      cwd: dir,
      encoding: 'utf-8',
      env: {
        ...process.env,
        PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
        STANDIN_DIR: dir,
        STANDIN_EXIT: String(exitCode),
      },
    });
    if (r.error) throw r.error;
    if (r.status === null) throw new Error(`gate did not exit: ${r.signal ?? 'unknown signal'}`);
    const argvFile = path.join(dir, 'argv');
    const argv = fs.existsSync(argvFile)
      ? fs.readFileSync(argvFile, 'utf-8').split('\n').filter((a) => a !== '')
      : [];
    return { status: r.status, argv };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe(`${DOC_REL} — ai-trust is described as the tool npx runs`, () => {
  it('the help-derived option set agrees with the real parser on the option the recipe shipped with', () => {
    const known = optionsFor('check');
    expect(known.has('--json'), `${aiTrustLabel()} check: --json is not in the parsed help`).toBe(true);
    expect(known.has('--no-scan'), `${aiTrustLabel()} check: --no-scan is not in the parsed help`).toBe(true);

    // The registry URL points at a closed local port, so the command stays
    // offline even on a build that accepts every option given here.
    const r = runAiTrust(['check', '.', '--no-scan', '--registry-url', 'http://127.0.0.1:9', '--format', 'json']);
    const refused = /unknown option '--format'/i.test(r.stderr);
    expect(
      known.has('--format'),
      `${aiTrustLabel()}: the parsed help and the real parser disagree about --format ` +
        `(parser ${refused ? 'refused' : 'accepted'} it; stderr: ${r.stderr.slice(0, 300)})`,
    ).toBe(!refused);
  });

  it('every option a documented `npx ai-trust` invocation passes is one the installed ai-trust registers', () => {
    const calls = invocations(readDoc());
    expect(calls.length, `${DOC_REL}: no \`npx ai-trust\` invocations found`).toBeGreaterThan(0);

    const commands = helpFor([]).commands;
    for (const call of calls) {
      const [sub, ...rest] = call.words;
      expect(commands, `${DOC_REL}:${call.line}: ${aiTrustLabel()} has no "${sub}" command`).toContain(sub);
      const known = optionsFor(sub);
      for (const word of rest.filter((w) => w.startsWith('-'))) {
        const flag = word.split('=')[0];
        expect(
          known.has(flag),
          `${DOC_REL}:${call.line}: ${aiTrustLabel()} ${sub} registers no ${flag} ` +
            `(it registers ${[...known].sort().join(', ')})`,
        ).toBe(true);
      }
    }
  });

  it('`ai-trust check` is given the published package the guide claims, not a directory or a server name', () => {
    const doc = readDoc();
    const pkg = claimedPackage(doc);
    const checks = invocations(doc).filter((c) => c.words[0] === 'check');
    expect(checks.length, `${DOC_REL}: no \`npx ai-trust check\` invocations found`).toBeGreaterThan(0);
    for (const call of checks) {
      const operand = call.words.slice(1).find((w) => !w.startsWith('-'));
      expect(
        operand,
        `${DOC_REL}:${call.line}: ai-trust check looks up a published package by name; ` +
          `this line passes "${operand}" instead of ${pkg}`,
      ).toBe(pkg);
    }
  });

  it('Step 4 says the rating is the registry\'s, not a locally computed sum of weighted factors', () => {
    const step = section(readDoc(), '## Step 4');
    expect(step).toContain('Registry');
    expect(step).not.toMatch(/calculated locally/i);
    expect(step).not.toMatch(/no data is uploaded/i);
    expect(step, 'Step 4 still carries a factor/weight table ai-trust does not print').not.toMatch(
      /^\|\s*Factor\s*\|\s*Weight\s*\|/m,
    );
  });

  it('Step 4 says only `check . --no-scan` reports `.` not found, and that `check .` packs the directory', () => {
    const step = section(readDoc(), '## Step 4');
    // Each `ai-trust check .` code span, with the prose up to the next `ai-trust` command span.
    const dotChecks = [...step.matchAll(/`ai-trust check \.((?: [^`]*)?)`([\s\S]*?)(?=`ai-trust |$)/g)];
    expect(dotChecks.length, 'Step 4 no longer names `ai-trust check .`').toBeGreaterThan(0);
    for (const [, flags, prose] of dotChecks) {
      const span = `\`ai-trust check .${flags}\``;
      const noScan = flags.split(/\s+/).includes('--no-scan');
      if (/not found/.test(prose)) {
        expect(noScan, `${span} is said to report "not found", which ai-trust does only with --no-scan`).toBe(true);
      }
      if (!noScan) {
        expect(prose, `${span} without --no-scan runs \`npm pack\` on the current directory`).toMatch(
          /`npm pack`[\s\S]*`prepack`/,
        );
      }
    }
  });

  it('Step 4 says ai-trust leaves the working tree unread only when it is given the published name', () => {
    const step = section(readDoc(), '## Step 4');
    // `ai-trust check .` without --no-scan packs the current directory (the test above), so a
    // sentence saying ai-trust does not read the working tree holds only for the published name.
    // Code spans are masked first: the `.` in `ai-trust check . --no-scan` would end a sentence.
    const sentences = step.replace(/`[^`\n]*`/g, '`code`').split(/(?<=[.!?])\s+/);
    const claims = sentences.filter((s) => {
      const at = s.search(/\bworking tree\b/i);
      return at !== -1 && /\b(?:neither|nor|not|never|no)\b|n't\b/i.test(s.slice(0, at));
    });
    expect(claims.length, 'Step 4 no longer says when ai-trust leaves your working tree unread').toBeGreaterThan(0);
    for (const claim of claims) {
      expect(
        claim,
        'Step 4 says ai-trust does not read your working tree without limiting that to the published name, ' +
          'but `ai-trust check .` packs the current directory',
      ).toMatch(/\bpublished (?:name|under)\b/i);
    }
  });

  it('the gate asks ai-trust for JSON about the claimed package and passes a score at the threshold', () => {
    expect(haveJq(), JQ_REQUIRED).toBe(true);
    const { status, argv } = runGate(JSON.stringify(registryAnswer(0.7, 'passed')), 0);
    expect(argv[0]).toBe('ai-trust');
    expect(argv[1]).toBe('check');
    expect(argv).toContain(claimedPackage(readDoc()));
    expect(argv).toContain('--json');
    expect(status).toBe(0);
  });

  it('the gate fails a score below the threshold', () => {
    expect(haveJq(), JQ_REQUIRED).toBe(true);
    expect(runGate(JSON.stringify(registryAnswer(0.69, 'passed')), 0).status).not.toBe(0);
  });

  it('the gate fails when the registry has no record of the package, even if ai-trust exits 0', () => {
    expect(haveJq(), JQ_REQUIRED).toBe(true);
    expect(runGate(JSON.stringify(NOT_FOUND), 0).status).not.toBe(0);
  });

  it('the gate fails a blocked verdict even when the score clears the threshold', () => {
    expect(haveJq(), JQ_REQUIRED).toBe(true);
    // ai-trust check exits 2 on a blocked or warning verdict.
    expect(runGate(JSON.stringify(registryAnswer(0.9, 'blocked')), 2).status).not.toBe(0);
  });

  it('the gate fails when ai-trust prints nothing and exits non-zero', () => {
    expect(haveJq(), JQ_REQUIRED).toBe(true);
    expect(runGate('', 1).status).not.toBe(0);
  });
});
