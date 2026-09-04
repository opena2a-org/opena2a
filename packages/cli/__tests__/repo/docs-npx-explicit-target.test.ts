import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// A committed .npmrc `node-options` line (and its yarn/pnpm equivalents)
// executes before the CLI's first instruction whenever the CLI is started
// through `npx` inside that tree. That class has no in-process fix, so the
// documented invocation form is from OUTSIDE the tree with the target as an
// operand. This test fails any documented `npx opena2a-cli` line whose
// target is implied by the working directory rather than named.

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

// Subcommands declared with a directory/file operand in
// packages/cli/src/index.ts: the operand must be present. The cross-check
// below reads index.ts and fails when a declared operand-bearing subcommand
// is missing here.
const REQUIRES_TARGET = new Set([
  'protect',
  'status',
  'init',
  'review',
  'scan-soul',
  'harden-soul',
  'harden-skill',
  'benchmark',
  'comply',
  'detect',
  'setup',
  'runtime',
  // and the ones whose operand is a package or target
  'check',
  'trust',
  'claim',
]);

// The committed exemption list. Nothing may be added here without a
// contract revision: these forms read no scanned tree at all.
const EXEMPT_SUBCOMMANDS = new Set(['login', 'logout', 'whoami']);
const EXEMPT_FLAGS = new Set(['--version', '--help']);

// Tokens that end the invocation on a documented line: shell operators,
// comments, and markdown table borders.
const TERMINATOR = /^[|>#;&)]/;

const NPX_INVOCATION = /npx (?:-y )?opena2a-cli(?=$|[\s`"'|])/g;

function tokensAfter(rest: string): string[] {
  const out: string[] = [];
  for (const raw of rest.split(/\s+/)) {
    if (!raw) continue;
    if (TERMINATOR.test(raw)) break;
    // A closing backtick ends an inline-code invocation: prose after the
    // code span is never an operand.
    const backtick = raw.indexOf('`');
    const inCode = backtick === -1 ? raw : raw.slice(0, backtick);
    const cleaned = inCode.replace(/^["']+/, '').replace(/["',.]+$/, '');
    if (cleaned) out.push(cleaned);
    if (backtick !== -1 || !cleaned) break;
  }
  return out;
}

// Returns null when the line is acceptable, or a reason string when its
// target is implied by the working directory.
export function checkInvocation(commandText: string): string | null {
  const tokens = tokensAfter(commandText);
  if (tokens.length === 0) return null; // bare `npx opena2a-cli` -- exempt
  const sub = tokens[0];
  if (sub.startsWith('-')) {
    return EXEMPT_FLAGS.has(sub) ? null : `flag "${sub}" before any subcommand; name the subcommand first`;
  }
  if (EXEMPT_SUBCOMMANDS.has(sub)) return null;
  if (!REQUIRES_TARGET.has(sub)) return null;
  // `runtime [subcommand] [directory]` (index.ts): the tree-reading operand
  // is the directory after the runtime subcommand.
  const operand = sub === 'runtime' ? tokens[2] : tokens[1];
  if (operand === undefined || operand.startsWith('-')) {
    return `"${sub}" without an explicit target: the scanned tree would be implied by the cwd`;
  }
  if (operand === '.' || operand === './') {
    return `"${sub} ${operand}" is the cwd-implied form; name the target path or run from outside the tree`;
  }
  return null;
}

// Runs the checker over a full documented line, one result per invocation.
export function lineViolations(line: string): string[] {
  const reasons: string[] = [];
  for (const match of line.matchAll(NPX_INVOCATION)) {
    const reason = checkInvocation(line.slice(match.index! + match[0].length));
    if (reason !== null) reasons.push(reason);
  }
  return reasons;
}

function docsMarkdownFiles(): string[] {
  const files: string[] = ['README.md', path.join('packages', 'cli', 'README.md')];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(path.join(REPO_ROOT, dir), { withFileTypes: true })) {
      const rel = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(rel);
      else if (entry.name.endsWith('.md')) files.push(rel);
    }
  };
  walk('docs');
  return files;
}

describe('documented npx opena2a-cli invocations name their target', () => {
  it('OPA-02.AC2 every documented invocation with a tree-reading subcommand carries an explicit target', () => {
    const violations: string[] = [];

    for (const file of docsMarkdownFiles()) {
      const lines = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8').split('\n');
      lines.forEach((line, i) => {
        for (const reason of lineViolations(line)) {
          violations.push(`${file}:${i + 1}: ${reason}\n    ${line.trim()}`);
        }
      });
    }

    expect(violations).toEqual([]);
  });

  it('OPA-02.AC2 REQUIRES_TARGET covers every subcommand declared with a directory or file operand in index.ts', () => {
    const indexTs = fs.readFileSync(
      path.join(REPO_ROOT, 'packages', 'cli', 'src', 'index.ts'),
      'utf-8'
    );
    const declared: string[] = [];
    for (const match of indexTs.matchAll(/\.command\('([^']+)'/g)) {
      const declaration = match[1];
      if (
        declaration.includes('[directory]') ||
        declaration.includes('[file]') ||
        declaration.includes('[files...]')
      ) {
        declared.push(declaration.split(' ')[0]);
      }
    }
    expect(declared).not.toEqual([]);
    expect(declared.filter((name) => !REQUIRES_TARGET.has(name))).toEqual([]);
  });

  it('OPA-02.AC3 the cwd-implied form is refused and the explicit form is admitted', () => {
    // Negative path pinned: reintroducing a cwd-implied line in any scanned
    // file fails AC2 above; this pins the rule itself against regression.
    expect(checkInvocation(' review')).not.toBeNull();
    expect(checkInvocation(' review --format json --ci')).not.toBeNull();
    expect(checkInvocation(' review ./')).not.toBeNull();
    expect(checkInvocation(' review .')).not.toBeNull();
    expect(checkInvocation(' detect')).not.toBeNull();
    expect(checkInvocation(' review "$GITHUB_WORKSPACE" --format json --ci')).toBeNull();
    expect(checkInvocation(' scan-soul my-agent --strict')).toBeNull();
    expect(checkInvocation(' --version')).toBeNull();
    expect(checkInvocation('')).toBeNull(); // bare invocation
    // The two QA counterexamples, verbatim: prose after the closing backtick
    // of an inline-code invocation is not an operand.
    expect(lineViolations('Run `npx opena2a-cli review` to scan your agent.')).not.toEqual([]);
    expect(lineViolations('`npx opena2a-cli detect` in the repo root')).not.toEqual([]);
    // An inline-code invocation whose operand sits inside the code span is
    // the admitted form.
    expect(
      lineViolations('Run `npx opena2a-cli review "$GITHUB_WORKSPACE"` from outside the tree.')
    ).toEqual([]);
  });

  it('OPA-02.AC3 the ci-cd.md HackMyAgent recipe runs from runner.temp with the workspace as the operand', () => {
    const cicd = fs.readFileSync(
      path.join(REPO_ROOT, 'docs', 'use-cases', 'ci-cd.md'),
      'utf-8'
    );
    expect(cicd).toMatch(
      /- name: HackMyAgent security scan\n\s+working-directory: \$\{\{ runner\.temp \}\}\n\s+run: \|\n\s+npx hackmyagent secure "\$GITHUB_WORKSPACE" --ci --format json/
    );
  });
});
