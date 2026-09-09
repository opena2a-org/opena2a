/**
 * Structural invariant over every child start under packages/cli/src (#246).
 *
 * child-env-wiring.test.ts runs the adapters and asserts on the environment
 * they hand a mocked spawn. That catches a regression at a site it exercises
 * and says nothing about a site it does not — and the sites that leaked the
 * operator's environment for every release since 0.1.2 were exactly the ones
 * no wiring test exercised (the direct `hackmyagent` spawns in index.ts and
 * router.ts, `review`'s scanner spawn, `shield/llm-backend`'s `claude` call).
 *
 * So this test walks the SOURCE. Every paren-balanced call of
 * `spawn|spawnSync|exec|execSync|execFile|execFileSync|fork(` whose callee is
 * a `node:child_process` binding in that file must either
 *
 *   - carry an `env:` option whose value is a resolver call — `childEnv(`,
 *     `probeEnv(` or `inheritEnv(` — directly, or through a same-file helper
 *     whose every `return` is one of those calls (the adapters' `toolEnv`,
 *     which picks `inheritEnv()` for an `envInherit` entry and
 *     `buildChildEnv(...)` otherwise); or
 *   - be listed, as `path:line`, in IMPLICIT_INHERIT below.
 *
 * IMPLICIT_INHERIT is the measured set of child starts that still inherit the
 * parent environment because they pass no `env` at all. It is compared for
 * EQUALITY: a site that is not listed fails, and a listed entry that no longer
 * matches (moved, fixed, renumbered) fails just as loudly. The roster can
 * therefore only change through a visible diff of this file, and the review
 * question for any such diff is "why did it grow?".
 *
 * `RegExp.prototype.exec` calls (`SIG_BLOCK_RE.exec(content)` in
 * commands/guard-signing.ts) are not child starts: the callee is a member
 * access, and the file binds nothing from `node:child_process`.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const SRC_ROOT = path.resolve(__dirname, '..', '..', 'src');

const CHILD_START_NAMES = ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'];

/** The three resolvers a site may hand a child directly. */
const RESOLVERS = ['childEnv', 'probeEnv', 'inheritEnv'];

/** What a same-file env helper may return. */
const HELPER_RETURNS = [...RESOLVERS, 'buildChildEnv'];

/**
 * Child starts that pass no `env` and so inherit the parent environment.
 * Measured at the commit that introduced this test. SHRINK ONLY.
 *
 * Each is a `git`, `npm`, `gh`, `op`, `ps`, `security`/`secret-tool` (OS
 * keychain), `which`, or open-in-browser invocation of a tool on the
 * operator's own machine, run for the operator's own account — none is the
 * delegated scanner or the model CLI, which are the two children #246 ruled
 * on. They are listed here so that they are counted, not excused: moving one
 * to a resolver removes its line from this roster in the same diff.
 */
const IMPLICIT_INHERIT: readonly string[] = [
  'commands/claim.ts:80',
  'commands/claim.ts:84',
  'commands/claim.ts:120',
  'commands/claim.ts:139',
  'commands/detect.ts:204',
  'commands/detect.ts:1059',
  'commands/detect.ts:1369',
  'commands/guard.ts:685',
  'commands/login.ts:270',
  'commands/onepassword-migration.ts:213',
  'commands/protect.ts:931',
  'commands/protect.ts:1450',
  'commands/review.ts:1076',
  'commands/review.ts:1843',
  'shield/detect.ts:33',
  'shield/status.ts:15',
  'shield/status.ts:24',
  'util/keychain.ts:97',
  'util/keychain.ts:108',
  'util/keychain.ts:116',
  'util/keychain.ts:127',
  'util/keychain.ts:141',
  'util/keychain.ts:160',
  'util/keychain.ts:190',
  'util/keychain.ts:199',
  'util/keychain.ts:209',
  'util/keychain.ts:225',
  'util/keychain.ts:243',
];

interface ChildStart {
  /** `relative/path.ts:line` of the call token. */
  site: string;
  callee: string;
  /** Balanced argument text of the call, comments and string bodies blanked. */
  args: string;
  /** The same argument text, verbatim from the source. */
  text: string;
  /** Text after `env:` inside the call, or null when the call passes no env. */
  envValue: string | null;
}

function listSourceFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return listSourceFiles(full);
    return entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts') ? [full] : [];
  });
}

/**
 * Replace the bodies of comments and string/template literals with spaces so
 * that positions and line numbers are preserved but no bracket, quote or
 * keyword inside them can confuse the scanner. Quote characters are kept.
 */
function blankCommentsAndStrings(source: string): string {
  const out = source.split('');
  let i = 0;
  const n = source.length;
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  while (i < n) {
    const c = source[i];
    const next = source[i + 1];
    if (c === '/' && next === '/') {
      const end = source.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (c === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2);
      const stop = end === -1 ? n : end + 2;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (c === '\'' || c === '"') {
      let j = i + 1;
      while (j < n && source[j] !== c && source[j] !== '\n') {
        if (source[j] === '\\') j++;
        j++;
      }
      blank(i + 1, j);
      i = j + 1;
      continue;
    }
    if (c === '`') {
      // Template literal: blank everything through the closing backtick,
      // including `${...}` expressions (tracking their nesting so a backtick
      // inside a nested template does not end the outer one early).
      let j = i + 1;
      let depth = 0;
      while (j < n) {
        const d = source[j];
        if (d === '\\') { j += 2; continue; }
        if (d === '$' && source[j + 1] === '{') { depth++; j += 2; continue; }
        if (d === '}' && depth > 0) { depth--; j++; continue; }
        if (d === '`' && depth === 0) break;
        j++;
      }
      blank(i + 1, j);
      i = j + 1;
      continue;
    }
    i++;
  }
  return out.join('');
}

/** Names bound from `node:child_process` in this file, plus namespace aliases. */
function childProcessBindings(blanked: string, original: string): { names: Set<string>; namespaces: Set<string> } {
  const names = new Set<string>();
  const namespaces = new Set<string>();
  // Module specifiers are string bodies, blanked above — read them from the
  // original text at the same positions instead.
  const spec = /['"](?:node:)?child_process['"]/;
  const named = /import\s*\{([^}]*)\}\s*from\s*(['"][^'"]*['"])/g;
  const nsImport = /import\s*\*\s*as\s+(\w+)\s+from\s*(['"][^'"]*['"])/g;
  const destructured = /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+import|require)\s*\(\s*(['"][^'"]*['"])\s*\)/g;
  const whole = /(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*(['"][^'"]*['"])\s*\)/g;

  const at = (m: RegExpExecArray, group: number): string => {
    const start = m.index + m[0].indexOf(m[group]);
    return original.slice(start, start + m[group].length);
  };
  const addNames = (list: string): void => {
    for (const part of list.split(',')) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      const alias = trimmed.split(/\s+as\s+/);
      names.add((alias[1] ?? alias[0]).trim());
    }
  };
  let m: RegExpExecArray | null;
  while ((m = named.exec(blanked)) !== null) if (spec.test(at(m, 2))) addNames(m[1]);
  while ((m = destructured.exec(blanked)) !== null) if (spec.test(at(m, 2))) addNames(m[1]);
  while ((m = nsImport.exec(blanked)) !== null) if (spec.test(at(m, 2))) namespaces.add(m[1]);
  while ((m = whole.exec(blanked)) !== null) if (spec.test(at(m, 2))) namespaces.add(m[1]);
  return { names, namespaces };
}

/** Text from `open` (an opening paren index) to its balanced close, exclusive. */
function balancedArgs(text: string, open: number): string {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  throw new Error(`unbalanced call at offset ${open}`);
}

function lineOf(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset; i++) if (text[i] === '\n') line++;
  return line;
}

function collectChildStarts(file: string): ChildStart[] {
  const original = fs.readFileSync(file, 'utf-8');
  const blanked = blankCommentsAndStrings(original);
  const { names, namespaces } = childProcessBindings(blanked, original);
  if (names.size === 0 && namespaces.size === 0) return [];

  const rel = path.relative(SRC_ROOT, file).split(path.sep).join('/');
  const starts: ChildStart[] = [];
  const token = new RegExp(`(^|[^.\\w$])(?:(\\w+)\\.)?(${CHILD_START_NAMES.join('|')})\\s*\\(`, 'g');
  let m: RegExpExecArray | null;
  while ((m = token.exec(blanked)) !== null) {
    const ns = m[2];
    const name = m[3];
    const bound = ns ? namespaces.has(ns) : names.has(name);
    if (!bound) continue;
    // A declaration (`function spawn(`) or a type position is not a call.
    const before = blanked.slice(Math.max(0, m.index - 12), m.index + m[1].length);
    if (/\bfunction\s*$/.test(before)) continue;

    const open = m.index + m[0].length - 1;
    const args = balancedArgs(blanked, open);
    // Blanking preserves offsets, so the verbatim text sits at the same slice.
    const text = original.slice(open + 1, open + 1 + args.length);
    const envMatch = /(^|[^\w$.])env\s*:\s*/.exec(args);
    const envValue = envMatch ? text.slice(envMatch.index + envMatch[0].length) : null;
    starts.push({
      site: `${rel}:${lineOf(blanked, m.index + m[1].length)}`,
      callee: ns ? `${ns}.${name}` : name,
      args,
      text,
      envValue,
    });
  }
  return starts;
}

/**
 * True when every `return` of the same-file function `helper` is a resolver
 * call, so a site whose env is `helper(...)` is a resolver site once removed.
 */
function isResolverHelper(blanked: string, helper: string): boolean {
  const decl = new RegExp(`function\\s+${helper}\\s*\\(`).exec(blanked);
  if (!decl) return false;
  const bodyOpen = blanked.indexOf('{', decl.index + decl[0].length);
  if (bodyOpen === -1) return false;
  const body = balancedArgs(blanked, bodyOpen);
  const returns = [...body.matchAll(/\breturn\b\s*([^;]*)/g)].map(r => r[1].trim());
  if (returns.length === 0) return false;
  return returns.every(expr => HELPER_RETURNS.some(fn => new RegExp(`^${fn}\\s*\\(`).test(expr)));
}

type Verdict =
  | { kind: 'resolver'; via: string }
  | { kind: 'implicit' }
  | { kind: 'violation'; reason: string };

function judge(start: ChildStart, blanked: string): Verdict {
  if (start.envValue === null) return { kind: 'implicit' };
  const call = /^([A-Za-z_$][\w$]*)\s*\(/.exec(start.envValue);
  if (!call) return { kind: 'violation', reason: `env is not a call: ${start.envValue.split('\n')[0].trim()}` };
  const callee = call[1];
  if (RESOLVERS.includes(callee)) return { kind: 'resolver', via: callee };
  if (isResolverHelper(blanked, callee)) return { kind: 'resolver', via: `${callee} -> resolver` };
  return { kind: 'violation', reason: `env is ${callee}(...), which is not a resolver` };
}

interface Survey {
  starts: Array<ChildStart & { verdict: Verdict }>;
  implicit: string[];
  violations: string[];
  spreads: string[];
}

function survey(): Survey {
  const starts: Survey['starts'] = [];
  for (const file of listSourceFiles(SRC_ROOT)) {
    const blanked = blankCommentsAndStrings(fs.readFileSync(file, 'utf-8'));
    for (const start of collectChildStarts(file)) {
      starts.push({ ...start, verdict: judge(start, blanked) });
    }
  }
  return {
    starts,
    implicit: starts.filter(s => s.verdict.kind === 'implicit').map(s => s.site).sort(),
    violations: starts
      .filter(s => s.verdict.kind === 'violation')
      .map(s => `${s.site} ${(s.verdict as { reason: string }).reason}`)
      .sort(),
    spreads: starts.filter(s => /\.\.\.\s*process\.env\b/.test(s.args)).map(s => s.site).sort(),
  };
}

function findStart(result: Survey, file: string, calleeArg: RegExp): Survey['starts'][number] {
  const hit = result.starts.find(s => s.site.startsWith(`${file}:`) && calleeArg.test(s.text));
  if (!hit) throw new Error(`no child start in ${file} matching ${calleeArg}`);
  return hit;
}

describe('child-env-sites — every child start under src/ (#246)', () => {
  const result = survey();

  it('OPA-14.AC3 the walker sees the child-start population, and none of the RegExp.exec calls', () => {
    // Guards the guard: if the walker silently matched nothing, every other
    // assertion here would pass vacuously.
    expect(result.starts.length).toBeGreaterThanOrEqual(40);
    const files = new Set(result.starts.map(s => s.site.split(':')[0]));
    for (const expected of [
      'index.ts', 'router.ts', 'commands/review.ts', 'shield/llm-backend.ts',
      'adapters/spawn.ts', 'adapters/python.ts', 'adapters/docker.ts', 'util/hma-version.ts',
    ]) {
      expect(files.has(expected), `walker found no child start in ${expected}`).toBe(true);
    }
    // RegExp.prototype.exec sites are member calls in files that bind nothing
    // from node:child_process; none may be counted as a child start.
    for (const notAStart of ['commands/guard-signing.ts', 'util/credential-patterns.ts', 'util/ai-config.ts']) {
      expect(files.has(notAStart), `${notAStart} has no child start`).toBe(false);
    }
  });

  it('OPA-14.AC3 every child start carries a resolver env or is on the implicit-inherit roster', () => {
    expect(result.violations, 'child starts whose env is neither a resolver nor absent').toEqual([]);
  });

  it('OPA-14.AC3 the roster equals the measured implicit-inherit set exactly (shrink only)', () => {
    // Symmetric on purpose: an unlisted implicit site fails, and so does a
    // listed site that has since been fixed or moved, so a stale roster is as
    // loud as a new leak.
    expect(result.implicit).toEqual([...IMPLICIT_INHERIT].sort());
  });

  it('OPA-14.AC3 no child start spreads process.env into its options', () => {
    expect(result.spreads).toEqual([]);
  });

  it('OPA-14.AC3 the three sites the ruling moved out of implicit inheritance carry a resolver', () => {
    const review = findStart(result, 'commands/review.ts', /'secure'/);
    expect(review.verdict).toEqual({ kind: 'resolver', via: 'childEnv' });
    expect(review.envValue).toMatch(/^childEnv\(\s*'hackmyagent'/);

    const version = findStart(result, 'util/hma-version.ts', /'--version'/);
    expect(version.verdict).toEqual({ kind: 'resolver', via: 'probeEnv' });

    const which = findStart(result, 'shield/llm-backend.ts', /'which'/);
    expect(which.verdict).toEqual({ kind: 'resolver', via: 'probeEnv' });

    for (const moved of [review.site, version.site, which.site]) {
      expect(IMPLICIT_INHERIT, `${moved} must not be on the roster`).not.toContain(moved);
    }
  });

  it('OPA-14.AC3 the adapters reach a resolver through toolEnv, and the seven fixed sites through childEnv', () => {
    for (const adapter of ['adapters/spawn.ts', 'adapters/python.ts', 'adapters/docker.ts']) {
      const run = result.starts.find(s => s.site.startsWith(`${adapter}:`) && /toolEnv/.test(s.envValue ?? ''));
      expect(run, `${adapter} run spawn goes through toolEnv`).toBeDefined();
      expect(run!.verdict).toEqual({ kind: 'resolver', via: 'toolEnv -> resolver' });
    }
    const direct = result.starts.filter(s =>
      /^(index\.ts|router\.ts):/.test(s.site) && /'hackmyagent'/.test(s.text));
    // spawnHmaCheck, spawnHackmyagent and spawnHmaCheckFromRouter, each with
    // a direct spawn and an npx fallback.
    expect(direct.length).toBe(6);
    for (const site of direct) {
      expect(site.envValue, site.site).toMatch(/^childEnv\(\s*'hackmyagent'\s*,\s*\{\s*set:/);
    }
    const claude = findStart(result, 'shield/llm-backend.ts', /^\s*'claude'\s*,\s*\[/);
    expect(claude.envValue).toMatch(/^childEnv\(\s*'claude'\s*\)/);
  });
});

describe('child-env-sites — the shipped-spread census (#246)', () => {
  const sixFiles = [
    'index.ts', 'router.ts', 'shield/llm-backend.ts',
    'adapters/spawn.ts', 'adapters/python.ts', 'adapters/docker.ts',
  ];

  function spreadLines(): Array<{ file: string; line: number; text: string }> {
    const hits: Array<{ file: string; line: number; text: string }> = [];
    for (const file of listSourceFiles(SRC_ROOT)) {
      const rel = path.relative(SRC_ROOT, file).split(path.sep).join('/');
      fs.readFileSync(file, 'utf-8').split('\n').forEach((text, idx) => {
        if (text.includes('...process.env')) hits.push({ file: rel, line: idx + 1, text });
      });
    }
    return hits;
  }

  it('OPA-14.AC2 exactly one `...process.env` under src/, inside the body of inheritEnv', () => {
    const hits = spreadLines();
    expect(hits.map(h => `${h.file}:${h.line}`)).toHaveLength(1);
    expect(hits[0].file).toBe('adapters/registry.ts');

    const source = fs.readFileSync(path.join(SRC_ROOT, 'adapters/registry.ts'), 'utf-8');
    const blanked = blankCommentsAndStrings(source);
    const decl = /export function inheritEnv\s*\(\s*\)[^{]*\{/.exec(blanked)!;
    expect(decl, 'inheritEnv is exported from adapters/registry.ts').not.toBeNull();
    const bodyOpen = decl.index + decl[0].length - 1;
    const body = balancedArgs(blanked, bodyOpen);
    const bodyStartLine = lineOf(blanked, bodyOpen);
    const bodyEndLine = bodyStartLine + body.split('\n').length - 1;
    expect(hits[0].line).toBeGreaterThanOrEqual(bodyStartLine);
    expect(hits[0].line).toBeLessThanOrEqual(bodyEndLine);
  });

  it('OPA-14.AC2 zero spreads in the six files that carried the seven at base', () => {
    const hits = spreadLines().filter(h => sixFiles.includes(h.file));
    expect(hits).toEqual([]);
  });

  it('OPA-14.AC2 the adapters’ toolEnv chooses inheritEnv() or buildChildEnv(), and the direct sites use childEnv', () => {
    for (const adapter of ['adapters/spawn.ts', 'adapters/python.ts', 'adapters/docker.ts']) {
      const blanked = blankCommentsAndStrings(fs.readFileSync(path.join(SRC_ROOT, adapter), 'utf-8'));
      const decl = /function toolEnv\s*\([^)]*\)[^{]*\{/.exec(blanked)!;
      expect(decl, `${adapter} defines toolEnv`).not.toBeNull();
      const body = balancedArgs(blanked, decl.index + decl[0].length - 1);
      expect(body).toMatch(/if\s*\(\s*config\.envInherit\s*\)\s*return\s+inheritEnv\(\)/);
      expect(body).toMatch(/return\s+buildChildEnv\(/);
      expect(body).not.toMatch(/process\.env\s*\}/);
    }

    const citationNames = ['HMA_CLI_PREFIX', 'HMA_CHECK_COMMAND', 'HMA_FULL_SCAN_HINT'];
    for (const [file, fns] of [
      ['index.ts', ['spawnHmaCheck', 'spawnHackmyagent']],
      ['router.ts', ['spawnHmaCheckFromRouter']],
    ] as const) {
      const source = fs.readFileSync(path.join(SRC_ROOT, file), 'utf-8');
      const blanked = blankCommentsAndStrings(source);
      for (const fn of fns) {
        const decl = new RegExp(`function ${fn}\\s*\\(`).exec(blanked)!;
        expect(decl, `${file} defines ${fn}`).not.toBeNull();
        const bodyOpen = blanked.indexOf('{', decl.index + decl[0].length);
        const bodyLength = balancedArgs(blanked, bodyOpen).length;
        // Verbatim body (string literals intact) at the offsets the blanked
        // text established.
        const body = source.slice(bodyOpen + 1, bodyOpen + 1 + bodyLength);
        const envs = [...body.matchAll(/env:\s*childEnv\(\s*'hackmyagent'\s*,\s*\{\s*set:\s*(\w+)\s*\}\s*\)/g)];
        expect(envs.length, `${fn}: direct spawn and npx fallback both use childEnv`).toBe(2);
        // The `set` carries the three citation names this site set at base.
        const setName = envs[0][1];
        const setDecl = new RegExp(`const ${setName}\\s*=\\s*\\{([^}]*)\\}`).exec(source)!;
        expect(setDecl, `${file}: ${setName} is declared`).not.toBeNull();
        for (const name of citationNames) expect(setDecl[1]).toContain(name);
      }
    }

    const backendSource = fs.readFileSync(path.join(SRC_ROOT, 'shield/llm-backend.ts'), 'utf-8');
    const backend = blankCommentsAndStrings(backendSource);
    const decl = /export function callClaudeCode\s*\(/.exec(backend)!;
    const bodyOpen = backend.indexOf('{', decl.index + decl[0].length);
    const body = backendSource.slice(bodyOpen + 1, bodyOpen + 1 + balancedArgs(backend, bodyOpen).length);
    expect(body).toMatch(/env:\s*childEnv\(\s*'claude'\s*\)/);
  });
});
