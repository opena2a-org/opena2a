import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// The Node.js floor a package declares in `engines.node` is a promise to the
// people who install it: every version it admits must be one that every
// package it installs at runtime admits too, and the install docs must state
// the same floor. opena2a-cli and the workspace root once declared
// `>=18.0.0`, and the docs said "Node.js 18 or later", while secretless-ai,
// the @noble crypto packages and @hono/node-server in the installed tree
// require Node 20.19 or 20. This test walks each workspace's runtime
// dependency tree in package-lock.json, as `npm ls --omit=dev --all` does,
// and compares every `engines.node` range it finds with the declared floor.

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

type Version = [number, number, number];

/** A contiguous run of versions; `hi: null` means no upper bound. */
interface Interval {
  lo: Version;
  loInc: boolean;
  hi: Version | null;
  hiInc: boolean;
}

interface LockEntry {
  name?: string;
  version?: string;
  link?: boolean;
  resolved?: string;
  engines?: { node?: string };
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
}

const lock = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package-lock.json'), 'utf-8')) as {
  packages: Record<string, LockEntry>;
};

function readManifest(rel: string): { name: string; engines?: { node?: string } } {
  return JSON.parse(fs.readFileSync(path.join(REPO_ROOT, rel, 'package.json'), 'utf-8'));
}

function cmp(a: Version, b: Version): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

/** A version with 1 to 3 numeric parts; `*` and `x` are not accepted here. */
function parseVersion(text: string): { v: Version; parts: number } {
  if (!/^\d+(\.\d+){0,2}$/.test(text)) throw new Error(`unsupported version "${text}"`);
  const nums = text.split('.').map(Number);
  return { v: [nums[0], nums[1] ?? 0, nums[2] ?? 0], parts: nums.length };
}

/** The exclusive upper bound of a partial version: `20` -> 21.0.0, `20.19` -> 20.20.0. */
function nextAfter(v: Version, parts: number): Version {
  if (parts === 1) return [v[0] + 1, 0, 0];
  if (parts === 2) return [v[0], v[1] + 1, 0];
  return [v[0], v[1], v[2] + 1];
}

/**
 * Turns a semver range into intervals, one per `||` alternative. Only the
 * forms that appear in engines fields are accepted; anything else throws so
 * that the test fails rather than passing on a range it did not read.
 */
function parseRange(range: string): Interval[] {
  return range.split('||').map(alt => {
    const out: Interval = { lo: [0, 0, 0], loInc: true, hi: null, hiInc: false };
    const raise = (lo: Version, inc: boolean) => {
      const c = cmp(lo, out.lo);
      if (c > 0 || (c === 0 && !inc)) Object.assign(out, { lo, loInc: inc });
    };
    const lower = (hi: Version, inc: boolean) => {
      const c = out.hi === null ? -1 : cmp(hi, out.hi);
      if (c < 0 || (c === 0 && !inc)) Object.assign(out, { hi, hiInc: inc });
    };
    const tokens = alt.trim().replace(/(>=|<=|>|<|=|\^|~)\s+/g, '$1').split(/\s+/).filter(Boolean);
    for (const token of tokens) {
      if (token === '*' || token === 'x') continue;
      const m = /^(>=|<=|>|<|=|\^|~)?v?(.+)$/.exec(token);
      if (!m) throw new Error(`unsupported comparator "${token}" in "${range}"`);
      const { v, parts } = parseVersion(m[2]);
      switch (m[1]) {
        case '>=': raise(v, true); break;
        case '<': lower(v, false); break;
        case '>':
          if (parts === 3) raise(v, false);
          else raise(nextAfter(v, parts), true);
          break;
        case '<=':
          if (parts === 3) lower(v, true);
          else lower(nextAfter(v, parts), false);
          break;
        case '^': {
          raise(v, true);
          const idx = v[0] > 0 || parts === 1 ? 1 : v[1] > 0 || parts === 2 ? 2 : 3;
          lower(nextAfter(v, idx), false);
          break;
        }
        case '~':
          raise(v, true);
          lower(nextAfter(v, Math.min(parts, 2)), false);
          break;
        default:
          raise(v, true);
          if (parts === 3) lower(v, true);
          else lower(nextAfter(v, parts), false);
      }
    }
    return out;
  });
}

/** True when every version from `floor` upward lies inside `range`. */
function admitsEverythingFrom(floor: Version, range: string): boolean {
  const intervals = parseRange(range);
  let at = floor;
  let atInc = true;
  for (let guard = 0; guard <= intervals.length; guard++) {
    const next = intervals.find(iv => {
      const lo = cmp(iv.lo, at);
      const reachesBack = lo < 0 || (lo === 0 && (iv.loInc || !atInc));
      if (!reachesBack) return false;
      if (iv.hi === null) return true;
      const hi = cmp(iv.hi, at);
      return hi > 0 || (hi === 0 && iv.hiInc && atInc);
    });
    if (!next) return false;
    if (next.hi === null) return true;
    at = next.hi;
    atInc = !next.hiInc;
  }
  return false;
}

/** The single lower bound an `engines.node` value of the form `>=X.Y.Z` states. */
function declaredFloor(range: string): Version {
  const m = /^>=\s*(\d+\.\d+\.\d+)$/.exec(range.trim());
  if (!m) throw new Error(`engines.node "${range}" is not of the form >=X.Y.Z`);
  return parseVersion(m[1]).v;
}

/** The lock key npm installs `name` at when it is required from `from`. */
function resolveDep(from: string, name: string): string | null {
  const parts = from === '' ? [] : from.split('/');
  for (let i = parts.length; i >= 0; i--) {
    const key = [...parts.slice(0, i), 'node_modules', name].join('/');
    if (lock.packages[key]) return key;
  }
  return null;
}

/** Every lock entry installed at runtime under `start`, and any required dependency that did not resolve. */
function runtimeClosure(start: string): { keys: Set<string>; missing: string[] } {
  const keys = new Set<string>([start]);
  const missing: string[] = [];
  const queue = [start];
  while (queue.length > 0) {
    const key = queue.shift()!;
    const entry = lock.packages[key];
    const optionalPeers = entry.peerDependenciesMeta ?? {};
    const wanted: Array<[string, boolean]> = [
      ...Object.keys(entry.dependencies ?? {}).map(n => [n, true] as [string, boolean]),
      ...Object.keys(entry.optionalDependencies ?? {}).map(n => [n, false] as [string, boolean]),
      ...Object.keys(entry.peerDependencies ?? {}).map(
        n => [n, !optionalPeers[n]?.optional] as [string, boolean],
      ),
    ];
    for (const [name, required] of wanted) {
      let dep = resolveDep(key, name);
      if (dep === null) {
        if (required) missing.push(`${name} (required by ${key || 'the workspace root'})`);
        continue;
      }
      if (lock.packages[dep].link && lock.packages[dep].resolved) dep = lock.packages[dep].resolved!;
      if (!keys.has(dep)) {
        keys.add(dep);
        queue.push(dep);
      }
    }
  }
  return { keys, missing };
}

function label(key: string): string {
  const entry = lock.packages[key];
  const name = entry.name ?? key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
  return `${name}@${entry.version ?? '?'}`;
}

const WORKSPACES = Object.keys(lock.packages).filter(k => /^packages\/[^/]+$/.test(k));

// The workspace root declares the floor for working in this repository; its
// runtime tree is every workspace's runtime tree.
const SUBJECTS: Array<{ rel: string; closure: () => ReturnType<typeof runtimeClosure> }> = [
  {
    rel: '.',
    closure: () => {
      const keys = new Set<string>();
      const missing: string[] = [];
      for (const ws of WORKSPACES) {
        const c = runtimeClosure(ws);
        c.keys.forEach(k => keys.add(k));
        missing.push(...c.missing);
      }
      return { keys, missing };
    },
  },
  ...WORKSPACES.filter(ws => readManifest(ws).engines?.node).map(ws => ({
    rel: ws,
    closure: () => runtimeClosure(ws),
  })),
];

describe('engines.node admits only Node versions the runtime dependency tree admits', () => {
  it('covers opena2a-cli and the workspace root', () => {
    expect(SUBJECTS.map(s => s.rel)).toEqual(expect.arrayContaining(['.', 'packages/cli']));
  });

  for (const subject of SUBJECTS) {
    const manifest = readManifest(subject.rel);
    it(`${manifest.name} (${subject.rel === '.' ? 'workspace root' : subject.rel})`, () => {
      const floor = declaredFloor(manifest.engines!.node!);
      const { keys, missing } = subject.closure();
      expect(missing).toEqual([]);
      const excluded = new Set<string>();
      for (const key of keys) {
        const range = lock.packages[key].engines?.node;
        if (range && !admitsEverythingFrom(floor, range)) {
          excluded.add(`${label(key)} requires node ${range}`);
        }
      }
      expect([...excluded].sort()).toEqual([]);
    });
  }
});

/** Files that tell a reader which Node.js to install, and the manifest whose floor they state. */
const FLOOR_DOCS: Array<{ file: string; manifest: string }> = [
  { file: 'README.md', manifest: 'packages/cli' },
  { file: 'packages/cli/README.md', manifest: 'packages/cli' },
  { file: 'CONTRIBUTING.md', manifest: '.' },
  ...fs
    .readdirSync(path.join(REPO_ROOT, 'docs', 'use-cases'))
    .filter(f => f.endsWith('.md'))
    .map(f => ({ file: `docs/use-cases/${f}`, manifest: 'packages/cli' })),
];

// "Node.js 20.19 or later", "Node.js >= 20.19", "Node.js 20.19+".
const FLOOR_STATEMENT = /Node\.js\s*(?:>=\s*(\d+(?:\.\d+){0,2})|(\d+(?:\.\d+){0,2})(?:\+|\s+or\s+later))/g;

// A CI runtime a doc tells the reader to use. A partial version floats to
// the newest release under it, as setup-node and the image tags do.
const CI_RUNTIME = /(?:node-version:\s*['"]?|image:\s*node:|cimg\/node:)(\d+(?:\.\d+){0,2})/g;

function floatsToAtLeast(spec: string, floor: Version): boolean {
  const nums = spec.split('.').map(Number);
  for (let i = 0; i < nums.length; i++) {
    if (nums[i] !== floor[i]) return nums[i] > floor[i];
  }
  return true;
}

describe('the docs state the Node.js floor the manifests declare', () => {
  for (const { file, manifest } of FLOOR_DOCS) {
    it(`${file} states the floor of ${manifest === '.' ? 'the workspace root' : manifest}`, () => {
      const floor = declaredFloor(readManifest(manifest).engines!.node!);
      const text = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8');
      const stated = [...text.matchAll(FLOOR_STATEMENT)].map(m => m[1] ?? m[2]);
      expect(stated.length).toBeGreaterThan(0);
      expect(stated.map(v => parseVersion(v).v.join('.'))).toEqual(stated.map(() => floor.join('.')));
    });

    it(`${file} runs CI on a Node.js release at or above that floor`, () => {
      const floor = declaredFloor(readManifest(manifest).engines!.node!);
      const text = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8');
      const below = [...text.matchAll(CI_RUNTIME)]
        .filter(m => !floatsToAtLeast(m[1], floor))
        .map(m => m[0]);
      expect(below).toEqual([]);
    });
  }
});

describe('the range reader', () => {
  it.each([
    ['>=20.19.0', [20, 19, 0], true],
    ['>= 20.19.0', [20, 19, 0], true],
    ['>= 20.19.0', [18, 0, 0], false],
    ['>=20', [20, 19, 0], true],
    ['>=20', [18, 0, 0], false],
    ['^18.17.0 || >=20.5.0', [20, 19, 0], true],
    ['^18.17.0 || >=20.5.0', [18, 0, 0], false],
    ['^18.17.0 || >=20.5.0', [18, 17, 0], false],
    ['^18.17.0 || ^20 || >=21', [20, 19, 0], true],
    ['^18.17.0 || ^20 || >=22', [20, 19, 0], false],
    ['^14.21.3 || >=16', [18, 0, 0], true],
    ['>=16 <22', [20, 19, 0], false],
  ] as Array<[string, Version, boolean]>)('%s admits every version from %j: %s', (range, floor, expected) => {
    expect(admitsEverythingFrom(floor, range)).toBe(expected);
  });

  it('refuses a form it does not read instead of passing it', () => {
    expect(() => admitsEverythingFrom([20, 19, 0], '20.x')).toThrow(/unsupported/);
    expect(() => admitsEverythingFrom([20, 19, 0], '18.0.0 - 22.0.0')).toThrow(/unsupported/);
  });
});
