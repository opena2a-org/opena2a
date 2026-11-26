/**
 * What `opena2a init` writes, held to what the command index declares.
 *
 * The init entry of src/semantic/command-index.json lists the files init
 * writes in the project (`writesInProject`) and outside it
 * (`writesOutsideProject`), each with the condition under which it is
 * written. This suite runs the built CLI against a temporary project with
 * HOME (and, in some cases, XDG_CONFIG_HOME) pointed at temporary folders,
 * with telemetry on and off, on a first run and a later run, and checks that
 * the files created, changed or deleted are exactly the ones the index
 * declares for that condition: no file the index leaves out, and no declared
 * file that was not written.
 *
 * A local server stands in for the Registry (advisory list and telemetry
 * endpoint), so nothing leaves the machine. dist/index.js must exist
 * (`npm run build`).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

const CLI_PATH = path.resolve(__dirname, '../../dist/index.js');
const INDEX_PATH = path.resolve(__dirname, '../../src/semantic/command-index.json');
const README_PATH = path.resolve(__dirname, '../../../../README.md');
const COMMANDS_DOC_PATH = path.resolve(__dirname, '../../../../docs/commands.md');

type Change = 'append' | 'write' | 'create' | 'delete' | 'transient';
type Observed = 'created' | 'changed' | 'deleted';

interface DeclaredWrite {
  path: string;
  change: Change;
  when: Record<string, string | string[]>;
  note: string;
}

interface IndexEntry {
  id: string;
  description: string;
  writesInProject?: unknown;
  writesOutsideProject?: unknown;
}

/** The conditions a run is made under, in the vocabulary of `when`. */
interface Condition {
  XDG_CONFIG_HOME: 'set' | 'unset';
  telemetry: 'on' | 'off';
  telemetryFile: 'no install id' | 'install id' | 'install id, no enabled field' | 'install id, enabled false';
  advisories: 'read from the Registry' | 'from the cache' | 'turned off';
  eventsFile: 'absent' | 'under 10 MB' | 'over 10 MB';
  secretlessOnPath: 'yes' | 'no';
}

function initEntry(): IndexEntry {
  const index = JSON.parse(fs.readFileSync(INDEX_PATH, 'utf-8')) as IndexEntry[];
  const entry = index.find(e => e.id === 'init');
  if (!entry) throw new Error('command-index.json has no init entry');
  return entry;
}

function declaredWrites(): DeclaredWrite[] {
  const list = initEntry().writesOutsideProject;
  if (!Array.isArray(list)) {
    throw new Error('the init entry of command-index.json declares no writesOutsideProject list');
  }
  return list as DeclaredWrite[];
}

function applies(write: DeclaredWrite, cond: Condition): boolean {
  return Object.entries(write.when).every(([key, want]) => {
    const have = (cond as unknown as Record<string, string>)[key];
    if (have === undefined) throw new Error(`unknown condition "${key}" in command-index.json`);
    return Array.isArray(want) ? want.includes(have) : want === have;
  });
}

/** Every regular file below `root`, by path relative to `base`, with a hash of its content. */
function snapshot(root: string, base: string, into = new Map<string, string>()): Map<string, string> {
  if (!fs.existsSync(root)) return into;
  for (const ent of fs.readdirSync(root, { withFileTypes: true })) {
    const full = path.join(root, ent.name);
    if (ent.isDirectory()) snapshot(full, base, into);
    else if (ent.isFile()) {
      into.set(path.relative(base, full), createHash('sha256').update(fs.readFileSync(full)).digest('hex'));
    }
  }
  return into;
}

function diff(before: Map<string, string>, after: Map<string, string>): Map<string, Observed> {
  const out = new Map<string, Observed>();
  for (const [p, h] of after) {
    if (!before.has(p)) out.set(p, 'created');
    else if (before.get(p) !== h) out.set(p, 'changed');
  }
  for (const p of before.keys()) if (!after.has(p)) out.set(p, 'deleted');
  return out;
}

function globRegex(pattern: string): RegExp {
  const escaped = pattern.split('*').map(s => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*');
  return new RegExp(`^${escaped}$`);
}

let server: http.Server;
let registryUrl = '';
let scratch = '';
let plainBin = '';
let secretlessBin = '';

beforeAll(async () => {
  server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      if (req.method === 'GET' && req.url?.startsWith('/api/v1/trust/advisories')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ advisories: [], total: 0, format: 'osv' }));
        return;
      }
      res.writeHead(204);
      res.end();
    });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  registryUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-init-home-'));
  plainBin = binDir('plain', false);
  secretlessBin = binDir('secretless', true);
});

afterAll(async () => {
  await new Promise<void>(resolve => server.close(() => resolve()));
  if (scratch) fs.rmSync(scratch, { recursive: true, force: true });
});

interface Place {
  home: string;
  xdg: string | null;
  project: string;
  tmp: string;
}

const SECRETLESS_BIN = path.resolve(__dirname, '../../../../node_modules/.bin/secretless-ai');

/**
 * A PATH holding node and git and, when asked, the secretless-ai program
 * opena2a-cli depends on, and nothing else: a helper installed on the
 * machine that runs the suite does not decide what init writes.
 */
function binDir(name: string, withSecretless: boolean): string {
  const dir = path.join(scratch, `bin-${name}`);
  fs.mkdirSync(dir, { recursive: true });
  fs.symlinkSync(process.execPath, path.join(dir, 'node'));
  const git = ['/usr/bin/git', '/usr/local/bin/git', '/opt/homebrew/bin/git'].find(p => fs.existsSync(p));
  if (git) fs.symlinkSync(git, path.join(dir, 'git'));
  if (withSecretless) fs.symlinkSync(fs.realpathSync(SECRETLESS_BIN), path.join(dir, 'secretless-ai'));
  return dir;
}

/** A temporary project, home and (when asked) config home. */
function makePlace(name: string, withXdg: boolean): Place {
  const root = path.join(scratch, name);
  const place: Place = {
    home: path.join(root, 'home'),
    xdg: withXdg ? path.join(root, 'xdg-config') : null,
    project: path.join(root, 'project'),
    tmp: path.join(root, 'tmp'),
  };
  fs.mkdirSync(place.tmp, { recursive: true });
  fs.mkdirSync(place.home, { recursive: true });
  if (place.xdg) fs.mkdirSync(place.xdg, { recursive: true });
  fs.mkdirSync(place.project, { recursive: true });
  fs.writeFileSync(
    path.join(place.project, 'package.json'),
    JSON.stringify({ name: 'demo-agent', version: '1.0.0', dependencies: { express: '4.21.0' } }, null, 2) + '\n',
  );
  fs.writeFileSync(path.join(place.project, 'index.js'), "console.log('hello');\n");
  fs.writeFileSync(path.join(place.project, '.gitignore'), '.env\nnode_modules\n');
  // Point the Registry at the local server: init reads the URL from here.
  fs.mkdirSync(path.join(place.home, '.opena2a'), { recursive: true });
  fs.writeFileSync(
    path.join(place.home, '.opena2a', 'config.json'),
    JSON.stringify({ registry: { url: registryUrl } }, null, 2) + '\n',
  );
  return place;
}

function telemetryFile(place: Place): string {
  return place.xdg
    ? path.join(place.xdg, 'opena2a', 'telemetry.json')
    : path.join(place.home, '.config', 'opena2a', 'telemetry.json');
}

function writeTelemetryFile(place: Place, content: object): void {
  const file = telemetryFile(place);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(content, null, 2) + '\n');
}

function runInit(place: Place, cond: Condition, extraArgs: string[]): Promise<{ code: number | null; output: string }> {
  // A clean environment: nothing from the shell that runs the suite (CI,
  // DO_NOT_TRACK, VITEST) decides whether telemetry is on.
  const env: Record<string, string> = {
    PATH: cond.secretlessOnPath === 'yes' ? secretlessBin : plainBin,
    HOME: place.home,
    USERPROFILE: place.home,
    TMPDIR: place.tmp,
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: cond.telemetry,
    OPENA2A_TELEMETRY_URL: `${registryUrl}/telemetry`,
  };
  if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
  if (place.xdg) env.XDG_CONFIG_HOME = place.xdg;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, 'init', place.project, ...extraArgs], {
      cwd: place.project,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', d => { output += String(d); });
    child.stderr.on('data', d => { output += String(d); });
    child.on('error', reject);
    child.on('close', code => resolve({ code, output }));
  });
}

/**
 * Run init under `cond` and check what it wrote against the index: the
 * project unchanged, and outside it exactly the declared files.
 */
async function expectDeclaredWrites(place: Place, cond: Condition, extraArgs: string[] = []): Promise<void> {
  const outside = [place.home, place.tmp, ...(place.xdg ? [place.xdg] : [])];
  const outsideBefore = new Map<string, string>();
  for (const dir of outside) snapshot(dir, path.dirname(place.home), outsideBefore);
  const projectBefore = snapshot(place.project, place.project);

  const { code, output } = await runInit(place, cond, extraArgs);
  expect(code, output).toBe(0);

  const outsideAfter = new Map<string, string>();
  for (const dir of outside) snapshot(dir, path.dirname(place.home), outsideAfter);

  // Nothing in the project changes.
  expect([...diff(projectBefore, snapshot(place.project, place.project))]).toEqual([]);
  expect(initEntry().writesInProject).toEqual([]);

  // Outside the project: the declared paths, resolved for this place.
  const root = path.dirname(place.home);
  const resolveDeclared = (p: string): string => {
    let abs: string;
    if (p.startsWith('~/')) abs = path.join(place.home, p.slice(2));
    else if (p.startsWith('$TMPDIR/')) abs = path.join(place.tmp, p.slice('$TMPDIR/'.length));
    else if (p.startsWith('$XDG_CONFIG_HOME/')) {
      if (!place.xdg) throw new Error(`${p} declared for a run without XDG_CONFIG_HOME`);
      abs = path.join(place.xdg, p.slice('$XDG_CONFIG_HOME/'.length));
    } else throw new Error(`declared path ${p} is not under ~ or $XDG_CONFIG_HOME`);
    return path.relative(root, abs).split(path.sep).join('/');
  };

  const applicable = declaredWrites().filter(w => applies(w, cond));
  const durable = applicable.filter(w => w.change !== 'transient');
  const observed = diff(outsideBefore, outsideAfter);

  const unexplained: string[] = [];
  const met = new Set<DeclaredWrite>();
  for (const [rel, kind] of observed) {
    const relPosix = rel.split(path.sep).join('/');
    const match = durable.find(w => {
      if (!globRegex(resolveDeclared(w.path)).test(relPosix)) return false;
      if (w.change === 'delete') return kind === 'deleted';
      if (w.change === 'create') return kind === 'created';
      return kind === 'created' || kind === 'changed';
    });
    if (match) met.add(match);
    else unexplained.push(`${relPosix} (${kind})`);
  }
  const unmet = durable.filter(w => !met.has(w)).map(w => `${w.path} (${w.change})`);

  expect({ unexplained, unmet }, `writes under ${JSON.stringify(cond)}`).toEqual({ unexplained: [], unmet: [] });

  // A transient file or folder is gone by the time init ends.
  for (const w of applicable.filter(t => t.change === 'transient')) {
    const target = path.join(root, resolveDeclared(w.path));
    const re = globRegex(path.basename(target));
    const parent = path.dirname(target);
    const left = fs.existsSync(parent) ? fs.readdirSync(parent).filter(n => re.test(n)) : [];
    expect(left, w.path).toEqual([]);
  }
  // Nothing else is left in the temporary directory either.
  expect(fs.readdirSync(place.tmp)).toEqual([]);
}

describe('what opena2a init writes', () => {
  it('dist/index.js exists (run `npm run build` first)', () => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);
  });

  it('the init entry declares its writes as a list of paths with their conditions', () => {
    const entry = initEntry();
    expect(entry.writesInProject).toEqual([]);
    const writes = declaredWrites();
    expect(writes.length).toBeGreaterThan(0);
    for (const w of writes) {
      expect(typeof w.path).toBe('string');
      expect(['append', 'write', 'create', 'delete', 'transient']).toContain(w.change);
      expect(typeof w.when).toBe('object');
      expect(typeof w.note).toBe('string');
    }
  });

  it('docs/commands.md names every file the init entry declares, and README links to it', () => {
    const commands = fs.readFileSync(COMMANDS_DOC_PATH, 'utf-8');
    const start = commands.indexOf('### What init writes');
    expect(start, 'docs/commands.md has a "What init writes" section').toBeGreaterThan(-1);
    const next = commands.indexOf('\n#', start + 1);
    const section = commands.slice(start, next === -1 ? undefined : next);
    for (const w of declaredWrites()) {
      expect(section, w.path).toContain(w.path.split('*')[0]);
    }
    const readme = fs.readFileSync(README_PATH, 'utf-8');
    expect(readme).toContain('(docs/commands.md#what-init-writes)');
  });

  describe('HOME only (XDG_CONFIG_HOME unset)', () => {
    let place: Place;
    beforeAll(() => { place = makePlace('home-only', false); });

    it('telemetry on, first run', async () => {
      await expectDeclaredWrites(place, {
        XDG_CONFIG_HOME: 'unset', telemetry: 'on', telemetryFile: 'no install id',
        advisories: 'read from the Registry', eventsFile: 'absent', secretlessOnPath: 'no',
      });
    }, 120_000);

    it('telemetry on, a later run', async () => {
      await expectDeclaredWrites(place, {
        XDG_CONFIG_HOME: 'unset', telemetry: 'on', telemetryFile: 'install id',
        advisories: 'from the cache', eventsFile: 'under 10 MB', secretlessOnPath: 'no',
      });
    }, 120_000);

    it('telemetry off, with an install ID stored by an earlier run', async () => {
      await expectDeclaredWrites(place, {
        XDG_CONFIG_HOME: 'unset', telemetry: 'off', telemetryFile: 'install id',
        advisories: 'from the cache', eventsFile: 'under 10 MB', secretlessOnPath: 'no',
      });
      expect(fs.existsSync(telemetryFile(place))).toBe(false);
    }, 120_000);

    it('telemetry off, first run, advisories turned off', async () => {
      const fresh = makePlace('home-only-off', false);
      await expectDeclaredWrites(fresh, {
        XDG_CONFIG_HOME: 'unset', telemetry: 'off', telemetryFile: 'no install id',
        advisories: 'turned off', eventsFile: 'absent', secretlessOnPath: 'no',
      }, ['--no-advisories']);
    }, 120_000);

    it('telemetry off, with an install ID beside enabled: false', async () => {
      const fresh = makePlace('home-only-off-choice', false);
      writeTelemetryFile(fresh, { enabled: false, installId: 'placeholder-install-id' });
      await expectDeclaredWrites(fresh, {
        XDG_CONFIG_HOME: 'unset', telemetry: 'off', telemetryFile: 'install id, enabled false',
        advisories: 'read from the Registry', eventsFile: 'absent', secretlessOnPath: 'no',
      });
      expect(JSON.parse(fs.readFileSync(telemetryFile(fresh), 'utf-8'))).toEqual({ enabled: false });
    }, 120_000);

    it('telemetry on, with an install ID and no enabled field', async () => {
      const fresh = makePlace('home-only-no-enabled', false);
      writeTelemetryFile(fresh, { installId: 'placeholder-install-id' });
      await expectDeclaredWrites(fresh, {
        XDG_CONFIG_HOME: 'unset', telemetry: 'on', telemetryFile: 'install id, no enabled field',
        advisories: 'turned off', eventsFile: 'absent', secretlessOnPath: 'no',
      }, ['--no-advisories']);
    }, 120_000);

    it('an event log over 10 MB is renamed before the event is written', async () => {
      const fresh = makePlace('home-only-rotate', false);
      const shieldDir = path.join(fresh.home, '.opena2a', 'shield');
      fs.mkdirSync(shieldDir, { recursive: true });
      fs.writeFileSync(path.join(shieldDir, 'events.jsonl'), 'x'.repeat(10 * 1024 * 1024 + 1) + '\n');
      await expectDeclaredWrites(fresh, {
        XDG_CONFIG_HOME: 'unset', telemetry: 'off', telemetryFile: 'no install id',
        advisories: 'turned off', eventsFile: 'over 10 MB', secretlessOnPath: 'no',
      }, ['--no-advisories']);
    }, 120_000);
  });

  describe('secretless-ai on PATH', () => {
    it('the secretless-ai program opena2a-cli depends on is installed', () => {
      expect(fs.existsSync(SECRETLESS_BIN)).toBe(true);
    });

    it('telemetry on, first run', async () => {
      const fresh = makePlace('secretless-on', false);
      await expectDeclaredWrites(fresh, {
        XDG_CONFIG_HOME: 'unset', telemetry: 'on', telemetryFile: 'no install id',
        advisories: 'turned off', eventsFile: 'absent', secretlessOnPath: 'yes',
      }, ['--no-advisories']);
    }, 120_000);

    it('telemetry off, first run', async () => {
      const fresh = makePlace('secretless-off', false);
      await expectDeclaredWrites(fresh, {
        XDG_CONFIG_HOME: 'unset', telemetry: 'off', telemetryFile: 'no install id',
        advisories: 'turned off', eventsFile: 'absent', secretlessOnPath: 'yes',
      }, ['--no-advisories']);
      expect(JSON.parse(fs.readFileSync(telemetryFile(fresh), 'utf-8')).installId).toEqual(expect.any(String));
    }, 120_000);

    it('telemetry off, with an install ID beside enabled: false', async () => {
      const fresh = makePlace('secretless-off-choice', false);
      writeTelemetryFile(fresh, { enabled: false, installId: 'placeholder-install-id' });
      await expectDeclaredWrites(fresh, {
        XDG_CONFIG_HOME: 'unset', telemetry: 'off', telemetryFile: 'install id, enabled false',
        advisories: 'turned off', eventsFile: 'absent', secretlessOnPath: 'yes',
      }, ['--no-advisories']);
    }, 120_000);

    it('telemetry off, XDG_CONFIG_HOME set, with an install ID stored', async () => {
      const fresh = makePlace('secretless-xdg-off', true);
      writeTelemetryFile(fresh, { enabled: true, installId: 'placeholder-install-id' });
      await expectDeclaredWrites(fresh, {
        XDG_CONFIG_HOME: 'set', telemetry: 'off', telemetryFile: 'install id',
        advisories: 'turned off', eventsFile: 'absent', secretlessOnPath: 'yes',
      }, ['--no-advisories']);
    }, 120_000);
  });

  describe('XDG_CONFIG_HOME set', () => {
    let place: Place;
    beforeAll(() => { place = makePlace('xdg', true); });

    it('telemetry on, first run', async () => {
      await expectDeclaredWrites(place, {
        XDG_CONFIG_HOME: 'set', telemetry: 'on', telemetryFile: 'no install id',
        advisories: 'read from the Registry', eventsFile: 'absent', secretlessOnPath: 'no',
      });
      expect(fs.existsSync(path.join(place.home, '.config'))).toBe(false);
    }, 120_000);

    it('telemetry off, with an install ID stored by an earlier run', async () => {
      await expectDeclaredWrites(place, {
        XDG_CONFIG_HOME: 'set', telemetry: 'off', telemetryFile: 'install id',
        advisories: 'from the cache', eventsFile: 'under 10 MB', secretlessOnPath: 'no',
      });
      expect(fs.existsSync(telemetryFile(place))).toBe(false);
    }, 120_000);

    it('telemetry off, with an install ID beside enabled: false', async () => {
      const fresh = makePlace('xdg-off-choice', true);
      writeTelemetryFile(fresh, { enabled: false, installId: 'placeholder-install-id' });
      await expectDeclaredWrites(fresh, {
        XDG_CONFIG_HOME: 'set', telemetry: 'off', telemetryFile: 'install id, enabled false',
        advisories: 'turned off', eventsFile: 'absent', secretlessOnPath: 'no',
      }, ['--no-advisories']);
    }, 120_000);
  });
});
