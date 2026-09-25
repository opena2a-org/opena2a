/**
 * The release job must prove every first-party pin is SATISFIABLE before it
 * reaches its first irreversible `npm publish` (QGF-145).
 *
 * Publishing cannot be undone. The roster in `.github/workflows/release.yml`
 * publishes eleven workspaces, six of which are pinned at an EXACT version by
 * another workspace in the same roster, and ordering the roster is necessary
 * without being sufficient: `@opena2a/check-core` pins
 * `@opena2a/registry-client 0.1.0` while `packages/registry-client` is `0.2.0`
 * in this tree, and `registry-client` already publishes FIRST. The run produces
 * `0.2.0`. Nothing it produces is `0.1.0`. Whether that pin resolves is a fact
 * about the registry, and no reordering can change it.
 *
 * So this cell holds `scripts/check-first-party-pins.mjs` to four things:
 *
 *   AC1  it derives the roster and the pins from the TREE -- proved against a
 *        synthetic repository whose roster and manifests are nothing like this
 *        one, so a hardcoded copy of either list cannot pass.
 *   AC2  the publish job runs it against the registry between the transport
 *        check and the publish loop, and nothing softens its exit.
 *   AC3  the resolver is injectable, so both directions of the refusal are
 *        reachable with no network -- and the registry is asked only about the
 *        pins the run cannot satisfy itself.
 *   AC4  a run that SKIPS a package while publishing something that package
 *        pins at a same-run version is refused, while the partial-release
 *        completion the loop's idempotence exists to serve stays green.
 *   AC5  the delivery adds a script, a cell and steps -- and edits neither the
 *        roster's membership, nor the publish loop, nor any pin.
 *
 * The base-tree fixtures below are the bytes at d467dc2a5a062a53b91ab4009147a20577df71c2.
 * They are a delivery-scoped invariant, not a freeze: when a pin or the roster
 * legitimately changes, the fixture moves in the same diff, deliberately and
 * visibly, which is the whole point of writing it down.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import yaml from 'js-yaml';

const SCRIPT_REL = 'scripts/check-first-party-pins.mjs';
const WORKFLOW_REL = '.github/workflows/release.yml';
const PACK_STEP = 'Pack every workspace the publish job will sign';
const TRANSPORT_STEP = 'Verify transport integrity (does not attest content)';
const PUBLISH_STEP = 'Publish packages (idempotent — skips versions already on npm)';
const REGISTRY = 'https://registry.npmjs.org/';

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

const ROOT = repoRoot();
const SCRIPT = path.join(ROOT, SCRIPT_REL);

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  /** Everything the run printed, on either stream. */
  text: string;
}

function runScript(args: string[], env?: NodeJS.ProcessEnv): Run {
  const r = spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: 'utf-8',
    env: env ?? process.env,
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, text: `${r.stdout}${r.stderr}` };
}

interface Pin {
  cls: string;
  from: string;
  to: string;
  spec: string;
  line: string;
}

const PIN_LINE = /^(SAME-RUN|RANGE|REGISTRY-DEPENDENT) +(\S+) -> (\S+) "([^"]*)"/;

function parsePins(text: string): Pin[] {
  return text
    .split('\n')
    .map(line => ({ line, m: PIN_LINE.exec(line) }))
    .filter((x): x is { line: string; m: RegExpExecArray } => x.m !== null)
    .map(({ line, m }) => ({ cls: m[1], from: m[2], to: m[3], spec: m[4], line }));
}

const key = (p: { cls: string; from: string; to: string; spec: string }) =>
  `${p.cls} ${p.from} -> ${p.to} "${p.spec}"`;

/**
 * The eight first-party pins the base tree carries.
 *
 * `@opena2a/aicomply` is pinned by `opena2a-cli` and shares the scope, and is
 * deliberately NOT here: it is not a roster entry, so this run does not publish
 * it and the release cannot answer whether it resolves. Its absence is what
 * makes the count eight rather than nine, and it is asserted below.
 */
const BASE_PINS = [
  { cls: 'SAME-RUN', from: 'opena2a-cli', to: '@opena2a/cli-ui', spec: '0.6.0' },
  { cls: 'SAME-RUN', from: 'opena2a-cli', to: '@opena2a/credential-patterns', spec: '0.1.3' },
  { cls: 'SAME-RUN', from: 'opena2a-cli', to: '@opena2a/registry-client', spec: '0.2.0' },
  { cls: 'SAME-RUN', from: 'opena2a-cli', to: '@opena2a/shared', spec: '0.1.2' },
  { cls: 'SAME-RUN', from: 'opena2a-cli', to: '@opena2a/telemetry', spec: '0.3.0' },
  { cls: 'RANGE', from: 'opena2a-cli', to: '@opena2a/aim-core', spec: '*' },
  { cls: 'REGISTRY-DEPENDENT', from: 'opena2a-cli', to: '@opena2a/contribute', spec: '0.1.0' },
  {
    cls: 'REGISTRY-DEPENDENT',
    from: '@opena2a/check-core',
    to: '@opena2a/registry-client',
    spec: '0.1.0',
  },
] as const;

/** The specs the registry is the authority on, and the only ones worth asking about. */
const REGISTRY_DEPENDENT_SPECS = ['@opena2a/contribute@0.1.0', '@opena2a/registry-client@0.1.0'];

/** The eleven roster pairs at base. Compared as a SET: order is QGF-114's business. */
const BASE_ROSTER: ReadonlyArray<readonly [string, string]> = [
  ['packages/cli', 'opena2a-cli'],
  ['packages/shared', '@opena2a/shared'],
  ['packages/cli-ui', '@opena2a/cli-ui'],
  ['packages/contribute', '@opena2a/contribute'],
  ['packages/ai-classifier', '@opena2a/ai-classifier'],
  ['packages/aim-core', '@opena2a/aim-core'],
  ['packages/registry-client', '@opena2a/registry-client'],
  ['packages/check-core', '@opena2a/check-core'],
  ['packages/telemetry', '@opena2a/telemetry'],
  ['packages/credential-patterns', '@opena2a/credential-patterns'],
  ['packages/atx-verify', '@opena2a/atx-verify'],
];

const PIN_BLOCKS = ['dependencies', 'optionalDependencies', 'peerDependencies'] as const;

/**
 * Every pin block present in a roster workspace at base, as RAW BYTES.
 *
 * Bytes rather than parsed objects because the criterion is byte-identity: a
 * reformat that preserves the object is still an edit to a manifest this
 * delivery promised not to touch. A `<workspace>::<block>` absent from this map
 * must be absent from the tree, so the comparison closes in both directions.
 */
const BASE_PIN_BLOCKS: Readonly<Record<string, string>> = {
  'packages/cli::dependencies': [
    '  "dependencies": {',
    '    "@inquirer/prompts": "^7.0.0",',
    '    "@opena2a/aicomply": "2.2.3",',
    '    "@opena2a/cli-ui": "0.6.0",',
    '    "@opena2a/contribute": "0.1.0",',
    '    "@opena2a/credential-patterns": "0.1.3",',
    '    "@opena2a/registry-client": "0.2.0",',
    '    "@opena2a/shared": "0.1.2",',
    '    "@opena2a/telemetry": "0.3.0",',
    '    "ai-trust": "^0.2.23",',
    '    "commander": "^13.1.0",',
    '    "hackmyagent": "0.30.0",',
    '    "secretless-ai": "^0.14.1"',
    '  }',
  ].join('\n'),
  'packages/cli::optionalDependencies': [
    '  "optionalDependencies": {',
    '    "@opena2a/aim-core": "*"',
    '  }',
  ].join('\n'),
  'packages/shared::dependencies': ['  "dependencies": {', '    "zod": "^3.24.0"', '  }'].join('\n'),
  'packages/cli-ui::dependencies': ['  "dependencies": {', '    "chalk": "^5.3.0"', '  }'].join('\n'),
  'packages/aim-core::dependencies': [
    '  "dependencies": {',
    '    "js-yaml": "^4.1.1",',
    '    "tweetnacl": "^1.0.3"',
    '  }',
  ].join('\n'),
  'packages/registry-client::dependencies': [
    '  "dependencies": {',
    '    "tweetnacl": "^1.0.3"',
    '  }',
  ].join('\n'),
  'packages/check-core::dependencies': [
    '  "dependencies": {',
    '    "@opena2a/registry-client": "0.1.0"',
    '  }',
  ].join('\n'),
  'packages/atx-verify::dependencies': [
    '  "dependencies": {',
    '    "canonicalize": "2.1.0"',
    '  }',
  ].join('\n'),
};

/**
 * The raw text of one top-level object block, brace-matched.
 *
 * The key is searched with its leading newline and indentation so
 * `"dependencies"` cannot match inside `"devDependencies"`,
 * `"peerDependencies"` or `"optionalDependencies"`.
 */
function rawBlock(text: string, blockKey: string): string | null {
  const open = `\n  "${blockKey}": {`;
  const at = text.indexOf(open);
  if (at === -1) return null;
  let depth = 0;
  for (let i = text.indexOf('{', at); i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}' && --depth === 0) return text.slice(at + 1, i + 1);
  }
  throw new Error(`unterminated "${blockKey}" block`);
}

function readWorkflow(): string {
  return fs.readFileSync(path.join(ROOT, WORKFLOW_REL), 'utf-8');
}

interface WorkflowStep {
  name?: string;
  uses?: string;
  run?: string;
  'continue-on-error'?: unknown;
}

function publishSteps(): WorkflowStep[] {
  const doc = yaml.load(readWorkflow()) as { jobs: { publish: { steps: WorkflowStep[] } } };
  return doc.jobs.publish.steps;
}

/** The `const wss = [...]` roster, read the way the script reads it. */
function rosterFromWorkflow(): Array<[string, string]> {
  const text = readWorkflow();
  const stepAt = text.indexOf(`- name: ${PACK_STEP}`);
  expect(stepAt, `${WORKFLOW_REL} has no "${PACK_STEP}" step`).toBeGreaterThan(-1);
  const openAt = text.indexOf('const wss = [', stepAt);
  const closeAt = text.indexOf('];', openAt);
  expect(openAt, 'no `const wss = [` array inside the pack step').toBeGreaterThan(-1);
  const body = text.slice(openAt + 'const wss = ['.length, closeAt);
  return [...body.matchAll(/\[\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\]/g)].map(m => [m[1], m[2]]);
}

// ---------------------------------------------------------------------------

describe('QGF-145.AC1 first-party pins are classified from the tree', () => {
  let pins: Pin[];
  let report: Run;

  beforeAll(() => {
    report = runScript([]);
  });

  it('QGF-145.AC1 reports the base tree\'s eight first-party pins in three classes', () => {
    expect(report.status, report.text).toBe(0);
    pins = parsePins(report.stdout);

    expect(pins.map(key).sort()).toEqual(BASE_PINS.map(key).sort());
    expect(pins).toHaveLength(8);

    const byClass = (cls: string) => pins.filter(p => p.cls === cls).length;
    expect(byClass('SAME-RUN')).toBe(5);
    expect(byClass('RANGE')).toBe(1);
    expect(byClass('REGISTRY-DEPENDENT')).toBe(2);
    expect(report.stdout).toContain(
      '8 first-party pin(s) across 11 roster workspace(s): 5 SAME-RUN, 1 RANGE, ' +
        '2 REGISTRY-DEPENDENT',
    );
  });

  it('QGF-145.AC1 names the block and the in-tree version on every line', () => {
    const lines = parsePins(runScript([]).stdout);
    const find = (from: string, to: string) =>
      lines.find(p => p.from === from && p.to === to)?.line ?? '';

    // The range is an OPTIONAL dependency and the workspace behind it is 0.2.0 --
    // the two facts that make "*" a range rather than an unsatisfiable pin.
    expect(find('opena2a-cli', '@opena2a/aim-core')).toContain('optionalDependencies');
    expect(find('opena2a-cli', '@opena2a/aim-core')).toContain('packages/aim-core is 0.2.0');

    // Both registry-dependent pins name a version this run does not publish.
    expect(find('opena2a-cli', '@opena2a/contribute')).toContain('packages/contribute is 0.3.0');
    expect(find('@opena2a/check-core', '@opena2a/registry-client')).toContain(
      'packages/registry-client is 0.2.0',
    );
  });

  it('QGF-145.AC1 classifies only pins that are themselves roster entries', () => {
    // `@opena2a/aicomply` is pinned by `opena2a-cli` and carries the scope, but
    // this run does not publish it, so the release has nothing to say about it.
    expect(runScript([]).stdout).not.toContain('@opena2a/aicomply');
  });

  it('QGF-145.AC1 derives both inputs from the repository rather than a copied list', () => {
    // A synthetic repository sharing nothing with this one: a two-entry roster,
    // different package names, and -- ahead of the real pack step -- a DECOY
    // `const wss` naming a workspace that does not exist. A script carrying a
    // hardcoded roster, or one that grabs the first `const wss` it sees rather
    // than the one inside the named step, cannot produce the expected output.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-pins-derive-'));
    try {
      fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
      fs.mkdirSync(path.join(dir, '.github/workflows'), { recursive: true });
      fs.mkdirSync(path.join(dir, 'packages/alpha'), { recursive: true });
      fs.mkdirSync(path.join(dir, 'packages/beta'), { recursive: true });
      fs.copyFileSync(SCRIPT, path.join(dir, SCRIPT_REL));
      fs.writeFileSync(
        path.join(dir, WORKFLOW_REL),
        [
          'jobs:',
          '  build:',
          '    steps:',
          '      - name: Some earlier step that also writes a wss array',
          '        run: |',
          '          const wss = [',
          '            ["packages/decoy","@fixture/decoy"],',
          '          ];',
          `      - name: ${PACK_STEP}`,
          '        run: |',
          '          const wss = [',
          '            ["packages/alpha","@fixture/alpha"],["packages/beta","@fixture/beta"],',
          '          ];',
          '',
        ].join('\n'),
      );
      fs.writeFileSync(
        path.join(dir, 'packages/alpha/package.json'),
        JSON.stringify(
          { name: '@fixture/alpha', version: '2.0.0', dependencies: { '@fixture/beta': '1.0.0' } },
          null,
          2,
        ),
      );
      fs.writeFileSync(
        path.join(dir, 'packages/beta/package.json'),
        JSON.stringify({ name: '@fixture/beta', version: '1.5.0' }, null, 2),
      );

      const r = spawnSync(process.execPath, [path.join(dir, SCRIPT_REL)], { encoding: 'utf-8' });
      expect(r.status, `${r.stdout}${r.stderr}`).toBe(0);
      expect(parsePins(r.stdout).map(key)).toEqual([
        'REGISTRY-DEPENDENT @fixture/alpha -> @fixture/beta "1.0.0"',
      ]);
      expect(r.stdout).toContain('1 first-party pin(s) across 2 roster workspace(s)');
      expect(r.stdout).not.toContain('opena2a');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('QGF-145.AC2 the publish job resolves pins before it publishes', () => {
  it('QGF-145.AC2 runs the pins script between the transport check and the publish loop', () => {
    const steps = publishSteps();
    const nameAt = (name: string) => steps.findIndex(s => s.name === name);
    const transport = nameAt(TRANSPORT_STEP);
    const publish = nameAt(PUBLISH_STEP);
    const gate = steps.findIndex(s => typeof s.run === 'string' && s.run.includes(SCRIPT_REL));

    expect(transport, `no "${TRANSPORT_STEP}" step`).toBeGreaterThan(-1);
    expect(publish, `no "${PUBLISH_STEP}" step`).toBeGreaterThan(-1);
    expect(gate, `no publish-job step runs ${SCRIPT_REL}`).toBeGreaterThan(-1);
    expect(gate).toBeGreaterThan(transport);
    expect(gate).toBeLessThan(publish);
    expect(steps[gate].run).toContain('--resolve');
    expect(steps[gate].run).toContain(REGISTRY);
  });

  it('QGF-145.AC2 lets nothing on the gate or in the script soften a non-zero exit', () => {
    const steps = publishSteps();
    const gate = steps.find(s => typeof s.run === 'string' && s.run.includes(SCRIPT_REL))!;
    expect(gate).toBeDefined();
    expect('continue-on-error' in gate).toBe(false);

    const suppression = /\|\|\s*true/;
    for (const step of steps) {
      if (typeof step.run === 'string' && step.run.includes(SCRIPT_REL)) {
        expect(step.run, `${step.name} suppresses its own failure`).not.toMatch(suppression);
      }
    }
    expect(fs.readFileSync(SCRIPT, 'utf-8')).not.toMatch(suppression);
  });

  it('QGF-145.AC2 asks npm view for exactly the registry-dependent specs, against npmjs.org', () => {
    // The real resolver, with `npm` itself stubbed on PATH: this is what the
    // publish job runs, minus the network. The stub records its argv, so the
    // command shape the criterion names is measured rather than read out of the
    // script's source.
    const stub = executableScratchDir();
    try {
      const log = path.join(stub, 'npm-argv.log');
      writeNpmStub(stub, log, { exitCode: 0, stdout: '9.9.9\n' });
      const r = runScript(['--resolve', '--registry', REGISTRY], {
        ...process.env,
        PATH: `${stub}${path.delimiter}${process.env.PATH ?? ''}`,
      });

      expect(r.status, r.text).toBe(0);
      const calls = fs.readFileSync(log, 'utf-8').trim().split('\n');
      expect(calls).toEqual(
        REGISTRY_DEPENDENT_SPECS.map(spec => `view ${spec} version --registry=${REGISTRY}`),
      );
    } finally {
      fs.rmSync(stub, { recursive: true, force: true });
    }
  });

  it('QGF-145.AC2 exits non-zero when the registry does not have the pinned version', () => {
    const stub = executableScratchDir();
    try {
      const log = path.join(stub, 'npm-argv.log');
      // What the real registry returns for a version that is not there.
      writeNpmStub(stub, log, {
        exitCode: 1,
        stderr: "npm error code E404\nnpm error 404 Not Found - GET https://registry.npmjs.org/\n",
      });
      const r = runScript(['--resolve', '--registry', REGISTRY], {
        ...process.env,
        PATH: `${stub}${path.delimiter}${process.env.PATH ?? ''}`,
      });

      expect(r.status, r.text).not.toBe(0);
      expect(r.text).toContain('@opena2a/contribute');
      expect(r.text).toContain('@opena2a/registry-client');
    } finally {
      fs.rmSync(stub, { recursive: true, force: true });
    }
  });

  it('QGF-145.AC2 exits non-zero when the registry could not be measured at all', () => {
    // An unreachable registry, a proxy, a rate limit: npm fails without an
    // E404. "Unknown" reading as "resolvable" is the one direction this gate
    // must never fail in, so it is refused rather than passed.
    const stub = executableScratchDir();
    try {
      const log = path.join(stub, 'npm-argv.log');
      writeNpmStub(stub, log, {
        exitCode: 1,
        stderr: 'npm error network request to https://registry.npmjs.org/ failed: ECONNREFUSED\n',
      });
      const r = runScript(['--resolve', '--registry', REGISTRY], {
        ...process.env,
        PATH: `${stub}${path.delimiter}${process.env.PATH ?? ''}`,
      });

      expect(r.status, r.text).not.toBe(0);
      expect(r.text).toContain('UNKNOWN');
    } finally {
      fs.rmSync(stub, { recursive: true, force: true });
    }
  });
});

describe('QGF-145.AC3 the resolver is injectable, so the refusal needs no network', () => {
  let dir = '';
  let queryLog = '';

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-pins-resolver-'));
    queryLog = path.join(dir, 'queried.log');
  });

  afterAll(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  /** A resolver module that records every spec it is asked about. */
  function resolverModule(name: string, verdict: string): string {
    const file = path.join(dir, name);
    fs.writeFileSync(
      file,
      [
        "import { appendFileSync } from 'node:fs';",
        `const LOG = ${JSON.stringify(queryLog)};`,
        'export default function resolve(pkg, version) {',
        "  appendFileSync(LOG, pkg + '@' + version + '\\n');",
        `  return ${verdict};`,
        '}',
        '',
      ].join('\n'),
    );
    return file;
  }

  it('QGF-145.AC3 refuses, naming the pin, when the pinned version is absent', () => {
    const mod = resolverModule(
      'contribute-absent.mjs',
      "!(pkg === '@opena2a/contribute' && version === '0.1.0')",
    );
    const r = runScript(['--resolve', '--resolver-module', mod]);

    expect(r.status, r.text).not.toBe(0);
    expect(r.text).toContain('opena2a-cli');
    expect(r.text).toContain('@opena2a/contribute');
    expect(r.text).toContain('0.1.0');
  });

  it('QGF-145.AC3 exits 0 when every queried spec is present', () => {
    const r = runScript(['--resolve', '--resolver-module', resolverModule('all-present.mjs', 'true')]);
    expect(r.status, r.text).toBe(0);
  });

  it('QGF-145.AC3 queries the registry-dependent pins and not the same-run ones', () => {
    fs.writeFileSync(queryLog, '');
    const r = runScript(['--resolve', '--resolver-module', resolverModule('recording.mjs', 'true')]);
    expect(r.status, r.text).toBe(0);

    const queried = fs.readFileSync(queryLog, 'utf-8').trim().split('\n').filter(Boolean);
    expect(queried.sort()).toEqual([...REGISTRY_DEPENDENT_SPECS].sort());

    // Nothing this run publishes itself was asked about: a same-run pin is
    // answered by the roster, and a range is answered by npm at install time.
    for (const pin of BASE_PINS.filter(p => p.cls !== 'REGISTRY-DEPENDENT')) {
      expect(queried).not.toContain(`${pin.to}@${pin.spec}`);
    }
  });
});

describe('QGF-145.AC4 a run that skips a package it just published a dependency of', () => {
  let dir = '';

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-pins-coherence-'));
  });

  afterAll(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  /** The TSV the publish loop writes: `pkg<TAB>version` per line. */
  function list(name: string, entries: ReadonlyArray<readonly [string, string]>): string {
    const file = path.join(dir, name);
    fs.writeFileSync(file, entries.map(([pkg, version]) => `${pkg}\t${version}`).join('\n') + '\n');
    return file;
  }

  it('QGF-145.AC4 refuses a skipped cli beside a published dependency it pins', () => {
    const r = runScript([
      '--coherence',
      '--skipped',
      list('skipped-cli.txt', [['opena2a-cli', '0.10.13']]),
      '--published',
      list('published-cli-ui.txt', [['@opena2a/cli-ui', '0.6.0']]),
    ]);

    expect(r.status, r.text).not.toBe(0);
    expect(r.text).toContain('opena2a-cli');
    expect(r.text).toContain('@opena2a/cli-ui');
    expect(r.text).toContain('0.6.0');
  });

  it('QGF-145.AC4 stays green when every roster entry was skipped and nothing published', () => {
    // The completed partial release the loop's idempotence exists to serve. It
    // is the direction that must not go red, or the gate makes a re-run of a
    // half-finished release impossible.
    const r = runScript([
      '--coherence',
      '--skipped',
      list(
        'skipped-all.txt',
        BASE_ROSTER.map(([ws, pkg]) => {
          const manifest = JSON.parse(
            fs.readFileSync(path.join(ROOT, ws, 'package.json'), 'utf-8'),
          );
          return [pkg, manifest.version] as const;
        }),
      ),
      '--published',
      list('published-none.txt', []),
    ]);

    expect(r.status, r.text).toBe(0);
    expect(r.stdout).toContain('Coherent');
  });

  it('QGF-145.AC4 runs as a publish-job step placed after the publish loop', () => {
    const steps = publishSteps();
    const publish = steps.findIndex(s => s.name === PUBLISH_STEP);
    const coherence = steps.findIndex(
      s => typeof s.run === 'string' && s.run.includes('--coherence'),
    );

    expect(coherence, 'no publish-job step runs the coherence check').toBeGreaterThan(-1);
    expect(coherence).toBeGreaterThan(publish);
    expect(steps[coherence].run).toContain(SCRIPT_REL);
    expect(steps[coherence].run).toContain('/tmp/skipped.txt');
    expect(steps[coherence].run).toContain('/tmp/published.txt');
    expect('continue-on-error' in steps[coherence]).toBe(false);
  });
});

describe('QGF-145.AC5 the roster, the publish loop and every pin are untouched', () => {
  it('QGF-145.AC5 keeps the roster at the same eleven [workspace, package] pairs', () => {
    const roster = rosterFromWorkflow();
    expect(roster).toHaveLength(11);
    // Membership, not sequence: the roster's ORDER is deliberately left free.
    expect(roster.map(p => p.join(' -> ')).sort()).toEqual(
      BASE_ROSTER.map(p => p.join(' -> ')).sort(),
    );
  });

  it('QGF-145.AC5 leaves the publish loop reading npm view before it publishes', () => {
    const loop = publishSteps().find(s => s.name === PUBLISH_STEP)?.run ?? '';
    const viewAt = loop.indexOf('npm view "$pkg@$version" version');
    const publishAt = loop.indexOf('npm publish "$file" --provenance --access public');

    expect(viewAt, 'the idempotence probe is gone from the publish loop').toBeGreaterThan(-1);
    expect(publishAt, 'the publish invocation changed shape').toBeGreaterThan(-1);
    expect(viewAt).toBeLessThan(publishAt);
    expect(loop).toContain(`--registry=${REGISTRY}`);
  });

  it('QGF-145.AC5 leaves every roster workspace\'s pin blocks byte-identical to the base tree', () => {
    const seen: Record<string, string> = {};
    for (const [ws] of BASE_ROSTER) {
      const text = fs.readFileSync(path.join(ROOT, ws, 'package.json'), 'utf-8');
      for (const block of PIN_BLOCKS) {
        const raw = rawBlock(text, block);
        if (raw !== null) seen[`${ws}::${block}`] = raw;
      }
    }
    // Symmetric: a changed pin fails, a reformatted block fails, and a block
    // that appeared or disappeared fails on the key set alone.
    expect(seen).toEqual(BASE_PIN_BLOCKS);
  });
});

// ---------------------------------------------------------------------------
// Stub plumbing for the two AC2 cells that drive the REAL npm-backed resolver.
// ---------------------------------------------------------------------------

/**
 * A directory the stubs can be executed from. `os.tmpdir()` first; if that
 * filesystem is mounted `noexec` the stub is skipped by execvp and the real
 * `npm` further down PATH would answer instead, so fall back to a scratch
 * directory inside this package.
 */
function executableScratchDir(): string {
  const candidates = [os.tmpdir(), path.resolve(__dirname, '..')];
  for (const base of candidates) {
    const dir = fs.mkdtempSync(path.join(base, '.opena2a-npm-stub-'));
    const probe = path.join(dir, 'probe');
    fs.writeFileSync(probe, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    if (spawnSync(probe, [], { stdio: 'ignore' }).status === 0) return dir;
    fs.rmSync(dir, { recursive: true, force: true });
  }
  throw new Error(`no executable scratch directory among ${candidates.join(', ')}`);
}

/** An `npm` on PATH that records its argv and answers however the case needs. */
function writeNpmStub(
  dir: string,
  log: string,
  answer: { exitCode: number; stdout?: string; stderr?: string },
): void {
  const js = path.join(dir, 'npm-stub.js');
  fs.writeFileSync(
    js,
    [
      "const fs = require('node:fs');",
      `fs.appendFileSync(${JSON.stringify(log)}, process.argv.slice(2).join(' ') + '\\n');`,
      `process.stdout.write(${JSON.stringify(answer.stdout ?? '')});`,
      `process.stderr.write(${JSON.stringify(answer.stderr ?? '')});`,
      `process.exit(${answer.exitCode});`,
      '',
    ].join('\n'),
  );
  // The absolute node path is baked in so the stub does not depend on where
  // node sits in the PATH the child is given.
  fs.writeFileSync(
    path.join(dir, 'npm'),
    `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(js)} "$@"\n`,
    { mode: 0o755 },
  );
}
