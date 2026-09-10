/**
 * What the CANDIDATE consumer audit does with the branch's own workspace
 * siblings.
 *
 * The gate under test installs the tarball this branch would publish and reads
 * the advisory report over the resulting tree. Every `@opena2a/*` dependency in
 * that tarball's manifest is pinned at an exact version, and on a branch that
 * bumps one of them the pinned version is not published yet — so the install
 * used to die on resolution (`npm error notarget`) before any advisory was
 * measured, and the gate reported a failure about npm rather than about the
 * change under review.
 *
 * These tests run the real gate as a child process with a test double for the
 * npm CLI on PATH (see `fixtures/fake-npm.mjs`). The registry, the advisory
 * database and `npm pack` are all modelled there; everything else — the gate's
 * own decisions, its exit code and its output — is the real thing.
 *
 * The dependency set is not typed in here. It is read out of
 * `packages/cli/package.json` on the branch under test, so the cases stay
 * pinned to what this repository actually ships: which scoped dependencies have
 * a workspace directory, and which one pins a version its own workspace no
 * longer carries.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const GATE = path.join(REPO_ROOT, 'scripts', 'audit-consumer-resolution.mjs');
const FAKE_NPM = path.join(HERE, 'fixtures', 'fake-npm.mjs');
const SCOPE = '@opena2a/';

const CLI_MANIFEST = JSON.parse(
  readFileSync(path.join(REPO_ROOT, 'packages', 'cli', 'package.json'), 'utf8')
);

/** Every `@opena2a/*` production dependency of the CLI this branch would pack. */
const SCOPED_DEPS = Object.fromEntries(
  Object.entries(CLI_MANIFEST.dependencies ?? {}).filter(([name]) => name.startsWith(SCOPE))
);

function workspaceManifest(dir) {
  const file = path.join(REPO_ROOT, 'packages', dir, 'package.json');
  return existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null;
}

const SCOPED = Object.entries(SCOPED_DEPS).map(([name, pinned]) => {
  const dir = name.slice(SCOPE.length);
  const manifest = workspaceManifest(dir);
  return { name, dir, pinned, workspaceVersion: manifest?.version ?? null, isSibling: manifest !== null };
});

/** Scoped dependencies that `packages/<dir>` can build from this branch. */
const SIBLINGS = SCOPED.filter((d) => d.isSibling);
/** Scoped dependencies that nothing in this tree can build. */
const NON_SIBLINGS = SCOPED.filter((d) => !d.isSibling);
/** Siblings whose pin the branch can reproduce exactly. */
const ALIGNED = SIBLINGS.filter((d) => d.pinned === d.workspaceVersion);
/** Siblings pinned at a version their own workspace no longer carries. */
const DRIFTED = SIBLINGS.filter((d) => d.pinned !== d.workspaceVersion);

const GHSA = 'GHSA-xcpc-8h2w-3j85';

const CLEAN_REPORT = {
  vulnerabilities: {},
  metadata: { vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 0, total: 0 } },
};

const HIGH_ADVISORY_REPORT = {
  vulnerabilities: {
    'adm-zip': {
      name: 'adm-zip',
      severity: 'high',
      isDirect: false,
      via: [
        {
          source: 1105443,
          name: 'adm-zip',
          dependency: 'adm-zip',
          title: 'adm-zip Arbitrary File Write via Archive Extraction',
          url: `https://github.com/advisories/${GHSA}`,
          severity: 'high',
          range: '<0.6.0',
        },
      ],
      effects: [],
      range: '<0.6.0',
      nodes: ['node_modules/adm-zip'],
      fixAvailable: false,
    },
  },
  metadata: { vulnerabilities: { critical: 0, high: 1, moderate: 0, low: 0, total: 1 } },
};

/**
 * The consumer tree the gate expects to find below the CLI: one nested copy of
 * `hackmyagent` under its waiver in FORBIDDEN_PACKAGES, plus the intermediate
 * that pulls it. Without this the gate fails every scenario with "stale waiver"
 * — correctly, since a waiver for a package that is no longer nested is a
 * defect — so the fixture models the tree the waiver describes.
 */
const NESTED_HACKMYAGENT = {
  'node_modules/hackmyagent': {
    version: '0.30.0',
    resolved: 'https://registry.npmjs.org/hackmyagent/-/hackmyagent-0.30.0.tgz',
  },
  'node_modules/ai-trust': {
    version: '0.2.23',
    resolved: 'https://registry.npmjs.org/ai-trust/-/ai-trust-0.2.23.tgz',
    dependencies: { hackmyagent: '^0.25.0' },
  },
  'node_modules/ai-trust/node_modules/hackmyagent': {
    version: '0.25.2',
    resolved: 'https://registry.npmjs.org/hackmyagent/-/hackmyagent-0.25.2.tgz',
  },
};

const WAIVER_FACTS = {
  latest: { 'ai-trust': { name: 'ai-trust', version: '0.2.23', dependencies: { hackmyagent: '^0.25.0' } } },
  versions: { 'hackmyagent@^0.25.0': ['0.25.0', '0.25.1', '0.25.2'] },
};

/**
 * A scratch root whose files can be executed.
 *
 * The double is put on PATH as `npm`, so the kernel has to be willing to exec
 * it — and a PATH entry whose `npm` is not executable is SKIPPED rather than
 * refused, which would send the gate to the real npm and this suite to the real
 * registry. `os.tmpdir()` is mounted `noexec` in some containers, so the
 * location is chosen by trying it rather than assumed, and a tree where nothing
 * works fails loudly instead of measuring the wrong thing.
 */
function execCapable(dir) {
  const probe = path.join(dir, 'exec-probe');
  writeFileSync(probe, '#!/bin/sh\nexit 7\n');
  chmodSync(probe, 0o755);
  const ran = spawnSync(probe, [], { encoding: 'utf8' });
  rmSync(probe, { force: true });
  return ran.status === 7;
}

let scratchRoot;
function scratchRootDir() {
  if (scratchRoot) return scratchRoot;
  const tried = [];
  // `node_modules/.cache` is the fallback because it is git-ignored and lives
  // on the same filesystem as the checkout, which has to be executable for
  // anything in this repository to run at all.
  for (const root of [tmpdir(), path.join(REPO_ROOT, 'node_modules', '.cache')]) {
    tried.push(root);
    try {
      mkdirSync(root, { recursive: true });
      const dir = mkdtempSync(path.join(root, 'qgf97-exec-'));
      const usable = execCapable(dir);
      rmSync(dir, { recursive: true, force: true });
      if (usable) {
        scratchRoot = root;
        return root;
      }
    } catch {
      // Try the next candidate.
    }
  }
  throw new Error(
    `no scratch directory here can execute a file (tried ${tried.join(', ')}), so the npm ` +
      'double cannot be put on PATH and these tests would silently measure the real registry.'
  );
}

function tarball(dir, manifest) {
  const src = path.join(dir, 'packsrc');
  mkdirSync(path.join(src, 'package'), { recursive: true });
  writeFileSync(
    path.join(src, 'package', 'package.json'),
    JSON.stringify(manifest, null, 2) + '\n'
  );
  const out = path.join(dir, `${manifest.name}-${manifest.version}.tgz`);
  const packed = spawnSync('tar', ['-czf', out, '-C', src, 'package'], { encoding: 'utf8' });
  if (packed.status !== 0) {
    throw new Error(
      `could not build a candidate tarball with tar (status ${packed.status}): ${packed.stderr ?? packed.error}`
    );
  }
  return out;
}

/**
 * Run the real gate against a candidate tarball, with npm replaced by the
 * double. `scopedDeps` is what the packed manifest declares; `served` is what
 * the registry answers for; `audit` is the report.
 */
function runGate({ scopedDeps = SCOPED_DEPS, served = [], audit = CLEAN_REPORT } = {}) {
  const dir = mkdtempSync(path.join(scratchRootDir(), 'qgf97-consumer-audit-'));
  try {
    return measure(dir, { scopedDeps, served, audit });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function measure(dir, { scopedDeps, served, audit }) {
  const manifest = {
    name: CLI_MANIFEST.name,
    version: CLI_MANIFEST.version,
    dependencies: { ...CLI_MANIFEST.dependencies, ...scopedDeps },
  };
  const target = tarball(dir, manifest);

  const callLog = path.join(dir, 'npm-calls.jsonl');
  writeFileSync(callLog, '');
  const fixture = path.join(dir, 'scenario.json');
  writeFileSync(
    fixture,
    JSON.stringify({
      callLog,
      served,
      scopedDeps,
      root: { name: manifest.name, version: manifest.version },
      extraLockPackages: NESTED_HACKMYAGENT,
      audit,
      ...WAIVER_FACTS,
    })
  );

  const bin = path.join(dir, 'bin');
  mkdirSync(bin);
  const shim = path.join(bin, 'npm');
  writeFileSync(shim, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(FAKE_NPM)} "$@"\n`);
  chmodSync(shim, 0o755);

  const run = spawnSync(process.execPath, [GATE, '--target', target], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      QGF97_FAKE_NPM_FIXTURE: fixture,
    },
  });

  const calls = readFileSync(callLog, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const combined = `${run.stdout ?? ''}${run.stderr ?? ''}`;
  if (calls.length === 0) {
    throw new Error(
      'the gate ran without invoking the npm double once, so whatever it measured was not this ' +
        `scenario. Check that ${shim} is on PATH and executable.\nexit=${run.status}\n${combined}`
    );
  }
  return {
    status: run.status,
    combined,
    calls,
    target,
    // The served probe only: `npm view <spec> version`. The waiver derivations
    // use `npm view` too, and they are not decisions about a sibling.
    views: calls.filter(
      (c) => c.argv[0] === 'view' && c.argv[2] === 'version' && !c.argv.includes('--json')
    ),
    packs: calls.filter((c) => c.argv[0] === 'pack'),
    install: calls.find((c) => c.event === 'install') ?? null,
    lock: calls.find((c) => c.event === 'installed')?.lock ?? null,
    context: () => `exit=${run.status}\n${combined}`,
  };
}

/** The `-w packages/<dir>` argument of every pack the gate ran. */
function packedWorkspaces(result) {
  return result.packs.map((c) => c.argv[c.argv.indexOf('-w') + 1]);
}

/** Every spec the gate asked the registry about with `npm view <spec> version`. */
function viewedSpecs(result) {
  return result.views.map((c) => c.argv[1]);
}

// The scenario every positive case reads: the drifted sibling and one aligned
// sibling are published, the remaining aligned siblings are not.
const PUBLISHED = [...DRIFTED, ...ALIGNED.slice(0, 1)];
const UNPUBLISHED = ALIGNED.slice(1);
const RESOLVED_SCENARIO = {
  served: [
    ...NON_SIBLINGS.map((d) => `${d.name}@${d.pinned}`),
    ...PUBLISHED.map((d) => `${d.name}@${d.pinned}`),
  ],
};

let resolvedRun;
function resolved() {
  if (!resolvedRun) resolvedRun = runGate(RESOLVED_SCENARIO);
  return resolvedRun;
}

test('QGF-97.AC1 packs every unserved workspace sibling from this branch and installs the candidate through it', () => {
  assert.ok(
    UNPUBLISHED.length > 0,
    'packages/cli declares no @opena2a/* sibling this scenario can leave unpublished'
  );
  const r = resolved();

  // Every sibling was asked about, and the unserved ones were packed from the
  // branch at the repository root.
  for (const dep of SIBLINGS) {
    assert.ok(
      viewedSpecs(r).includes(`${dep.name}@${dep.pinned}`),
      `${dep.name}@${dep.pinned} was never asked of the registry\n${r.context()}`
    );
  }
  assert.deepEqual(
    packedWorkspaces(r).sort(),
    UNPUBLISHED.map((d) => `packages/${d.dir}`).sort(),
    `packed the wrong workspaces\n${r.context()}`
  );
  for (const pack of r.packs) {
    assert.equal(pack.cwd, REPO_ROOT, `npm pack did not run at the repository root\n${r.context()}`);
    assert.ok(pack.argv.includes('--ignore-scripts'), `npm pack ran without --ignore-scripts\n${r.context()}`);
  }

  // The scratch consumer manifest the probe installed from points each of them
  // at the tarball that pack produced.
  assert.ok(r.install, `the candidate tarball was never installed\n${r.context()}`);
  const overrides = r.install.probeManifest.overrides ?? {};
  assert.deepEqual(
    Object.keys(overrides).sort(),
    UNPUBLISHED.map((d) => d.name).sort(),
    `the probe manifest redirected the wrong dependencies\n${r.context()}`
  );
  for (const dep of UNPUBLISHED) {
    const redirected = r.install.overrideTargets[dep.name];
    assert.ok(
      redirected.spec.startsWith('file:'),
      `${dep.name} was not pointed at a tarball path: ${redirected.spec}\n${r.context()}`
    );
    assert.ok(redirected.exists, `${dep.name} points at a tarball that is not on disk\n${r.context()}`);
    assert.equal(
      redirected.contents,
      `fake pack of packages/${dep.dir}@${dep.workspaceVersion}\n`,
      `${dep.name} does not point at the pack of packages/${dep.dir}\n${r.context()}`
    );
    assert.equal(
      r.lock.packages[`node_modules/${dep.name}`].resolved,
      redirected.spec,
      `${dep.name} did not resolve from the branch's pack\n${r.context()}`
    );
  }

  // And the verdict is the advisory report's: this tree is clean, so it passes.
  assert.match(r.combined, /Consumer resolution: 0 critical, 0 high/, r.context());
  assert.equal(r.status, 0, `the audit failed on a clean tree\n${r.context()}`);
});

test('QGF-97.AC2 leaves a sibling the registry serves resolving from the registry', () => {
  assert.ok(PUBLISHED.length > 0, 'this scenario leaves no @opena2a/* sibling published');
  const r = resolved();
  const overrides = r.install.probeManifest.overrides ?? {};

  for (const dep of PUBLISHED) {
    assert.equal(
      overrides[dep.name],
      undefined,
      `${dep.name} is served at ${dep.pinned} but the probe manifest redirected it\n${r.context()}`
    );
    assert.ok(
      !packedWorkspaces(r).includes(`packages/${dep.dir}`),
      `packages/${dep.dir} was packed although the registry serves ${dep.pinned}\n${r.context()}`
    );
    assert.match(
      r.lock.packages[`node_modules/${dep.name}`].resolved,
      /^https:\/\/registry\.npmjs\.org\//,
      `${dep.name} did not resolve from the registry\n${r.context()}`
    );
  }
});

test('QGF-97.AC3 fails on the advisory, not on resolution, when a sibling is unpublished', () => {
  assert.ok(UNPUBLISHED.length > 0, 'this scenario leaves no @opena2a/* sibling unpublished');
  const r = runGate({ ...RESOLVED_SCENARIO, audit: HIGH_ADVISORY_REPORT });

  assert.notEqual(r.status, 0, `the audit passed with an unlisted high advisory\n${r.context()}`);
  assert.ok(r.combined.includes(GHSA), `the audit never named ${GHSA}\n${r.context()}`);
  assert.equal(
    r.combined.split('notarget').length - 1,
    0,
    `the audit still fails on resolution — it said "notarget"\n${r.context()}`
  );
  assert.equal(
    r.combined.split('ETARGET').length - 1,
    0,
    `the audit still fails on resolution — it said "ETARGET"\n${r.context()}`
  );
});

test('QGF-97.AC4 never packs or redirects a scoped dependency that is not a workspace sibling', () => {
  assert.ok(
    NON_SIBLINGS.length > 0,
    'every @opena2a/* dependency of packages/cli now has a workspace directory, so this case ' +
      'no longer has an instance in the tree — repoint it at a dependency nothing here can build'
  );
  const r = resolved();
  const overrides = r.install.probeManifest.overrides ?? {};

  for (const dep of NON_SIBLINGS) {
    assert.ok(
      !packedWorkspaces(r).some((ws) => ws === `packages/${dep.dir}`),
      `${dep.name} was packed although packages/${dep.dir} does not exist\n${r.context()}`
    );
    assert.equal(overrides[dep.name], undefined, `${dep.name} was redirected\n${r.context()}`);
    assert.ok(
      !viewedSpecs(r).some((spec) => spec.startsWith(`${dep.name}@`)),
      `${dep.name} is not a workspace sibling, so the gate has nothing to decide about it\n${r.context()}`
    );
    assert.match(
      r.lock.packages[`node_modules/${dep.name}`].resolved,
      /^https:\/\/registry\.npmjs\.org\//,
      `${dep.name} did not resolve from the registry\n${r.context()}`
    );
  }
});

test('QGF-97.AC5 refuses to substitute a version the manifest does not pin', () => {
  assert.ok(
    DRIFTED.length > 0,
    'no @opena2a/* sibling pins a version its own workspace has moved past, so this case has ' +
      'no instance in the tree — pin one in the scenario below instead'
  );
  const drifted = DRIFTED[0];
  const r = runGate({
    scopedDeps: { ...SCOPED_DEPS, [drifted.name]: drifted.pinned },
    served: [
      ...NON_SIBLINGS.map((d) => `${d.name}@${d.pinned}`),
      ...ALIGNED.map((d) => `${d.name}@${d.pinned}`),
    ],
  });

  assert.notEqual(r.status, 0, `the audit passed on a version substitution\n${r.context()}`);
  assert.ok(r.combined.includes(drifted.name), `the audit never named ${drifted.name}\n${r.context()}`);
  assert.ok(
    r.combined.includes(drifted.pinned),
    `the audit never named the pinned version ${drifted.pinned}\n${r.context()}`
  );
  assert.ok(
    r.combined.includes(drifted.workspaceVersion),
    `the audit never named the version packages/${drifted.dir} would pack ` +
      `(${drifted.workspaceVersion})\n${r.context()}`
  );
  assert.deepEqual(packedWorkspaces(r), [], `something was packed anyway\n${r.context()}`);
  assert.equal(r.install, null, `the tree was measured anyway\n${r.context()}`);
});
