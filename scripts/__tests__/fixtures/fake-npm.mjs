#!/usr/bin/env node
/**
 * A test double for the `npm` CLI, driven by a JSON scenario.
 *
 * `scripts/audit-consumer-resolution.mjs` reaches the registry four ways —
 * `npm view` for whether a version is served, `npm pack` for a workspace
 * sibling, `npm install` for the consumer tree and `npm audit` for the advisory
 * report. None of those are available to a test: the registry is a live third
 * party, the advisory database changes underneath us, and the audit's whole
 * subject is a tree that by definition is not published yet.
 *
 * So the tests put this file on PATH as `npm` and hand it a scenario. It is a
 * MODEL of npm, and the parts it models are the parts the gate depends on:
 *
 *   view <name>@<version> version   Exit 0 printing the version when the
 *                                   scenario says the registry serves that
 *                                   spec; otherwise npm's E404 on stderr with
 *                                   exit 1, which is what an unpublished
 *                                   version really answers.
 *   pack --ignore-scripts -w <ws>   Writes one `.tgz` into --pack-destination,
 *                                   named the way npm names it, with the
 *                                   version read from the REAL workspace
 *                                   manifest at the cwd it was run in.
 *   install <spec>                  Resolves the packed manifest's scoped
 *                                   dependencies the way npm does: an entry in
 *                                   the consumer root's `overrides` resolves to
 *                                   that spec, anything else has to be served
 *                                   by the registry, and a dependency that is
 *                                   neither fails with npm's real ETARGET /
 *                                   notarget text. That failure is the defect
 *                                   this task removes, so the double has to be
 *                                   able to produce it.
 *   audit --omit=dev --json         Prints the scenario's report and exits
 *                                   non-zero when it carries anything, as npm
 *                                   does.
 *
 * Every invocation is appended to the scenario's `callLog` as one JSON line, so
 * a test can assert on which commands ran, where, and — for the install — on
 * the scratch consumer manifest that was on disk at the moment npm read it.
 * That manifest is deleted by the gate's own `finally`, so recording it here is
 * the only way to observe it.
 *
 * Anything not modelled exits 66 rather than guessing, so an unrecognised call
 * shows up as a loud test failure instead of a quiet pass.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const FIXTURE = process.env.QGF97_FAKE_NPM_FIXTURE;
if (!FIXTURE || !existsSync(FIXTURE)) {
  process.stderr.write(`fake npm: QGF97_FAKE_NPM_FIXTURE is not a readable file (${FIXTURE})\n`);
  process.exit(66);
}
const scenario = JSON.parse(readFileSync(FIXTURE, 'utf8'));
const argv = process.argv.slice(2);
const cwd = process.cwd();

function record(entry) {
  appendFileSync(scenario.callLog, JSON.stringify({ argv, cwd, ...entry }) + '\n');
}

function unmodelled(why) {
  process.stderr.write(`fake npm: ${why}: npm ${argv.join(' ')}\n`);
  process.exit(66);
}

/** Split a package spec into name and the range/version after the last `@`. */
function splitSpec(spec) {
  const at = spec.lastIndexOf('@');
  if (at <= 0) return { name: spec, range: 'latest' };
  return { name: spec.slice(0, at), range: spec.slice(at + 1) };
}

/** Where npm would say a published version came from. */
function registryTarball(name, version) {
  const base = name.startsWith('@') ? name.slice(name.indexOf('/') + 1) : name;
  return `https://registry.npmjs.org/${name}/-/${base}-${version}.tgz`;
}

const served = new Set(scenario.served ?? []);
const scopedDeps = scenario.scopedDeps ?? {};

function doView() {
  const spec = argv[1];
  const wantsJson = argv.includes('--json');
  const field = argv[2] && !argv[2].startsWith('--') ? argv[2] : null;
  const { name, range } = splitSpec(spec);

  // The served probe: `npm view <name>@<version> version`, no --json.
  if (field === 'version' && !wantsJson) {
    if (served.has(spec)) {
      process.stdout.write(`${range}\n`);
      process.exit(0);
    }
    process.stderr.write(
      'npm error code E404\n' +
        `npm error 404 No match found for version ${range}\n` +
        'npm error 404\n' +
        `npm error 404  '${spec}' is not in this registry.\n`
    );
    process.exit(1);
  }

  // `versionsSatisfying`: `npm view <name>@<range> version --json`.
  if (field === 'version' && wantsJson) {
    const list = (scenario.versions ?? {})[spec];
    if (!list) {
      process.stderr.write(`npm error code E404\nnpm error 404 No match found for version ${range}\n`);
      process.exit(1);
    }
    process.stdout.write(JSON.stringify(list));
    process.exit(0);
  }

  // `registryLatest`: `npm view <name>@latest --json`.
  if (!field && wantsJson) {
    const manifest = (scenario.latest ?? {})[name];
    if (!manifest) unmodelled(`no scenario manifest for ${name}@latest`);
    process.stdout.write(JSON.stringify(manifest));
    process.exit(0);
  }

  unmodelled('unmodelled view');
}

function doPack() {
  const ws = argv[argv.indexOf('-w') + 1];
  const destIdx = argv.indexOf('--pack-destination');
  if (!ws || destIdx === -1) unmodelled('pack without -w or --pack-destination');
  const dest = argv[destIdx + 1];
  const manifestPath = path.join(cwd, ws, 'package.json');
  if (!existsSync(manifestPath)) unmodelled(`pack of ${ws}, which has no package.json under ${cwd}`);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const filename = `${manifest.name.replace('@', '').replace('/', '-')}-${manifest.version}.tgz`;
  mkdirSync(dest, { recursive: true });
  writeFileSync(path.join(dest, filename), `fake pack of ${ws}@${manifest.version}\n`);
  process.stdout.write(`${filename}\n`);
  process.exit(0);
}

function doInstall() {
  const spec = argv[argv.length - 1];
  const probeManifestPath = path.join(cwd, 'package.json');
  const probeManifest = JSON.parse(readFileSync(probeManifestPath, 'utf8'));
  const overrides = probeManifest.overrides ?? {};
  // The gate deletes its scratch directory on the way out, so the manifest it
  // installed from — and whatever its overrides point at — are only observable
  // here, while the install is happening.
  record({
    event: 'install',
    probeManifest,
    overrideTargets: Object.fromEntries(
      Object.entries(overrides).map(([name, spec]) => {
        const file = spec.startsWith('file:') ? spec.slice('file:'.length) : spec;
        return [
          name,
          { spec, exists: existsSync(file), contents: existsSync(file) ? readFileSync(file, 'utf8') : null },
        ];
      })
    ),
  });

  const unresolvable = Object.entries(scopedDeps).filter(
    ([name, version]) => !overrides[name] && !served.has(`${name}@${version}`)
  );
  if (unresolvable.length > 0) {
    const [name, version] = unresolvable[0];
    process.stderr.write(
      'npm error code ETARGET\n' +
        `npm error notarget No matching version found for ${name}@${version}.\n` +
        "npm error notarget In most cases you or one of your dependencies are requesting\n" +
        'npm error notarget a package version that doesn\'t exist.\n'
    );
    process.exit(1);
  }

  const root = scenario.root;
  const lock = {
    name: probeManifest.name,
    version: probeManifest.version,
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': {
        name: probeManifest.name,
        version: probeManifest.version,
        dependencies: { [root.name]: `file:${spec}` },
      },
      [`node_modules/${root.name}`]: {
        version: root.version,
        resolved: `file:${spec}`,
        dependencies: { ...scopedDeps },
      },
    },
  };
  for (const [name, version] of Object.entries(scopedDeps)) {
    lock.packages[`node_modules/${name}`] = overrides[name]
      ? { version, resolved: overrides[name] }
      : { version, resolved: registryTarball(name, version) };
  }
  Object.assign(lock.packages, scenario.extraLockPackages ?? {});

  for (const [entry, meta] of Object.entries(lock.packages)) {
    if (entry === '') continue;
    const dir = path.join(cwd, entry);
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({
        name: entry.slice(entry.lastIndexOf('node_modules/') + 'node_modules/'.length),
        version: meta.version,
      }) + '\n'
    );
  }
  writeFileSync(path.join(cwd, 'package-lock.json'), JSON.stringify(lock, null, 2) + '\n');
  record({ event: 'installed', lock });
  // npm records the installed spec in the consumer manifest. The gate does not
  // read it back, but leaving it out would make the double diverge for no gain.
  probeManifest.dependencies = { ...(probeManifest.dependencies ?? {}), [root.name]: `file:${spec}` };
  writeFileSync(probeManifestPath, JSON.stringify(probeManifest) + '\n');
  process.stdout.write(`added ${Object.keys(lock.packages).length - 1} packages\n`);
  process.exit(0);
}

function doAudit() {
  const report = scenario.audit;
  if (!report) unmodelled('audit with no scenario report');
  process.stdout.write(JSON.stringify(report));
  process.exit((report.metadata?.vulnerabilities?.total ?? 0) > 0 ? 1 : 0);
}

record({});
switch (argv[0]) {
  case 'view':
    doView();
    break;
  case 'pack':
    doPack();
    break;
  case 'install':
    doInstall();
    break;
  case 'audit':
    doAudit();
    break;
  default:
    unmodelled('unmodelled subcommand');
}
