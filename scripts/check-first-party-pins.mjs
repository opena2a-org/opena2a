#!/usr/bin/env node
/**
 * Prove every first-party pin in the release roster is SATISFIABLE before the
 * release job reaches its first irreversible `npm publish`.
 *
 * ## The state this refuses
 *
 * `.github/workflows/release.yml` packs eleven workspaces and publishes them in
 * roster order. Six of those workspaces are pinned, at an EXACT version, by
 * another workspace in the same roster. Ordering the roster so a dependency is
 * published before its dependent is necessary, and it is not sufficient, and one
 * measured pair in this tree proves the gap with no reference to the registry at
 * all:
 *
 *     packages/check-core   pins  @opena2a/registry-client 0.1.0
 *     packages/registry-client  is  0.2.0  in this tree
 *
 * `registry-client` already sits ahead of `check-core` in the roster, so every
 * ordering check this repository could write is green on that pair. The run
 * publishes 0.2.0. Nothing the run produces is 0.1.0. Whether that pin resolves
 * is a fact about the REGISTRY, not about the roster, and no reordering can
 * change it. The same shape holds for `opena2a-cli` -> `@opena2a/contribute
 * 0.1.0` against an in-tree `packages/contribute` of 0.3.0.
 *
 * A publish is irreversible. `npm publish` cannot be taken back, so a pin that
 * turns out to be unresolvable has to be discovered BEFORE the loop starts, not
 * by a user whose `npm install` fails afterwards.
 *
 * ## The classification, and why it is the whole point
 *
 * Querying the registry for every first-party pin would be both slow and wrong:
 * most of these pins are satisfied by the very run that is about to publish
 * them, so asking npm about them asks the wrong question. So every pin whose
 * name is itself a roster entry lands in exactly one of three classes:
 *
 *   SAME-RUN            the pin string equals that workspace's in-tree version,
 *                       so this run publishes exactly what the pin asks for.
 *                       Roster ORDER is what makes this one safe; the registry
 *                       has nothing to say about it and is not asked.
 *
 *   RANGE               the pin string is not a single exact version ("*",
 *                       "^1.2.0", "workspace:*"). npm resolves it at install
 *                       time against whatever is published then. This script
 *                       takes no position on whether a range is the right thing
 *                       to write -- it classifies, and moves on.
 *
 *   REGISTRY-DEPENDENT  the pin is an exact version that is NOT this
 *                       workspace's in-tree version. The run publishes a
 *                       different version, so nothing the run produces can
 *                       satisfy the pin. This is the only class where the
 *                       registry is the authority, and the only class `--resolve`
 *                       queries.
 *
 * ## The coherence check, and the silent no-op it exists to catch
 *
 * The publish loop is idempotent: it runs `npm view "$pkg@$version" version` and
 * SKIPS anything already on npm, so a partial release can be completed by a
 * re-run. That idempotence has a failure mode. If `opena2a-cli@0.10.13` is
 * already on the registry -- carrying a DIFFERENT dependency set, because it was
 * published from a different tree -- then the next release skips `opena2a-cli`
 * entirely while publishing `@opena2a/cli-ui@0.6.0`, the cli change in this tree
 * never ships, and the run is green.
 *
 * `--coherence` reads the two lists the loop already writes and refuses that
 * run: a roster entry SKIPPED as already-published, while a package it pins at a
 * SAME-RUN version was PUBLISHED in the same run, means the registry now holds
 * one half of this tree and one half of some other one. The direction that must
 * stay green -- every entry skipped and nothing published -- is exactly the
 * completed partial release the idempotence exists to serve, and it is not a
 * violation because nothing new was published against the stale dependent.
 *
 * ## Both inputs are derived, never copied
 *
 * The roster is read out of the `const wss = [` array inside release.yml's
 * `Pack every workspace the publish job will sign` step, and each pin is read
 * out of that workspace's own package.json. A second hand-maintained copy of
 * either list would be a check that drifts silently the first time somebody adds
 * a workspace -- and drifts in the direction of passing, which is the only
 * direction that matters.
 *
 * ## Usage
 *
 *   node scripts/check-first-party-pins.mjs
 *       Classify and print. Always exits 0; this is the reporting mode.
 *
 *   node scripts/check-first-party-pins.mjs --resolve [--registry <url>]
 *       Classify, then resolve every REGISTRY-DEPENDENT pin against the
 *       registry with `npm view "<pkg>@<version>" version`. Exits non-zero if
 *       any one of them does not resolve, and exits non-zero if the answer could
 *       not be measured at all. Not measured is not a pass.
 *
 *   node scripts/check-first-party-pins.mjs --coherence \
 *       --skipped /tmp/skipped.txt --published /tmp/published.txt
 *       Classify, then refuse an incoherent run. Both files are the TSV
 *       (`pkg<TAB>version`) the publish loop writes.
 *
 *   --resolver-module <path>
 *       Replace the npm-backed resolver with one exported by <path>, so the
 *       refusal path is reachable with no network. FOR TESTS ONLY: the release
 *       workflow never passes it, and a resolver that is not the registry
 *       answers a different question than the gate is asking.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** The workflow both inputs are derived from. */
export const RELEASE_WORKFLOW = '.github/workflows/release.yml';

/** The step inside it whose `const wss = [` array IS the publish roster. */
export const PACK_STEP = 'Pack every workspace the publish job will sign';

/** Same registry the publish loop publishes to. Asking a different one is a lie. */
export const DEFAULT_REGISTRY = 'https://registry.npmjs.org/';

/**
 * The manifest blocks that decide what a consumer resolves.
 *
 * `devDependencies` is deliberately absent: it is not installed by a consumer
 * and is not published in a way that can fail anybody's install.
 */
export const PIN_BLOCKS = ['dependencies', 'optionalDependencies', 'peerDependencies'];

export const SAME_RUN = 'SAME-RUN';
export const RANGE = 'RANGE';
export const REGISTRY_DEPENDENT = 'REGISTRY-DEPENDENT';

/**
 * A single exact semver version -- the official SemVer 2.0.0 grammar, anchored.
 *
 * Anything else is a RANGE by definition: "*", "^1.2.3", "1.x", ">=1.0.0",
 * "workspace:*", "npm:other@1.0.0". The distinction is load-bearing rather than
 * cosmetic, because only an exact pin can be unsatisfiable in a way this run
 * could have prevented.
 */
const EXACT_VERSION =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/**
 * The publish roster, read out of release.yml rather than restated here.
 *
 * Located by STEP NAME first and by the array second, so a `const wss` appearing
 * anywhere else in the file can never be mistaken for the roster.
 */
export function readRoster(repoRoot = REPO_ROOT) {
  const file = path.join(repoRoot, RELEASE_WORKFLOW);
  if (!existsSync(file)) {
    throw new Error(
      `${RELEASE_WORKFLOW} is not on disk at ${repoRoot}, so the publish roster cannot be ` +
        'read. The roster is this check\'s first input; without it nothing was measured.'
    );
  }
  const text = readFileSync(file, 'utf8');
  const stepAt = text.indexOf(`- name: ${PACK_STEP}`);
  if (stepAt === -1) {
    throw new Error(
      `${RELEASE_WORKFLOW} has no step named "${PACK_STEP}", so the publish roster cannot be ` +
        'located. If that step was renamed, rename it here too rather than letting this check ' +
        'go quiet.'
    );
  }
  const openAt = text.indexOf('const wss = [', stepAt);
  const closeAt = openAt === -1 ? -1 : text.indexOf('];', openAt);
  if (openAt === -1 || closeAt === -1) {
    throw new Error(
      `the "${PACK_STEP}" step carries no \`const wss = [ ... ];\` array, so the publish ` +
        'roster cannot be read out of it.'
    );
  }
  const body = text.slice(openAt + 'const wss = ['.length, closeAt);
  const roster = [];
  for (const m of body.matchAll(/\[\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\]/g)) {
    roster.push({ workspace: m[1], pkg: m[2] });
  }
  if (roster.length === 0) {
    throw new Error(
      `the \`const wss\` array in the "${PACK_STEP}" step yielded no [workspace, package] ` +
        'pairs. An empty roster would make every check below vacuously green.'
    );
  }
  return roster;
}

/**
 * Each roster workspace's own manifest: the version this run would publish, and
 * the pin blocks.
 *
 * The name is asserted against the roster's own second element, the same
 * assertion the pack step makes. A workspace that is not the package the roster
 * claims makes every version comparison below meaningless.
 */
export function readRosterWorkspaces(repoRoot = REPO_ROOT, roster = readRoster(repoRoot)) {
  return roster.map(entry => {
    const manifestPath = path.join(repoRoot, entry.workspace, 'package.json');
    if (!existsSync(manifestPath)) {
      throw new Error(
        `${entry.workspace}/package.json is not on disk, so the pins of roster entry ` +
          `${entry.pkg} cannot be read. Not a pass.`
      );
    }
    let manifest;
    try {
      manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    } catch (e) {
      throw new Error(`${entry.workspace}/package.json is not parseable JSON: ${e.message}`);
    }
    if (manifest.name !== entry.pkg) {
      throw new Error(
        `${entry.workspace} is ${manifest.name}, but the roster calls it ${entry.pkg}. The ` +
          'roster and the tree disagree about what this run publishes.'
      );
    }
    if (typeof manifest.version !== 'string' || manifest.version.length === 0) {
      throw new Error(`${entry.workspace}/package.json declares no version.`);
    }
    return { ...entry, version: manifest.version, manifest };
  });
}

/** SAME-RUN / RANGE / REGISTRY-DEPENDENT for one pin. See the header. */
export function classifyPin(spec, inTreeVersion) {
  if (!EXACT_VERSION.test(spec)) return RANGE;
  return spec === inTreeVersion ? SAME_RUN : REGISTRY_DEPENDENT;
}

/**
 * Every pin one roster workspace places on another, classified.
 *
 * Pins on packages OUTSIDE the roster are not first-party for this purpose even
 * when they share the `@opena2a/` scope: this run does not publish them, so
 * whether they resolve is not a question the release can answer. `@opena2a/
 * aicomply` is such a pin in this tree.
 */
export function collectFirstPartyPins(workspaces) {
  const byName = new Map(workspaces.map(w => [w.pkg, w]));
  const pins = [];
  for (const from of workspaces) {
    for (const block of PIN_BLOCKS) {
      const deps = from.manifest[block];
      if (!deps || typeof deps !== 'object') continue;
      for (const name of Object.keys(deps).sort()) {
        const target = byName.get(name);
        if (!target) continue;
        const spec = deps[name];
        pins.push({
          from: from.pkg,
          fromWorkspace: from.workspace,
          block,
          to: target.pkg,
          toWorkspace: target.workspace,
          spec,
          inTreeVersion: target.version,
          class: classifyPin(spec, target.version),
        });
      }
    }
  }
  return pins;
}

/** One line naming the depender, the depended, the pin string and the class. */
export function formatPin(pin) {
  return (
    `${pin.class.padEnd(REGISTRY_DEPENDENT.length)}  ${pin.from} -> ${pin.to} "${pin.spec}"  ` +
    `(${pin.block}; ${pin.toWorkspace} is ${pin.inTreeVersion} in this tree)`
  );
}

/**
 * Ask the resolver about every REGISTRY-DEPENDENT pin, and only those.
 *
 * SAME-RUN pins are answered by this run and RANGE pins are answered by npm at
 * install time; querying either would be asking the registry a question it is
 * not the authority on. Identical specs are asked once, but every PIN that rests
 * on a missing spec is reported, because each one is a separate broken install.
 */
export async function resolveRegistryDependentPins(pins, resolve, log = () => {}) {
  const queried = [];
  const answers = new Map();
  const unresolvable = [];
  for (const pin of pins) {
    if (pin.class !== REGISTRY_DEPENDENT) continue;
    const spec = `${pin.to}@${pin.spec}`;
    if (!answers.has(spec)) {
      const present = await resolve(pin.to, pin.spec);
      answers.set(spec, present);
      queried.push(spec);
      log(`  ${spec}  ->  ${present ? 'present' : 'ABSENT'}`);
    }
    if (!answers.get(spec)) unresolvable.push(pin);
  }
  return { queried, unresolvable };
}

/**
 * Roster entries this run SKIPPED that pin a package this run PUBLISHED.
 *
 * Matched on the skipped package's NAME: the skip list can only ever hold the
 * version this run packed, and the defect is that the registry's copy of that
 * name is a different build from this tree's, whatever version string it wears.
 */
export function findIncoherentPairs({ pins, skipped, published }) {
  const skippedVersionOf = new Map(skipped.map(e => [e.pkg, e.version]));
  const publishedSpecs = new Set(published.map(e => `${e.pkg}@${e.version}`));
  const out = [];
  for (const pin of pins) {
    if (pin.class !== SAME_RUN) continue;
    if (!skippedVersionOf.has(pin.from)) continue;
    if (!publishedSpecs.has(`${pin.to}@${pin.spec}`)) continue;
    out.push({
      skipped: pin.from,
      skippedVersion: skippedVersionOf.get(pin.from),
      published: pin.to,
      version: pin.spec,
    });
  }
  return out;
}

/** `pkg<TAB>version` per line, as the publish loop writes it. Empty is valid. */
export function readPublishList(file, label) {
  if (!existsSync(file)) {
    throw new Error(
      `the ${label} list ${file} does not exist, so what this run did cannot be read. The ` +
        'publish loop writes both lists before this check runs; an absent one means the run ' +
        'did not reach the loop. Not a pass.'
    );
  }
  const out = [];
  for (const raw of readFileSync(file, 'utf8').split('\n')) {
    const line = raw.trim();
    if (line.length === 0) continue;
    const [pkg, version, ...rest] = line.split('\t');
    if (!pkg || !version || rest.length > 0) {
      throw new Error(
        `the ${label} list ${file} has a line this check cannot read: ${JSON.stringify(raw)}. ` +
          'Expected `package<TAB>version`.'
      );
    }
    out.push({ pkg, version });
  }
  return out;
}

/**
 * The real resolver: npm's own view of the registry the loop publishes to.
 *
 * Returns false ONLY for a definite "that version is not there". Anything else
 * -- a network failure, a proxy, an auth error, a rate limit -- throws, because
 * a gate that could not take its measurement has not passed, and "unknown"
 * silently reading as "resolvable" is the one direction this check must never
 * fail in.
 */
export function npmResolver(registry = DEFAULT_REGISTRY, log = () => {}) {
  return (pkg, version) => {
    const spec = `${pkg}@${version}`;
    log(`  npm view "${spec}" version --registry=${registry}`);
    let out;
    try {
      out = execFileSync('npm', ['view', spec, 'version', `--registry=${registry}`], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (e) {
      const said = `${e.stdout ?? ''}${e.stderr ?? ''}`;
      if (/E404|No match found for version|is not in this registry/.test(said)) return false;
      throw new Error(
        `could not resolve "${spec}" against ${registry}, so it is UNKNOWN whether this pin is ` +
          `satisfiable: ${said.trim().slice(0, 300) || e.message}`
      );
    }
    if (out.trim().length === 0) {
      throw new Error(
        `npm view "${spec}" version exited 0 but printed nothing, so the registry's answer for ` +
          'this pin was not measured. Not a pass.'
      );
    }
    return true;
  };
}

/** Load an injected resolver. See `--resolver-module` in the header. */
async function loadResolverModule(spec) {
  const abs = path.resolve(spec);
  if (!existsSync(abs)) throw new Error(`--resolver-module ${spec} does not exist.`);
  const mod = await import(pathToFileURL(abs).href);
  const resolve = mod.default ?? mod.resolve;
  if (typeof resolve !== 'function') {
    throw new Error(`--resolver-module ${spec} exports no default (or \`resolve\`) function.`);
  }
  return resolve;
}

function parseArgs(argv) {
  const opts = {
    resolve: false,
    coherence: false,
    registry: DEFAULT_REGISTRY,
    resolverModule: null,
    skipped: null,
    published: null,
  };
  const valueOf = (flag, i) => {
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) throw new Error(`${flag} needs a value.`);
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--resolve':
        opts.resolve = true;
        break;
      case '--coherence':
        opts.coherence = true;
        break;
      case '--registry':
        opts.registry = valueOf('--registry', i++);
        break;
      case '--resolver-module':
        opts.resolverModule = valueOf('--resolver-module', i++);
        break;
      case '--skipped':
        opts.skipped = valueOf('--skipped', i++);
        break;
      case '--published':
        opts.published = valueOf('--published', i++);
        break;
      default:
        throw new Error(`unknown argument ${JSON.stringify(argv[i])}.`);
    }
  }
  if (opts.coherence && (!opts.skipped || !opts.published)) {
    throw new Error('--coherence needs both --skipped <file> and --published <file>.');
  }
  // Refused rather than silently ordered, because the two modes run on opposite
  // sides of the publish loop: one asks the registry BEFORE anything is
  // published, the other reads what the loop DID. A single invocation claiming
  // both would answer one of them against the wrong moment.
  if (opts.coherence && opts.resolve) {
    throw new Error('--resolve and --coherence are separate steps; pass one or the other.');
  }
  return opts;
}

export async function run(argv, { repoRoot = REPO_ROOT, out = console.log, err = console.error } = {}) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    err(`check-first-party-pins: ${e.message}`);
    return 2;
  }

  let pins;
  let workspaces;
  try {
    workspaces = readRosterWorkspaces(repoRoot);
    pins = collectFirstPartyPins(workspaces);
  } catch (e) {
    err(`::error::check-first-party-pins could not read the roster or its pins: ${e.message}`);
    return 1;
  }

  const counts = { [SAME_RUN]: 0, [RANGE]: 0, [REGISTRY_DEPENDENT]: 0 };
  out(`=== First-party pins in the ${RELEASE_WORKFLOW} publish roster ===`);
  for (const pin of pins) {
    counts[pin.class] += 1;
    out(formatPin(pin));
  }
  out(
    `${pins.length} first-party pin(s) across ${workspaces.length} roster workspace(s): ` +
      `${counts[SAME_RUN]} ${SAME_RUN}, ${counts[RANGE]} ${RANGE}, ` +
      `${counts[REGISTRY_DEPENDENT]} ${REGISTRY_DEPENDENT}`
  );

  if (opts.coherence) {
    return coherenceMode(opts, pins, out, err);
  }
  if (opts.resolve) {
    return resolveMode(opts, pins, out, err);
  }
  return 0;
}

async function resolveMode(opts, pins, out, err) {
  const pending = pins.filter(p => p.class === REGISTRY_DEPENDENT);
  out('');
  out(
    `=== Resolving ${pending.length} ${REGISTRY_DEPENDENT} pin(s) against ${opts.registry} ===`
  );
  if (pending.length === 0) {
    out('Nothing to resolve: every first-party pin is satisfied by this run or is a range.');
    return 0;
  }

  let resolver;
  try {
    resolver = opts.resolverModule
      ? await loadResolverModule(opts.resolverModule)
      : npmResolver(opts.registry, out);
  } catch (e) {
    err(`::error::check-first-party-pins could not build a resolver: ${e.message}`);
    return 1;
  }

  let result;
  try {
    result = await resolveRegistryDependentPins(pins, resolver, out);
  } catch (e) {
    err(
      `::error::check-first-party-pins did not measure the registry, so no pin was proved ` +
        `satisfiable: ${e.message}`
    );
    return 1;
  }

  if (result.unresolvable.length === 0) {
    out('');
    out(
      `All ${result.queried.length} ${REGISTRY_DEPENDENT} pin(s) already resolve on ` +
        `${opts.registry}. Safe to publish.`
    );
    return 0;
  }

  err('');
  for (const pin of result.unresolvable) {
    err(
      `::error::${pin.from} pins ${pin.to} ${pin.spec}, which is not on ${opts.registry} and is ` +
        `not produced by this run -- ${pin.toWorkspace} is ${pin.inTreeVersion} in this tree, so ` +
        `this run publishes ${pin.to} ${pin.inTreeVersion}. Installing ${pin.from} would fail.`
    );
  }
  err(
    `\nRefusing to publish: ${result.unresolvable.length} first-party pin(s) cannot be ` +
      'satisfied by this run or by the registry. A publish cannot be taken back, so this is ' +
      'refused before the loop rather than discovered by a user afterwards. Either raise the ' +
      'pin to the version this run publishes, or publish the missing version first.'
  );
  return 1;
}

function coherenceMode(opts, pins, out, err) {
  let skipped;
  let published;
  try {
    skipped = readPublishList(opts.skipped, 'skipped');
    published = readPublishList(opts.published, 'published');
  } catch (e) {
    err(`::error::check-first-party-pins could not read this run's outcome: ${e.message}`);
    return 1;
  }

  out('');
  out('=== Publish-list / skip-list coherence ===');
  out(`skipped:   ${skipped.map(e => `${e.pkg}@${e.version}`).join(', ') || '(none)'}`);
  out(`published: ${published.map(e => `${e.pkg}@${e.version}`).join(', ') || '(none)'}`);

  const bad = findIncoherentPairs({ pins, skipped, published });
  if (bad.length === 0) {
    out('Coherent: no skipped roster entry pins a package this run published.');
    return 0;
  }

  err('');
  for (const pair of bad) {
    err(
      `::error::${pair.skipped} was SKIPPED (${pair.skippedVersion} is already on npm) while ` +
        `${pair.published} ${pair.version} was PUBLISHED by this run. This tree's ` +
        `${pair.skipped} pins ${pair.published} ${pair.version}, so the ${pair.skipped} users ` +
        `resolve was built from a different tree than the ${pair.published} they now get.`
    );
  }
  err(
    `\nRefusing the release: ${bad.length} skip/publish pair(s) leave the registry holding half ` +
      'of this tree and half of another. The skip is idempotence working as intended only when ' +
      'nothing it depends on moved underneath it. Bump the skipped package and re-run.'
  );
  return 1;
}

/* c8 ignore start -- entry point; the exported `run` is what the tests drive. */
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  run(process.argv.slice(2)).then(
    code => {
      process.exitCode = code;
    },
    e => {
      console.error(`::error::check-first-party-pins crashed: ${e?.stack ?? e}`);
      process.exitCode = 1;
    }
  );
}
/* c8 ignore stop */
