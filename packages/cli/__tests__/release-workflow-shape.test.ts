/**
 * The release workflow must pack and publish every workspace a package depends
 * on BEFORE it publishes that package (QGF-114.AC1-AC5).
 *
 * `release.yml` packs all eleven workspaces in one job and then publishes them
 * in roster order, in a loop whose every iteration is irreversible: `npm
 * publish` cannot be taken back. The tag trigger is not filtered per package —
 * a `cli-v*` tag runs the same job that publishes all eleven — so with
 * `packages/cli` at roster index 0 the CLI reached npm before the workspaces it
 * pins exactly (`@opena2a/cli-ui`, `@opena2a/shared`, ...). Any failure between
 * the two leaves the published CLI unable to install: its pins resolve to
 * versions the registry does not serve yet. Publishing dependencies first
 * closes that window — the CLI is the last irreversible act of the run, and
 * anything that fails before it fails while it is still unpublished.
 *
 * The order is therefore load-bearing, and nothing in the workflow states why.
 * This file is that statement: it derives the roster from `release.yml` and the
 * dependency edges from the workspace manifests, so a reorder that reopens the
 * window fails here and names the pair it broke.
 *
 * Read as TEXT rather than parsed as YAML on purpose. The roster is a
 * JavaScript literal inside a shell script inside a YAML block scalar, so
 * reaching it is a textual step whatever parses the outer document — and
 * QGF-114.AC4 feeds this same derivation a copy of the file with one entry
 * moved, which has to be the file's own bytes rather than a re-serialisation
 * that could normalise the difference away.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

/** `packages/cli/__tests__` -> `packages/cli` -> `packages` -> the repository. */
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const RELEASE_WORKFLOW = path.join(REPO_ROOT, '.github', 'workflows', 'release.yml');

/** The step that holds both the roster and the `npm pack` invocation. */
const PACK_STEP = 'Pack every workspace the publish job will sign';

/** The entry QGF-114 moves, matched as it is written in the workflow. */
const CLI_ENTRY = '["packages/cli","opena2a-cli"]';

/** npm's install-time fields. `devDependencies` never ship, so they cannot strand a publish. */
const DEPENDENCY_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'] as const;

interface RosterEntry {
  /** Workspace directory, relative to the repository root. */
  workspace: string;
  /** The package name the workflow asserts that workspace's manifest carries. */
  pkg: string;
}

interface DependencyEdge {
  name: string;
  spec: string;
  field: (typeof DEPENDENCY_FIELDS)[number];
}

/**
 * The dedented body of the named step's `run: |` block.
 *
 * Anchored on the step's own `- name:` line and bounded by indentation, so a
 * commented-out or relocated copy of the script is not what gets read.
 */
function stepScript(workflowYaml: string, stepName: string): string {
  const lines = workflowYaml.split('\n');
  const start = lines.findIndex(
    (line) => /^\s*-\s+name:\s+(.*?)\s*$/.exec(line)?.[1] === stepName,
  );
  if (start < 0) {
    throw new Error(`${RELEASE_WORKFLOW} has no step named "${stepName}"`);
  }
  const stepIndent = lines[start].indexOf('-');

  let runAt = -1;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (lines[i].trim() === '') continue;
    if (lines[i].length - lines[i].trimStart().length <= stepIndent) break;
    if (/^\s*run:\s*\|\s*$/.test(lines[i])) {
      runAt = i;
      break;
    }
  }
  if (runAt < 0) {
    throw new Error(`step "${stepName}" in ${RELEASE_WORKFLOW} has no \`run: |\` block`);
  }

  const runIndent = lines[runAt].length - lines[runAt].trimStart().length;
  const body: string[] = [];
  let blockIndent = -1;
  for (let i = runAt + 1; i < lines.length; i += 1) {
    if (lines[i].trim() === '') {
      body.push('');
      continue;
    }
    const indent = lines[i].length - lines[i].trimStart().length;
    if (indent <= runIndent) break;
    if (blockIndent < 0) blockIndent = indent;
    body.push(lines[i].slice(blockIndent));
  }
  return body.join('\n');
}

/** The `const wss = [...]` roster, in the order the publish loop consumes it. */
function roster(packScript: string): RosterEntry[] {
  const block = /const wss = \[([\s\S]*?)\];/.exec(packScript);
  if (!block) {
    throw new Error(`the "${PACK_STEP}" step no longer declares a \`const wss = [\` roster`);
  }
  const entries = [...block[1].matchAll(/\["([^"]+)","([^"]+)"\]/g)].map((m) => ({
    workspace: m[1],
    pkg: m[2],
  }));
  if (entries.length === 0) {
    throw new Error(`the \`const wss = [\` roster in ${RELEASE_WORKFLOW} is empty`);
  }
  return entries;
}

/** The `--workspace=` values of the `npm pack` invocation, in the order they are written. */
function packWorkspaces(packScript: string): string[] {
  const lines = packScript.split('\n');
  const start = lines.findIndex((line) => line.includes('npm pack '));
  if (start < 0) {
    throw new Error(`the "${PACK_STEP}" step no longer runs \`npm pack\``);
  }
  const invocation: string[] = [];
  for (let i = start; i < lines.length; i += 1) {
    invocation.push(lines[i]);
    if (!lines[i].trimEnd().endsWith('\\')) break;
  }
  return [...invocation.join('\n').matchAll(/--workspace=([^\s\\]+)/g)].map((m) => m[1]);
}

function manifest(workspace: string): Record<string, unknown> {
  return JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, workspace, 'package.json'), 'utf-8'),
  ) as Record<string, unknown>;
}

/**
 * The `@opena2a/*` packages a workspace installs, from its own manifest.
 *
 * `opena2a-cli` is admitted alongside the scope because it is a roster entry
 * too: the property is about publish order among the eleven, and its unscoped
 * name must not exempt it if something ever depends on it.
 */
function opena2aDependencies(workspace: string): DependencyEdge[] {
  const pj = manifest(workspace);
  const edges: DependencyEdge[] = [];
  for (const field of DEPENDENCY_FIELDS) {
    const deps = (pj[field] ?? {}) as Record<string, string>;
    for (const name of Object.keys(deps).sort()) {
      if (name.startsWith('@opena2a/') || name === 'opena2a-cli') {
        edges.push({ name, spec: deps[name], field });
      }
    }
  }
  return edges;
}

/**
 * Every roster entry published at or before an `@opena2a/*` workspace it
 * depends on. Dependencies outside the roster (`@opena2a/aicomply` is not a
 * workspace of this monorepo) cannot be ordered by it and are not edges.
 */
function orderViolations(entries: RosterEntry[]): string[] {
  const rosterIndex = new Map(entries.map((entry, index) => [entry.pkg, index]));
  const violations: string[] = [];
  entries.forEach((entry, index) => {
    for (const dep of opena2aDependencies(entry.workspace)) {
      const depIndex = rosterIndex.get(dep.name);
      if (depIndex === undefined || depIndex < index) continue;
      violations.push(
        `${entry.pkg} (roster index ${index}) is published before ${dep.name} ${dep.spec} ` +
          `(roster index ${depIndex}), which it declares in ${dep.field}`,
      );
    }
  });
  return violations;
}

/**
 * The dependency-before-dependent assertion (QGF-114.AC2). Shared, because
 * QGF-114.AC4 exists to watch THIS assertion fail on the base ordering.
 */
function assertDependencyBeforeDependent(entries: RosterEntry[]): void {
  const violations = orderViolations(entries);
  expect(
    violations,
    `.github/workflows/release.yml publishes a package before an @opena2a workspace it ` +
      `depends on, so a failure between the two strands the published package:\n  ` +
      `${violations.join('\n  ')}`,
  ).toEqual([]);
}

/**
 * A copy of the workflow whose only difference is that the `packages/cli` entry
 * sits at the front of the roster again — the ordering this task removed.
 */
function withCliPackedFirst(workflowYaml: string): string {
  const lines = workflowYaml.split('\n');
  const open = lines.findIndex((line) => line.includes('const wss = ['));
  const close = lines.findIndex((line, i) => i > open && line.trim() === '];');
  if (open < 0 || close < 0) {
    throw new Error(`no \`const wss = [ ... ];\` roster to reorder in ${RELEASE_WORKFLOW}`);
  }
  const at = lines.findIndex((line, i) => i > open && i < close && line.includes(CLI_ENTRY));
  if (at < 0) {
    throw new Error(`${CLI_ENTRY} is not a roster entry of ${RELEASE_WORKFLOW}`);
  }
  if ((lines[at].match(/\["/g) ?? []).length !== 1) {
    throw new Error(
      `${CLI_ENTRY} shares a line with another entry; moving it alone would change more ` +
        `than one entry's position`,
    );
  }
  const [cliLine] = lines.splice(at, 1);
  lines.splice(open + 1, 0, cliLine);
  return lines.join('\n');
}

/** Every publishable workspace on disk — what the roster has to cover, derived. */
function publishableWorkspaces(): string[] {
  return fs
    .readdirSync(path.join(REPO_ROOT, 'packages'), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => `packages/${entry.name}`)
    .filter((workspace) => fs.existsSync(path.join(REPO_ROOT, workspace, 'package.json')))
    .filter((workspace) => manifest(workspace).private !== true);
}

const workflowSource = fs.readFileSync(RELEASE_WORKFLOW, 'utf-8');
const packScript = stepScript(workflowSource, PACK_STEP);
const entries = roster(packScript);

describe('release.yml pack-and-publish order', () => {
  it('QGF-114.AC1 packs packages/cli last, and npm pack lists the roster in the same order', () => {
    expect(entries[entries.length - 1]).toEqual({ workspace: 'packages/cli', pkg: 'opena2a-cli' });
    // Everything ahead of it is a scoped workspace — the CLI is the only
    // unscoped package, so this pins "after all ten @opena2a/* entries"
    // without restating the ten.
    const unscopedAhead = entries
      .slice(0, -1)
      .map((entry) => entry.pkg)
      .filter((pkg) => !pkg.startsWith('@opena2a/'));
    expect(unscopedAhead).toEqual([]);
    // The tarballs the loop publishes come from this invocation; a roster the
    // pack list disagrees with would publish in an order nothing produced.
    expect(packWorkspaces(packScript)).toEqual(entries.map((entry) => entry.workspace));
  });

  it('QGF-114.AC2 publishes every @opena2a workspace before the packages that depend on it', () => {
    assertDependencyBeforeDependent(entries);
  });

  it('QGF-114.AC3 derives every roster package from the workspace manifests, not a fixed list', () => {
    // Reading each manifest is what makes the ordering property a measurement
    // of the tree rather than a restatement of it. The workflow throws at pack
    // time on a name mismatch, which would abort a release mid-tag; the same
    // check here fails in CI instead.
    for (const entry of entries) {
      expect(
        manifest(entry.workspace).name,
        `${entry.workspace}/package.json is not ${entry.pkg}`,
      ).toBe(entry.pkg);
    }
  });

  it('QGF-114.AC4 fails the ordering assertion on a copy that packs packages/cli first', () => {
    const baseOrder = roster(stepScript(withCliPackedFirst(workflowSource), PACK_STEP));
    // The mutation moved one entry and nothing else.
    expect(baseOrder[0]).toEqual({ workspace: 'packages/cli', pkg: 'opena2a-cli' });
    expect(baseOrder.map((entry) => entry.pkg).sort()).toEqual(
      entries.map((entry) => entry.pkg).sort(),
    );

    let failure: Error | undefined;
    try {
      assertDependencyBeforeDependent(baseOrder);
    } catch (error) {
      failure = error as Error;
    }
    expect(
      failure,
      'the ordering assertion passed on the ordering it exists to refuse',
    ).toBeDefined();
    // It has to say WHICH pair, or a failing release job tells the next
    // person only that something is out of order.
    expect(failure?.message).toContain('opena2a-cli');
    expect(failure?.message).toContain('@opena2a/shared');
  });

  it('QGF-114.AC5 rosters every publishable workspace exactly once, and no others', () => {
    const workspaces = entries.map((entry) => entry.workspace);
    expect([...workspaces].sort()).toEqual(publishableWorkspaces().sort());
    expect(new Set(workspaces).size).toBe(workspaces.length);
  });
});
