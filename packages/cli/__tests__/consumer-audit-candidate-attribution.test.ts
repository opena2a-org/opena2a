/**
 * Pins what the CANDIDATE consumer-resolution audit SAYS when it fails, and the
 * one base comparison that lets it name this branch as the cause (QGF-112).
 *
 * The gate itself cannot be exercised from a test: making it fail requires an
 * `npm install` resolved against the live registry and an `npm audit` against
 * the live advisory database. What can be measured offline is the thing this
 * contract is actually about — the text the run composes out of what it
 * measured — so these cases import ../../../scripts/audit-consumer-resolution.mjs
 * and call the composer directly.
 *
 * That import is possible at all only because the module stopped auditing on
 * load; QGF-112.AC3 pins that, and pins it in child processes rather than here,
 * because "importing performs an install" is not a claim a test can make about
 * a module it has already imported.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import yaml from 'js-yaml';

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const AUDIT_SCRIPT = path.join(REPO_ROOT, 'scripts', 'audit-consumer-resolution.mjs');
const SECURITY_WORKFLOW = path.join(REPO_ROOT, '.github', 'workflows', 'security.yml');

const auditSource = fs.readFileSync(AUDIT_SCRIPT, 'utf-8');

/**
 * The two substrings that attribute a failure to the diff under review. They
 * are the whole subject of AC1 and AC2: printing them is a claim about a
 * comparison, and a run that took no comparison may not make it.
 */
const ATTRIBUTION = ['about the change under review', 'fixable in this branch'];

/** What every CANDIDATE closing text has to say about its own measurement. */
const MEASURED = 'It measured the tarball this branch would publish';

function occurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

/** The audit module's exports. Untyped: it is a plain .mjs script. */
let cached: any;

/**
 * Load the audit module, once, inside the case that needs it.
 *
 * Deliberately not a `beforeAll`: the cases below that read the workflow and
 * the manifests are checking invariants that hold whether or not the module
 * imports cleanly, and a hook would take them down with it — which is exactly
 * what a module that audits on load does.
 */
async function auditModule(): Promise<any> {
  // @vite-ignore: a plain node ESM file outside this package's root, loaded
  // as-is rather than transformed.
  cached ??= await import(/* @vite-ignore */ pathToFileURL(AUDIT_SCRIPT).href);
  return cached;
}

/**
 * Import the audit module in a child process and report what the import did.
 *
 * `PATH` is pointed at an empty directory, so any `npm install`/`npm audit` the
 * import attempts fails to spawn at all rather than reaching a registry; `HOME`
 * and `TMPDIR` are pointed at fresh directories, so anything written during the
 * import lands somewhere this test can see.
 */
function importInChild(overrides: Record<string, string> = {}) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'qgf112-import-probe-'));
  try {
    const emptyPath = path.join(sandbox, 'no-tools');
    const home = path.join(sandbox, 'home');
    const temp = path.join(sandbox, 'temp');
    for (const dir of [emptyPath, home, temp]) fs.mkdirSync(dir);

    const probe = [
      `await import(${JSON.stringify(pathToFileURL(AUDIT_SCRIPT).href)});`,
      `process.stdout.write('IMPORTED');`,
    ].join('\n');

    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', probe], {
      encoding: 'utf-8',
      timeout: 60_000,
      env: { PATH: emptyPath, HOME: home, TMPDIR: temp, ...overrides },
    });
    // Read while the sandbox still exists. On its own this only catches a
    // scratch directory that is LEFT behind — the run removes its own in a
    // `finally` — which is why the next case points TMPDIR at a path that
    // does not exist and lets `mkdtempSync` itself be the measurement.
    return { ...result, tempEntries: fs.readdirSync(temp) };
  } finally {
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
}

describe('CANDIDATE consumer-resolution audit: what it reports and what it attributes', () => {
  it('QGF-112.AC1 reports the tarball it measured and that the base artifact was not measured', async () => {
    const audit = await auditModule();
    const text: string = audit.candidateClosingGuidance(audit.BASE_COMPARISON.NOT_MEASURED);

    expect(text).toContain(MEASURED);
    expect(text).toMatch(/did not measure the base artifact/i);
    for (const claim of ATTRIBUTION) expect(text).not.toContain(claim);
  });

  it('QGF-112.AC1 reports the tarball it measured and that the base artifact carries the same failure', async () => {
    const audit = await auditModule();
    const text: string = audit.candidateClosingGuidance(audit.BASE_COMPARISON.SAME_FAILURE_ON_BASE);

    expect(text).toContain(MEASURED);
    expect(text).toMatch(/base artifact/i);
    expect(text).toMatch(/the same failure is present/i);
    for (const claim of ATTRIBUTION) expect(text).not.toContain(claim);
  });

  it('QGF-112.AC2 attributes the failure to this branch for the measured-absent outcome and no other', async () => {
    const audit = await auditModule();
    const outcomes: string[] = Object.values(audit.BASE_COMPARISON);
    // Three outcomes, so that "no other" is a statement about a closed set
    // rather than about whichever one happened to be looked up.
    expect(outcomes).toHaveLength(3);
    expect(outcomes).toContain(audit.BASE_COMPARISON.ABSENT_FROM_BASE);

    for (const outcome of outcomes) {
      const text: string = audit.candidateClosingGuidance(outcome);
      const earned = outcome === audit.BASE_COMPARISON.ABSENT_FROM_BASE;
      for (const claim of ATTRIBUTION) {
        if (earned) expect(text).toContain(claim);
        else expect(text, `outcome ${outcome} claims "${claim}"`).not.toContain(claim);
      }
      // Nothing else names a cause either: the two outcomes that measured no
      // difference say what was measured and stop.
      if (!earned) expect(text).not.toMatch(/caused by|introduced by|blame|this branch's fault/i);
    }
  });

  it('QGF-112.AC2 refuses an outcome it does not recognise instead of defaulting to attribution', async () => {
    const audit = await auditModule();
    for (const unknown of [undefined, null, '', 'yes', 'toString', 'constructor', 0, {}]) {
      expect(() => audit.candidateClosingGuidance(unknown)).toThrow(/unknown base-comparison/i);
    }
  });

  it('QGF-112.AC2 holds the branch-attributing text in one binding reached from one outcome', () => {
    // The runtime check above proves the composer returns it for one outcome.
    // This proves there is no SECOND way to print it: the sentence exists once
    // in the module, under one name, used once — as the value of the entry
    // keyed by the outcome that measured its absence on the base.
    for (const claim of ATTRIBUTION) {
      expect(occurrences(auditSource, claim), `"${claim}" occurs more than once`).toBe(1);
    }
    expect(
      occurrences(auditSource, 'BRANCH_ATTRIBUTED_GUIDANCE'),
      'the attributing text should be declared once and referenced once',
    ).toBe(2);
    expect(auditSource).toContain('[BASE_COMPARISON.ABSENT_FROM_BASE, BRANCH_ATTRIBUTED_GUIDANCE]');
  });

  it('QGF-112.AC3 imports without spawning a child process, installing, auditing or reaching the network', () => {
    const child = importInChild();

    expect(child.stderr).toBe('');
    expect(child.stdout).toBe('IMPORTED');
    expect(child.status).toBe(0);
    // No npm was reachable on PATH and nothing complained, and no banner was
    // printed: the install-and-audit run was not entered.
    expect(child.stdout + child.stderr).not.toMatch(/Consumer-resolution audit|npm error/);
    expect(child.tempEntries).toEqual([]);
  });

  it('QGF-112.AC3 imports without creating a scratch directory', () => {
    // TMPDIR points at a path that does not exist, so the `mkdtempSync` that
    // opens the audit would throw ENOENT — outside the run's own try/catch, so
    // it would reject the import. A clean import is the measurement.
    const missing = path.join(os.tmpdir(), `qgf112-absent-tmpdir-${process.pid}-${Date.now()}`);
    expect(fs.existsSync(missing)).toBe(false);

    const child = importInChild({ TMPDIR: missing });

    expect(child.stderr).toBe('');
    expect(child.stdout).toBe('IMPORTED');
    expect(child.status).toBe(0);
    expect(fs.existsSync(missing)).toBe(false);
  });

  it('QGF-112.AC3 still runs the audit when the module is the process entry point', () => {
    // The guard must not have turned the gate off: run as the program, with a
    // `--target` that has no value, it still reaches argument handling and
    // exits non-zero.
    const child = spawnSync(process.execPath, [AUDIT_SCRIPT, '--target'], {
      encoding: 'utf-8',
      timeout: 60_000,
    });

    expect(child.stderr).toContain('--target needs a value');
    expect(child.status).toBe(2);
  });

  it('QGF-112.AC4 allowlists no advisory on a package this repository publishes', async () => {
    const audit = await auditModule();
    const published = fs
      .readdirSync(path.join(REPO_ROOT, 'packages'))
      .map((dir) => path.join(REPO_ROOT, 'packages', dir, 'package.json'))
      .filter((manifest) => fs.existsSync(manifest))
      .map((manifest) => JSON.parse(fs.readFileSync(manifest, 'utf-8')).name as string);
    expect(published).toContain('opena2a-cli');

    // An entry naming one of our own packages would be this gate waiving the
    // thing it exists to measure, so the check is on every string an entry
    // carries rather than on the `package` field alone.
    for (const entry of audit.ALLOWED as Array<Record<string, unknown>>) {
      for (const value of Object.values(entry)) {
        if (typeof value === 'string') expect(published).not.toContain(value);
      }
    }
  });

  it('QGF-112.AC4 keeps both forbidden nested packages and the derived hackmyagent waiver', async () => {
    const audit = await auditModule();
    const forbidden = audit.FORBIDDEN_PACKAGES as Array<Record<string, any>>;
    expect(forbidden.map((f) => [f.name, f.where])).toEqual([
      ['opena2a-cli', 'nested'],
      ['hackmyagent', 'nested'],
    ]);

    expect(forbidden[0].waiver).toBeUndefined();
    expect(forbidden[1].waiver.reviewBy).toBe('2026-11-01');
    // A waiver may not state an environment-dependent fact; it derives it.
    expect(typeof forbidden[1].waiver.derive).toBe('function');
    expect(forbidden[1].waiver.derive.name).toBe('deriveNestedHackmyagent');
  });

  it('QGF-112.AC4 still exits 1 whenever the run collected any failure', () => {
    // Unconditional on `failures` being non-empty: no severity threshold, no
    // mode that downgrades it to a warning, nothing between the banner and the
    // exit. Read from source because the exit is what a test cannot survive.
    const guarded = auditSource.match(/ {2}if \(failures\.length > 0\) \{[\s\S]*?\n {2}\}/);
    expect(guarded).not.toBeNull();
    expect(guarded![0]).toContain('    process.exit(1);\n  }');
    expect(occurrences(auditSource, 'process.exit(1)')).toBe(1);
  });

  it('QGF-112.AC4 leaves every packages/* dependency version where base put it', () => {
    // The candidate run is red because `packages/cli` pins workspace versions a
    // consumer has to resolve from the registry. Moving any of these numbers
    // would change what the gate measures, which is not what this change is
    // allowed to do — it changes what the run SAYS. Update deliberately, in a
    // change that is about the dependency.
    const BASE: Record<string, Record<string, Record<string, string>>> = {
      'ai-classifier': {
        devDependencies: { '@types/node': '^20.11.0', typescript: '^5.7.0', vitest: '^4.1.8' },
      },
      'aim-core': {
        dependencies: { 'js-yaml': '^4.1.1', tweetnacl: '^1.0.3' },
        devDependencies: {
          '@types/js-yaml': '^4.0.9',
          '@types/node': '^20.0.0',
          typescript: '^5.3.3',
          vitest: '^4.1.8',
        },
      },
      'atx-verify': {
        dependencies: { canonicalize: '2.1.0' },
        devDependencies: { '@types/node': '^20.11.0', typescript: '^5.7.0', vitest: '^4.1.8' },
      },
      'check-core': {
        dependencies: { '@opena2a/registry-client': '0.1.0' },
        devDependencies: { '@types/node': '^20.11.0', typescript: '^5.7.0', vitest: '^4.1.8' },
      },
      cli: {
        dependencies: {
          '@inquirer/prompts': '^7.0.0',
          '@opena2a/aicomply': '2.2.3',
          '@opena2a/cli-ui': '0.6.0',
          '@opena2a/contribute': '0.1.0',
          '@opena2a/credential-patterns': '0.1.3',
          '@opena2a/registry-client': '0.2.0',
          '@opena2a/shared': '0.1.2',
          '@opena2a/telemetry': '0.3.0',
          'ai-trust': '^0.2.23',
          commander: '^13.1.0',
          hackmyagent: '0.30.0',
          'secretless-ai': '^0.14.1',
        },
        devDependencies: {
          '@types/js-yaml': '^4.0.9',
          '@types/node': '^22.0.0',
          'js-yaml': '^4.1.0',
          tsx: '^4.21.0',
          typescript: '^5.7.0',
          vitest: '^4.1.8',
        },
        optionalDependencies: { '@opena2a/aim-core': '*' },
      },
      'cli-ui': {
        dependencies: { chalk: '^5.3.0' },
        devDependencies: { '@types/node': '^20.11.0', typescript: '^5.7.0', vitest: '^4.1.8' },
      },
      contribute: { devDependencies: { typescript: '^5.7.0', vitest: '^4.1.8' } },
      'credential-patterns': {
        devDependencies: { '@types/node': '^20.11.0', typescript: '^5.7.0', vitest: '^4.1.8' },
      },
      'registry-client': {
        dependencies: { tweetnacl: '^1.0.3' },
        devDependencies: { '@types/node': '^20.11.0', typescript: '^5.7.0', vitest: '^4.1.8' },
      },
      shared: {
        dependencies: { zod: '^3.24.0' },
        devDependencies: { typescript: '^5.7.0', vitest: '^4.1.8' },
      },
      telemetry: {
        devDependencies: { '@types/node': '^20.11.0', typescript: '^5.7.0', vitest: '^4.1.8' },
      },
    };

    const actual: Record<string, Record<string, Record<string, string>>> = {};
    for (const dir of fs.readdirSync(path.join(REPO_ROOT, 'packages')).sort()) {
      const manifestPath = path.join(REPO_ROOT, 'packages', dir, 'package.json');
      if (!fs.existsSync(manifestPath)) continue;
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
      const blocks: Record<string, Record<string, string>> = {};
      for (const block of [
        'dependencies',
        'devDependencies',
        'optionalDependencies',
        'peerDependencies',
      ]) {
        if (manifest[block]) blocks[block] = manifest[block];
      }
      actual[dir] = blocks;
    }

    expect(actual).toEqual(BASE);
  });

  it('QGF-112.AC5 keeps consumer-audit-candidate wired to every non-schedule event and able to fail', () => {
    const workflow = yaml.load(fs.readFileSync(SECURITY_WORKFLOW, 'utf-8')) as any;
    const job = workflow.jobs['consumer-audit-candidate'];

    expect(job.name).toBe('Consumer resolution audit (candidate artifact)');
    expect(job.if).toBe("github.event_name != 'schedule'");

    const audited = job.steps[job.steps.length - 1];
    expect(audited.run.trim()).toBe(
      'npm run audit:consumer -- --target "${{ steps.pack.outputs.tarball }}"',
    );

    // A gate that cannot fail is not a gate.
    expect(job['continue-on-error']).toBeUndefined();
    for (const step of job.steps) expect(step['continue-on-error']).toBeUndefined();
    expect(JSON.stringify(job)).not.toContain('|| true');
  });

  it('QGF-112.AC5 keeps the workflow on pull_request, push and schedule with no paths filter', () => {
    const workflow = yaml.load(fs.readFileSync(SECURITY_WORKFLOW, 'utf-8')) as any;
    // YAML 1.1 readers resolve a bare `on:` key to boolean true; js-yaml 4 does
    // not, but reading both keeps this pinned to the workflow rather than to
    // the parser.
    const triggers = workflow.on ?? workflow[true as unknown as string];

    expect(Object.keys(triggers).sort()).toEqual(['pull_request', 'push', 'schedule']);
    // A `paths` filter would let a diff skip the gate by touching nothing it lists.
    expect(JSON.stringify(triggers)).not.toContain('paths');
  });

  it('QGF-112.AC5 leaves consumer-audit-published and the PUBLISHED closing text at base', () => {
    const workflow = yaml.load(fs.readFileSync(SECURITY_WORKFLOW, 'utf-8')) as any;

    expect(workflow.jobs['consumer-audit-published']).toEqual({
      name: 'Consumer resolution audit (published artifact)',
      if: "github.event_name == 'schedule'",
      'runs-on': 'ubuntu-latest',
      permissions: { contents: 'read' },
      steps: [
        { uses: 'actions/checkout@v4' },
        { uses: 'actions/setup-node@v4', with: { 'node-version': 22 } },
        { name: 'Audit the tree a consumer resolves from npm today', run: 'npm run audit:consumer' },
      ],
    });

    // The PUBLISHED half of the closing text says a true thing about a measured
    // artifact and is untouched by this contract.
    expect(auditSource).toContain(
      "'  This is the PUBLISHED run. It measured what users can install right now, so a\\n' +",
    );
    expect(auditSource).toContain(
      "'  failure here is NOT fixable by merging — it clears when a fix is released.\\n'",
    );
    expect(auditSource).toContain("if (target.mode === 'CANDIDATE') {");
  });
});
