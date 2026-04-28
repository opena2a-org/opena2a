#!/usr/bin/env tsx
/**
 * release-smoke-corpus.ts — opena2a-corpus consumer harness for opena2a-cli.
 *
 * Per [CHIEF-CA-044] each consumer ships its own harness; this one's
 * particular job is verifying structural parity between `opena2a scan`
 * and `hackmyagent secure` for every fixture. The opena2a-cli delegates
 * to HMA; if structural parity drifts (different score, different finding
 * IDs), the wrapper has diverged and that's a release-blocker.
 *
 * "Structural parity" = same score + same set of distinguishing finding
 * IDs + same severity histogram. Timestamps and "fix" command strings
 * differ legitimately (different binary names) and are normalized out.
 *
 * Per [CHIEF-CDS-028] OPENA2A_CORPUS_DETERMINISTIC=1 is set.
 *
 * Exit code 0 = green, 1 = drift, 2 = setup error.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync, statSync, readdirSync, mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface FixtureManifest {
  fixture: string;
  surface: string;
  intent: string;
  expected?: {
    opena2aCli?: {
      delegateTo?: string;
      parity?: 'byte-identical-to-hma' | 'structurally-equivalent' | 'independent';
    };
    hma?: { score?: { min: number; max: number } };
  };
}

interface CorpusManifest {
  corpusName: string;
  corpusVersion: string;
  consumers: { name: string; surfaces: string[] }[];
}

const CORPUS_ROOT =
  process.env.OPENA2A_CORPUS_PATH ?? join(homedir(), '.opena2a', 'corpus');
const OPENA2A_CLI = resolve(__dirname, '..', 'dist', 'index.js');
const HMA_CLI =
  process.env.HMA_CLI_PATH ??
  resolve(__dirname, '..', '..', '..', '..', 'hackmyagent', 'dist', 'cli.js');
const CONSUMER_NAME = 'opena2a-cli';
const UPDATE_GOLDEN = process.env.OPENA2A_CORPUS_UPDATE_GOLDEN === '1';
const GOLDEN_ROOT = resolve(__dirname, '..', 'golden', 'opena2a-cli');

function fail(msg: string, code = 2): never {
  process.stderr.write(`release-smoke-corpus: ${msg}\n`);
  process.exit(code);
}

function loadCorpusManifest(): CorpusManifest {
  const path = join(CORPUS_ROOT, 'corpus-manifest.yaml');
  if (!existsSync(path)) {
    fail(
      `corpus not found at ${CORPUS_ROOT}\n` +
        `clone it: git clone https://github.com/opena2a-org/opena2a-corpus.git ${CORPUS_ROOT}\n` +
        `or set OPENA2A_CORPUS_PATH to a local checkout.`,
    );
  }
  return yaml.load(readFileSync(path, 'utf8')) as CorpusManifest;
}

function loadFixtureManifest(path: string): FixtureManifest {
  return yaml.load(readFileSync(path, 'utf8')) as FixtureManifest;
}

function consumerSurfaces(corpus: CorpusManifest): string[] {
  const me = corpus.consumers.find((c) => c.name === CONSUMER_NAME);
  if (!me) fail(`consumer '${CONSUMER_NAME}' not in corpus-manifest.yaml`);
  return me.surfaces;
}

interface ScanResult {
  score: number;
  findings: string[];
  severities: Record<string, number>;
}

function runScan(cli: 'opena2a' | 'hma', target: string): ScanResult {
  const env = { ...process.env, OPENA2A_CORPUS_DETERMINISTIC: '1' };
  const args =
    cli === 'opena2a'
      ? [OPENA2A_CLI, 'scan', target, '--json']
      : [HMA_CLI, 'secure', target, '--json'];
  const r = spawnSync(process.execPath, args, {
    encoding: 'utf8',
    env,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (!r.stdout) {
    return { score: -1, findings: [`__${cli}_exit_${r.status}__`], severities: {} };
  }
  const data = JSON.parse(r.stdout);
  const fails = (data.allFindings ?? data.findings ?? []).filter(
    (f: { passed?: boolean }) => f.passed === false,
  ) as { checkId: string; severity: string }[];
  const findings = [...new Set(fails.map((f) => f.checkId))].sort();
  const severities = fails.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  return {
    score: typeof data.score === 'number' ? data.score : -1,
    findings,
    severities,
  };
}

function severitiesEqual(a: Record<string, number>, b: Record<string, number>): boolean {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of keys) {
    if ((a[k] ?? 0) !== (b[k] ?? 0)) return false;
  }
  return true;
}

function findingsEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((id, i) => id === b[i]);
}

function renderGolden(opena2a: ScanResult, hma: ScanResult): string {
  const sevSorted = (s: Record<string, number>) =>
    JSON.stringify(Object.fromEntries(Object.entries(s).sort()));
  return [
    `parity=${opena2a.score === hma.score && findingsEqual(opena2a.findings, hma.findings) && severitiesEqual(opena2a.severities, hma.severities) ? 'green' : 'drift'}`,
    `score.opena2a=${opena2a.score}`,
    `score.hma=${hma.score}`,
    `severities.opena2a=${sevSorted(opena2a.severities)}`,
    `severities.hma=${sevSorted(hma.severities)}`,
    `checkIds.opena2a=${opena2a.findings.join(',')}`,
    `checkIds.hma=${hma.findings.join(',')}`,
    '',
  ].join('\n');
}

function diffFixture(
  fixtureRel: string,
  fixtureDir: string,
  manifest: FixtureManifest,
): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const expected = manifest.expected?.opena2aCli;
  if (!expected) {
    return {
      ok: true,
      reasons: ['skipped: manifest declares no opena2aCli expectation'],
    };
  }
  const opena2a = runScan('opena2a', fixtureDir);
  const hma = runScan('hma', fixtureDir);
  if (opena2a.score === -1 || hma.score === -1) {
    reasons.push(
      `cli exited non-zero (opena2a=${opena2a.score}, hma=${hma.score})`,
    );
    return { ok: false, reasons };
  }
  // Apply parity contract.
  if (expected.parity === 'byte-identical-to-hma') {
    // Stricter: identical score + identical findings + identical severities.
    if (opena2a.score !== hma.score) {
      reasons.push(`score mismatch: opena2a=${opena2a.score} hma=${hma.score}`);
    }
    if (!findingsEqual(opena2a.findings, hma.findings)) {
      reasons.push(`findings drift: count differs or IDs differ`);
    }
    if (!severitiesEqual(opena2a.severities, hma.severities)) {
      reasons.push(`severities drift`);
    }
  } else if (expected.parity === 'structurally-equivalent') {
    // Same score + same finding ID set + same severity histogram (timestamp /
    // fix-string differences are normalized out by ignoring those fields).
    if (opena2a.score !== hma.score) {
      reasons.push(`score mismatch: opena2a=${opena2a.score} hma=${hma.score}`);
    }
    if (!findingsEqual(opena2a.findings, hma.findings)) {
      reasons.push(`finding-ID set mismatch`);
    }
    if (!severitiesEqual(opena2a.severities, hma.severities)) {
      reasons.push(`severity histogram mismatch`);
    }
  }
  // Golden snapshot — captures both sides for future drift inspection.
  const goldenPath = join(GOLDEN_ROOT, fixtureRel, 'parity.txt');
  const rendered = renderGolden(opena2a, hma);
  if (UPDATE_GOLDEN) {
    mkdirSync(dirname(goldenPath), { recursive: true });
    writeFileSync(goldenPath, rendered);
  } else if (existsSync(goldenPath)) {
    if (readFileSync(goldenPath, 'utf8') !== rendered) {
      reasons.push(
        `golden mismatch — re-run with OPENA2A_CORPUS_UPDATE_GOLDEN=1 to update`,
      );
    }
  } else {
    reasons.push(
      `golden missing — run with OPENA2A_CORPUS_UPDATE_GOLDEN=1 to bake`,
    );
  }
  return { ok: reasons.length === 0, reasons };
}

function main(): void {
  if (!existsSync(OPENA2A_CLI)) {
    fail(`opena2a-cli dist/index.js not built. run \`npm run build\` first.`);
  }
  if (!existsSync(HMA_CLI)) {
    fail(
      `hackmyagent dist/cli.js not built at ${HMA_CLI}.\n` +
        `set HMA_CLI_PATH or build hackmyagent first.`,
    );
  }
  const corpus = loadCorpusManifest();
  const surfaces = consumerSurfaces(corpus);
  process.stdout.write(
    `release-smoke-corpus: ${corpus.corpusName} ${corpus.corpusVersion}\n` +
      `consumer: ${CONSUMER_NAME}, surfaces: ${surfaces.join(',')}\n` +
      `corpus path: ${CORPUS_ROOT}\n` +
      `hma cli: ${HMA_CLI}\n\n`,
  );

  let pass = 0;
  let fail_ = 0;
  let skip = 0;
  for (const surface of surfaces) {
    const surfaceDir = join(CORPUS_ROOT, surface);
    if (!existsSync(surfaceDir)) {
      process.stdout.write(`  skip ${surface}/* — surface absent (Phase 3?)\n`);
      skip++;
      continue;
    }
    for (const intent of ['benign', 'buggy', 'malicious']) {
      const intentDir = join(surfaceDir, intent);
      if (!existsSync(intentDir)) continue;
      for (const fixtureName of readdirSync(intentDir)) {
        const fixtureDir = join(intentDir, fixtureName);
        if (!statSync(fixtureDir).isDirectory()) continue;
        const manifestPath = join(fixtureDir, 'manifest.yaml');
        if (!existsSync(manifestPath)) continue;
        const manifest = loadFixtureManifest(manifestPath);
        const fixtureRel = `${surface}/${intent}/${fixtureName}`;
        const r = diffFixture(fixtureRel, fixtureDir, manifest);
        if (r.ok) {
          process.stdout.write(`  ok   ${fixtureRel}\n`);
          pass++;
        } else {
          process.stdout.write(`  FAIL ${fixtureRel}\n`);
          for (const reason of r.reasons) {
            process.stdout.write(`         ${reason}\n`);
          }
          fail_++;
        }
      }
    }
  }
  process.stdout.write(`\n${pass} passed, ${fail_} failed, ${skip} skipped\n`);
  process.exit(fail_ === 0 ? 0 : 1);
}

main();
