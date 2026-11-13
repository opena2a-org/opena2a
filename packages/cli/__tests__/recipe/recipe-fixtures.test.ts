/**
 * The three agents .github/workflows/recipe.yml runs the published CI recipe
 * against, under test/fixtures/recipe/. Each control must be refused by its
 * own threshold and pass the other, so each is pinned here to the findings
 * that put it there, through the built CLI with the arguments the recipe
 * passes. A scoring change that lifts a control over its threshold fails this
 * file in the same pull request, before the workflow's control could pass for
 * a reason other than the one it is there for. The same agent without its
 * planted items must clear the threshold, so the named findings are the cause
 * and not a bystander.
 *
 *  - agent-review-below-50: one project MCP server with shell access
 *    (`.mcp.json`, `shell-runner`). detect rates it critical; review reports it
 *    as the `shadow-ai` finding `mcp-server`, and the Project Governance
 *    participant of the dominant-analyzer floor holds the composite under 50.
 *    Its governance deduction alone leaves governance at 60 or more.
 *  - agent-governance-below-60: three AI configuration files that grant broad
 *    permissions (`ai.config.json`, `ai.config.yml`, `langchain.config.js`),
 *    each rated high by detect; together they take governance under 60. None
 *    is critical, so review's composite stays at 50 or more.
 *  - agent-benign: a SOUL.md, no MCP server and one AI configuration rated low.
 *
 * The children run with a fresh HOME (no host Shield log, MCP configuration
 * or identity), the advisory request turned off and the Registry at a refused
 * loopback port, and with `--skip-hma`: the recipe reaches the scanner
 * through npx, which would fetch it. detect also counts AI tools running on
 * the host; a developer machine runs some and the CI runner runs none, so the
 * children see a `ps` that lists no process. One child runs at a time.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const CLI = path.resolve(__dirname, '..', '..', 'dist', 'index.js');
const FIXTURES = path.join(REPO_ROOT, 'test', 'fixtures', 'recipe');
const TIMEOUT = 180_000;

let scratch: string;
let home: string;
let bin: string;

beforeAll(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'recipe-fixtures-'));
  home = path.join(scratch, 'home');
  bin = path.join(scratch, 'bin');
  fs.mkdirSync(home);
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'ps'), '#!/bin/sh\necho "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND"\n', {
    mode: 0o755,
  });
});

afterAll(() => {
  if (scratch) fs.rmSync(scratch, { recursive: true, force: true });
});

interface Run<T> {
  status: number | null;
  json: T;
  stderr: string;
}

interface DetectJson {
  summary: { governanceScore: number; totalAgents: number };
  agents: unknown[];
  mcpServers: { name: string; source: string; risk: string; verified: boolean }[];
  aiConfigs: { file: string; risk: string }[];
  identity: { soulFiles: number; aimIdentities: number };
  findings: { severity: string; category: string; title: string }[];
}

interface ReviewJson {
  compositeScore: number;
  scoreModel: { floorHeldBy: string[] };
  reportFindings: {
    severity: string;
    title: string;
    foundBy: { source: string; checkId: string }[];
    locations: { file: string }[];
  }[];
}

/** The built CLI with the recipe's arguments, from outside the scanned tree. */
function cli<T>(verb: 'detect' | 'review', target: string): Run<T> {
  const args = [CLI, verb, target, '--format', 'json', '--ci'];
  if (verb === 'review') args.push('--skip-hma');
  const res = spawnSync(process.execPath, args, {
    cwd: scratch,
    encoding: 'utf-8',
    timeout: TIMEOUT - 10_000,
    env: {
      PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
      HOME: home,
      USERPROFILE: home,
      XDG_CONFIG_HOME: path.join(home, '.config'),
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      OPENA2A_ADVISORIES: 'off',
      OPENA2A_REGISTRY_URL: 'http://127.0.0.1:9',
    },
  });
  let json: T;
  try {
    json = JSON.parse(res.stdout) as T;
  } catch {
    throw new Error(`${verb} ${target} printed no JSON (exit ${res.status}): ${res.stderr.slice(0, 2000)}`);
  }
  return { status: res.status, json, stderr: res.stderr };
}

/** A copy of a fixture without the named files, for the cause-and-effect cases. */
function without(fixture: string, files: string[]): string {
  const copy = path.join(scratch, `${fixture}-without-${files.length}`);
  fs.cpSync(path.join(FIXTURES, fixture), copy, { recursive: true });
  for (const f of files) {
    expect(fs.existsSync(path.join(copy, f)), f).toBe(true);
    fs.rmSync(path.join(copy, f));
  }
  return copy;
}

const fixture = (name: string): string => path.join(FIXTURES, name);

const riskByFile = (d: DetectJson): Record<string, string> =>
  Object.fromEntries(d.aiConfigs.map((c) => [c.file, c.risk]));

const projectServers = (d: DetectJson) => d.mcpServers.filter((s) => s.source.includes('(project)'));

const ids = (r: ReviewJson): string[] =>
  r.reportFindings.flatMap((f) => f.foundBy.map((b) => `${f.severity} ${b.source}:${b.checkId}`));

describe('agent-review-below-50: review refuses it, governance passes it', () => {
  it(
    'review exits 1 with the composite under 50, held there by shadow-ai mcp-server on .mcp.json',
    () => {
      const r = cli<ReviewJson>('review', fixture('agent-review-below-50'));
      expect(r.status, r.stderr).toBe(1);
      expect(typeof r.json.compositeScore).toBe('number');
      expect(r.json.compositeScore).toBeLessThan(50);
      expect(r.json.scoreModel.floorHeldBy).toEqual(['Project Governance']);
      const mcp = r.json.reportFindings.filter((f) => f.foundBy.some((b) => b.source === 'shadow-ai' && b.checkId === 'mcp-server'));
      expect(mcp, JSON.stringify(ids(r.json))).toHaveLength(1);
      expect(mcp[0].severity).toBe('critical');
      expect(mcp[0].locations.map((l) => l.file)).toEqual(['.mcp.json']);
    },
    TIMEOUT,
  );

  it(
    'detect: governance at 60 or more; the one project MCP server, shell-runner, is critical',
    () => {
      const d = cli<DetectJson>('detect', fixture('agent-review-below-50'));
      expect(d.status, d.stderr).toBe(0);
      expect(d.json.agents).toEqual([]);
      expect(projectServers(d.json).map((s) => [s.name, s.risk, s.verified])).toEqual([['shell-runner', 'critical', false]]);
      expect(d.json.findings.map((f) => [f.severity, f.category])).toContainEqual(['critical', 'mcp']);
      expect(d.json.summary.governanceScore).toBeGreaterThanOrEqual(60);
    },
    TIMEOUT,
  );

  it(
    'without .mcp.json, review exits 0 at 50 or more with no floor held',
    () => {
      const r = cli<ReviewJson>('review', without('agent-review-below-50', ['.mcp.json']));
      expect(r.status, r.stderr).toBe(0);
      expect(r.json.compositeScore).toBeGreaterThanOrEqual(50);
      expect(r.json.scoreModel.floorHeldBy).toEqual([]);
    },
    TIMEOUT,
  );
});

describe('agent-governance-below-60: governance refuses it, review passes it', () => {
  const PLANTED = ['ai.config.json', 'ai.config.yml', 'langchain.config.js'];

  it(
    'detect: governance under 60 from three AI configuration files rated high, and nothing else',
    () => {
      const d = cli<DetectJson>('detect', fixture('agent-governance-below-60'));
      expect(d.status, d.stderr).toBe(0);
      expect(d.json.agents).toEqual([]);
      expect(projectServers(d.json)).toEqual([]);
      expect(riskByFile(d.json)).toEqual(Object.fromEntries(PLANTED.map((f) => [f, 'high'])));
      expect(d.json.findings.map((f) => [f.severity, f.category, f.title])).toEqual([
        ['high', 'config', 'AI config files grant broad permissions'],
      ]);
      expect(d.json.summary.governanceScore).toBeLessThan(60);
    },
    TIMEOUT,
  );

  it(
    'review exits 0 at 50 or more: no planted file is critical, so no floor is held',
    () => {
      const r = cli<ReviewJson>('review', fixture('agent-governance-below-60'));
      expect(r.status, r.stderr).toBe(0);
      expect(r.json.compositeScore).toBeGreaterThanOrEqual(50);
      expect(r.json.scoreModel.floorHeldBy).toEqual([]);
    },
    TIMEOUT,
  );

  it(
    'without the three files, governance is 60 or more',
    () => {
      const d = cli<DetectJson>('detect', without('agent-governance-below-60', PLANTED));
      expect(d.status, d.stderr).toBe(0);
      expect(d.json.aiConfigs).toEqual([]);
      expect(d.json.summary.governanceScore).toBeGreaterThanOrEqual(60);
    },
    TIMEOUT,
  );
});

describe('agent-benign: both scores clear their thresholds', () => {
  it(
    'detect: governance at 60 or more; SOUL.md is read and the one AI configuration is rated low',
    () => {
      const d = cli<DetectJson>('detect', fixture('agent-benign'));
      expect(d.status, d.stderr).toBe(0);
      expect(d.json.agents).toEqual([]);
      expect(projectServers(d.json)).toEqual([]);
      expect(d.json.identity.soulFiles).toBe(1);
      expect(riskByFile(d.json)).toEqual({ 'ai.config.json': 'low' });
      expect(d.json.findings.filter((f) => f.severity === 'critical' || f.severity === 'high')).toEqual([]);
      expect(d.json.summary.governanceScore).toBeGreaterThanOrEqual(60);
    },
    TIMEOUT,
  );

  it(
    'review exits 0 at 50 or more with no floor held',
    () => {
      const r = cli<ReviewJson>('review', fixture('agent-benign'));
      expect(r.status, r.stderr).toBe(0);
      expect(r.json.compositeScore).toBeGreaterThanOrEqual(50);
      expect(r.json.scoreModel.floorHeldBy).toEqual([]);
    },
    TIMEOUT,
  );
});
