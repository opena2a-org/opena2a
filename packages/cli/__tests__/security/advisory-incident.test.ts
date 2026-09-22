import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import yaml from 'js-yaml';

/**
 * The weekly PUBLISHED consumer-resolution audit measures a tree no pull request
 * can change: what a user installing `opena2a-cli` from npm resolves today. When
 * it goes red, the only place that fact existed was a scheduled run's log, which
 * nobody is subscribed to — so a live advisory reaching users could sit unread
 * between Mondays.
 *
 * `scripts/advisory-incident.mjs` turns that red run into ONE GitHub issue
 * labelled `published-artifact-advisory`, and closes it when the closure audits
 * clean again. The two halves this file measures:
 *
 *   the record  — built from the CAPTURED COMBINED stdout and stderr of the
 *                 audit, because the version is on stdout
 *                 (audit-consumer-resolution.mjs:712-714) and the advisory ids
 *                 are on stderr (:736 pushed onto `failures`, printed at
 *                 :811-813). A failure step capturing stdout alone would file an
 *                 incident naming a version and no advisory — the reader-facing
 *                 half. The captures below are therefore built as two named
 *                 halves and joined, so a parser that reads only one of them
 *                 fails here rather than in production.
 *
 *   the wiring  — .github/workflows/security.yml, parsed as YAML rather than
 *                 grepped: `issues: write` on the scheduled job only, the
 *                 failure step gated on `failure() && github.event_name ==
 *                 'schedule'`, and NO path by which a pull request run can open
 *                 an issue.
 *
 * No test here reaches GitHub. The issue client is injected, and every write it
 * would perform is recorded and asserted against.
 */

const LABEL = 'published-artifact-advisory';
const ASSIGNEE = 'thebenignhacker';
const WORKFLOW_REL = '.github/workflows/security.yml';
const AUDIT_SCRIPT_REL = 'scripts/audit-consumer-resolution.mjs';
const INCIDENT_SCRIPT_REL = 'scripts/advisory-incident.mjs';
const RUN_URL = 'https://github.com/opena2a-org/opena2a/actions/runs/17482910463';

/**
 * Repo root: the nearest ancestor whose package.json declares workspaces.
 *
 * Anchored on `import.meta.url` rather than `__dirname` so the file is a plain
 * ES module: it runs identically under the runner and under bare `node`, which
 * is how this suite is re-derived where the runner cannot be installed.
 */
function repoRoot(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
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

function incidentScriptPath(): string {
  return path.join(repoRoot(), INCIDENT_SCRIPT_REL);
}

/**
 * The module under test, imported by path rather than by package specifier.
 *
 * Loaded per test instead of at file scope on purpose: before the module exists,
 * a file-scope import fails collection and every criterion in this file reports
 * as one unnamed error. Imported here, the red-first run names each criterion it
 * fails.
 */
async function incident(): Promise<Record<string, any>> {
  return import(/* @vite-ignore */ pathToFileURL(incidentScriptPath()).href);
}

// --- Captures --------------------------------------------------------------
//
// The shapes below mirror what audit-consumer-resolution.mjs prints. They are
// held to the script's own source by the last AC1 case, so a change to either
// side shows up as a failure rather than as a fixture that quietly drifted.

const ADVISORY_HIGH = 'GHSA-xcpc-8h2w-3j85';
const ADVISORY_CRITICAL = 'GHSA-7fh5-64p2-3v2j';
const RESOLVED_VERSION = '0.10.13';
const PACKAGE_COUNT = '412';

/** What `console.log` writes: the banner, the resolved line, the counts. */
const PUBLISHED_STDOUT = [
  '[PUBLISHED] PUBLISHED artifact — the tree a user resolves from npm right now',
  '[PUBLISHED] Has the already-shipped tree drifted into an advisory since release?',
  '[PUBLISHED] Target: opena2a-cli@latest',
  '',
  `[PUBLISHED] Resolved opena2a-cli@${RESOLVED_VERSION} — ${PACKAGE_COUNT} packages in the production closure`,
  '',
  'Consumer resolution: 1 critical, 1 high, 3 moderate, 0 low',
  "(This repo's own workspace audit measures a different tree — devDependencies " +
    'included, `overrides` honoured, nothing published — and its number does not ' +
    'describe what a user installs.)',
  '',
].join('\n');

/** What `console.error` writes: the FAILED banner and every failure entry. */
const PUBLISHED_STDERR = [
  '',
  '[PUBLISHED] Consumer-resolution audit FAILED — PUBLISHED artifact — the tree a user resolves from npm right now:',
  '',
  `  - Unlisted high advisory in the consumer tree: ${ADVISORY_HIGH} (via adm-zip).`,
  '    A user installing opena2a-cli inherits it. Either raise the floor to a patched',
  '    version, drop the dependency, or add it to ALLOWED in',
  '    scripts/audit-consumer-resolution.mjs with a reason a user would accept, a review',
  '    date, and a derivation for anything about it that depends on the environment.',
  '',
  `  - Unlisted critical advisory in the consumer tree: ${ADVISORY_CRITICAL} (via onnxruntime-node, hackmyagent).`,
  '    A user installing opena2a-cli inherits it. Either raise the floor to a patched',
  '    version, drop the dependency, or add it to ALLOWED in',
  '    scripts/audit-consumer-resolution.mjs with a reason a user would accept, a review',
  '    date, and a derivation for anything about it that depends on the environment.',
  '',
  '  This is the PUBLISHED run. It measured what users can install right now, so a',
  '  failure here is NOT fixable by merging — it clears when a fix is released.',
  '',
].join('\n');

/** The file the workflow's `2>&1 | tee` leaves behind: both halves, one file. */
const PUBLISHED_CAPTURE = `${PUBLISHED_STDOUT}${PUBLISHED_STDERR}`;

/** The shape the audit writes when it throws before measuring anything. */
const UNMEASURED_REASON =
  'npm install --omit=dev --ignore-scripts failed: request to ' +
  'https://registry.npmjs.org/opena2a-cli failed, reason: getaddrinfo EAI_AGAIN registry.npmjs.org';
const UNMEASURED_CAPTURE = [
  '[PUBLISHED] PUBLISHED artifact — the tree a user resolves from npm right now',
  '[PUBLISHED] Has the already-shipped tree drifted into an advisory since release?',
  '[PUBLISHED] Target: opena2a-cli@latest',
  '',
  '[PUBLISHED] Consumer-resolution audit FAILED — PUBLISHED artifact — the tree a user resolves from npm right now:',
  '',
  '  - The consumer tree was not measured, so this run produced no result:',
  `    ${UNMEASURED_REASON}`,
  '',
].join('\n');

/** The other artifact. A pull request's run, which may never file an incident. */
const CANDIDATE_CAPTURE = [
  '[CANDIDATE] CANDIDATE artifact — the tree a user would resolve from THIS BRANCH',
  '[CANDIDATE] Would merging this change ship an advisory to users?',
  '[CANDIDATE] Target: /home/runner/work/_temp/candidate/opena2a-cli-0.10.14.tgz',
  '',
  '[CANDIDATE] Resolved opena2a-cli@0.10.14 — 413 packages in the production closure',
  '',
  '[CANDIDATE] Consumer-resolution audit FAILED — CANDIDATE artifact — the tree a user would resolve from THIS BRANCH:',
  '',
  `  - Unlisted high advisory in the consumer tree: ${ADVISORY_HIGH} (via adm-zip).`,
  '',
].join('\n');

// --- The injected issues client -------------------------------------------

type IssueStub = { number: number; title: string };
type Call = { method: string; args: any[] };

const READ = 'listOpenLabelled';

/**
 * Stands in for the forge. It answers exactly one question — which OPEN issues
 * carry the label — and records every call, so "performs zero writes" and
 * "performs exactly one create" are measured rather than assumed.
 */
function fakeClient(open: IssueStub[]) {
  const calls: Call[] = [];
  let nextNumber = 900;
  return {
    calls,
    writes(): Call[] {
      return calls.filter((c) => c.method !== READ);
    },
    of(method: string): Call[] {
      return calls.filter((c) => c.method === method);
    },
    listOpenLabelled(label: string): IssueStub[] {
      calls.push({ method: READ, args: [label] });
      // A copy, so the module cannot mutate the fixture into agreement.
      return open.map((issue) => ({ ...issue }));
    },
    createIssue(record: any) {
      calls.push({ method: 'createIssue', args: [record] });
      return { number: nextNumber++ };
    },
    commentIssue(number: number, body: string) {
      calls.push({ method: 'commentIssue', args: [number, body] });
    },
    setIssueTitle(number: number, title: string) {
      calls.push({ method: 'setIssueTitle', args: [number, title] });
    },
    closeIssue(number: number) {
      calls.push({ method: 'closeIssue', args: [number] });
    },
  };
}

/** A log sink, so a message this suite asserts on never has to be scraped. */
function fakeLog() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out: (line: string) => void out.push(line),
    err: (line: string) => void err.push(line),
    stdout: () => out.join('\n'),
    stderr: () => err.join('\n'),
  };
}

// --- The workflow ----------------------------------------------------------

function workflow(): any {
  return yaml.load(fs.readFileSync(path.join(repoRoot(), WORKFLOW_REL), 'utf-8'));
}

function publishedJob(): any {
  const job = workflow().jobs?.['consumer-audit-published'];
  if (!job) throw new Error(`${WORKFLOW_REL}: no job "consumer-audit-published"`);
  return job;
}

function stepsOf(job: any): any[] {
  return Array.isArray(job?.steps) ? job.steps : [];
}

function stepRunning(job: any, pattern: RegExp): any {
  return stepsOf(job).find((s) => typeof s?.run === 'string' && pattern.test(s.run));
}

/** Every `$RUNNER_TEMP/<file>` a run body names, deduplicated. */
function runnerTempPaths(run: string): string[] {
  return [...new Set([...run.matchAll(/\$RUNNER_TEMP\/[A-Za-z0-9._-]+/g)].map((m) => m[0]))];
}

function workflowFiles(): string[] {
  const dir = path.join(repoRoot(), '.github', 'workflows');
  return fs.readdirSync(dir).filter((f) => /\.ya?ml$/.test(f));
}

describe('scripts/advisory-incident.mjs — one labelled issue per failing published audit', () => {
  it('QGF-118.AC1 builds one record from the combined capture: title, labels, assignees, body', async () => {
    const { buildIncidentRecord } = await incident();
    const record = buildIncidentRecord({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL });

    expect(record.title).toBe(`Published-artifact consumer audit failing: opena2a-cli@${RESOLVED_VERSION}`);
    expect(record.labels).toEqual([LABEL]);
    expect(record.assignees).toEqual([ASSIGNEE]);

    // The run URL verbatim: a reader who cannot reach the log from the issue has
    // to go looking for the run that produced it, which is the state this whole
    // unit exists to end.
    expect(record.body).toContain(RUN_URL);
    expect(record.body).toContain(`opena2a-cli@${RESOLVED_VERSION}`);
    expect(record.body).toContain(PACKAGE_COUNT);
    expect(record.body).toContain(ADVISORY_HIGH);
    expect(record.body).toContain(ADVISORY_CRITICAL);
  });

  it('QGF-118.AC1 names every advisory in the capture, and only the ids', async () => {
    const { parseAuditCapture } = await incident();
    const parsed = parseAuditCapture(PUBLISHED_CAPTURE);

    // The id is the last segment of the advisory URL — the token between
    // `advisory in the consumer tree: ` and ` (via `. Not the severity, not the
    // packages it lands on, not the trailing sentence.
    expect(parsed.advisoryIds).toEqual([ADVISORY_HIGH, ADVISORY_CRITICAL]);
    expect(parsed.name).toBe('opena2a-cli');
    expect(parsed.version).toBe(RESOLVED_VERSION);
    expect(parsed.packageCount).toBe(PACKAGE_COUNT);
  });

  it('QGF-118.AC1 a capture of the stdout half alone names no advisory — the combined file is load-bearing', async () => {
    const { buildIncidentRecord } = await incident();

    const stdoutOnly = buildIncidentRecord({ capture: PUBLISHED_STDOUT, runUrl: RUN_URL });
    expect(
      stdoutOnly.body,
      'the advisory ids are on STDERR; a record built from stdout alone would name a version ' +
        'and no advisory, which is the reader-facing half of this incident',
    ).not.toContain(ADVISORY_HIGH);

    const combined = buildIncidentRecord({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL });
    expect(combined.body).toContain(ADVISORY_HIGH);
    expect(combined.title).toBe(stdoutOnly.title);
  });

  it('QGF-118.AC1 the shapes it parses are the shapes the audit script writes', async () => {
    // Measured, not restated: these are the templates in
    // scripts/audit-consumer-resolution.mjs that the captures above mirror. If
    // the audit's wording moves, this fails here rather than filing an incident
    // titled `opena2a-cli@unknown` on the next red Monday.
    const source = fs.readFileSync(path.join(repoRoot(), AUDIT_SCRIPT_REL), 'utf-8');
    expect(source).toContain('Resolved ${liveness.rootName}@${liveness.rootVersion} — ');
    expect(source).toContain('${liveness.packageCount} packages in the production closure');
    expect(source).toContain('Unlisted ${adv.severity} advisory in the consumer tree: ${adv.id} ');
    expect(source).toContain('(via ${[...adv.packages].join(\', \')}).');
    expect(source).toContain('The consumer tree was not measured, so this run produced no result:');

    // And the parser reads them back off a line built from those templates.
    const { parseAuditCapture } = await incident();
    expect(parseAuditCapture(PUBLISHED_CAPTURE).version).toBe(RESOLVED_VERSION);
  });

  it('QGF-118.AC2 a capture with no resolved line invents no version and carries the failure text', async () => {
    const { buildIncidentRecord } = await incident();
    const record = buildIncidentRecord({ capture: UNMEASURED_CAPTURE, runUrl: RUN_URL });

    expect(record.title).toBe('Published-artifact consumer audit failing: opena2a-cli@unknown');
    expect(record.body).toContain('The consumer tree was not measured, so this run produced no result:');
    expect(record.body).toContain(UNMEASURED_REASON);
    expect(record.body).toContain(RUN_URL);
  });

  it('QGF-118.AC2 a CANDIDATE capture performs zero issue writes of any kind', async () => {
    const { openIncident } = await incident();
    const client = fakeClient([]);
    const log = fakeLog();

    const code = await openIncident({ capture: CANDIDATE_CAPTURE, runUrl: RUN_URL, client, log });

    expect(code).not.toBe(0);
    expect(log.stderr()).toContain('CANDIDATE');
    expect(
      client.writes(),
      'a pull request run measures the candidate tarball; an incident filed from it would name ' +
        'a version no user can install',
    ).toEqual([]);
  });

  it('QGF-118.AC2 the command itself exits non-zero on a CANDIDATE capture, naming CANDIDATE', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-incident-'));
    try {
      const file = path.join(dir, 'audit.log');
      fs.writeFileSync(file, CANDIDATE_CAPTURE);
      const r = spawnSync(
        process.execPath,
        [incidentScriptPath(), 'open', '--audit-log', file, '--run-url', RUN_URL],
        { encoding: 'utf-8' },
      );
      expect(r.error).toBeUndefined();
      expect(r.status).not.toBe(0);
      expect(`${r.stderr}${r.stdout}`).toContain('CANDIDATE');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('QGF-118.AC3 with no open labelled issue: exactly one create, and no other write', async () => {
    const { openIncident, buildIncidentRecord } = await incident();
    const client = fakeClient([]);

    const code = await openIncident({
      capture: PUBLISHED_CAPTURE,
      runUrl: RUN_URL,
      client,
      log: fakeLog(),
    });

    expect(code).toBe(0);
    expect(client.writes()).toHaveLength(1);
    expect(client.of('createIssue')).toHaveLength(1);

    const record = buildIncidentRecord({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL });
    const created = client.of('createIssue')[0].args[0];
    expect(created.title).toBe(record.title);
    expect(created.labels).toEqual([LABEL]);
    expect(created.assignees).toEqual([ASSIGNEE]);
    expect(created.body).toBe(record.body);

    // Read the open set through the label, and nothing else.
    expect(client.of(READ)).toHaveLength(1);
    expect(client.of(READ)[0].args[0]).toBe(LABEL);
  });

  it('QGF-118.AC3 with exactly one open: one comment on that number, title set, zero creates', async () => {
    const { openIncident, buildIncidentRecord } = await incident();
    const client = fakeClient([{ number: 41, title: 'Published-artifact consumer audit failing: opena2a-cli@0.10.11' }]);

    const code = await openIncident({
      capture: PUBLISHED_CAPTURE,
      runUrl: RUN_URL,
      client,
      log: fakeLog(),
    });

    expect(code).toBe(0);
    expect(client.of('createIssue')).toEqual([]);
    expect(client.of('commentIssue')).toHaveLength(1);

    const [number, body] = client.of('commentIssue')[0].args;
    expect(number).toBe(41);
    expect(body).toContain(RUN_URL);
    expect(body).toContain(`opena2a-cli@${RESOLVED_VERSION}`);
    expect(body).toContain(ADVISORY_HIGH);
    expect(body).toContain(ADVISORY_CRITICAL);

    // The stale version in the title is the thing a reader sees first, so it is
    // moved to the run this update carries.
    expect(client.of('setIssueTitle')).toHaveLength(1);
    expect(client.of('setIssueTitle')[0].args).toEqual([
      41,
      buildIncidentRecord({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL }).title,
    ]);
  });

  it('QGF-118.AC3 with two or more open: comments the lowest number, zero creates, non-zero exit', async () => {
    const { openIncident } = await incident();
    const client = fakeClient([
      { number: 57, title: 'Published-artifact consumer audit failing: opena2a-cli@0.10.12' },
      { number: 41, title: 'Published-artifact consumer audit failing: opena2a-cli@0.10.11' },
    ]);
    const log = fakeLog();

    const code = await openIncident({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL, client, log });

    expect(code).not.toBe(0);
    expect(client.of('createIssue')).toEqual([]);
    expect(client.of('commentIssue')).toHaveLength(1);
    expect(client.of('commentIssue')[0].args[0]).toBe(41);
    expect(
      log.stderr(),
      'a duplicate pair has to name the invariant it breaks, or the next reader files a third',
    ).toContain('at-most-one-open-labelled-issue');
  });

  it('QGF-118.AC4 resolve closes every open labelled issue with a comment naming the run', async () => {
    const { resolveIncident } = await incident();
    const client = fakeClient([
      { number: 57, title: 'Published-artifact consumer audit failing: opena2a-cli@0.10.12' },
      { number: 41, title: 'Published-artifact consumer audit failing: opena2a-cli@0.10.11' },
    ]);

    const code = await resolveIncident({ runUrl: RUN_URL, client, log: fakeLog() });

    expect(code).toBe(0);
    expect(client.of('closeIssue').map((c) => c.args[0]).sort()).toEqual([41, 57]);
    expect(client.of('commentIssue')).toHaveLength(2);
    for (const call of client.of('commentIssue')) {
      expect(call.args[1]).toContain(RUN_URL);
      expect(call.args[1]).toContain('audits clean');
    }
    expect(client.of('createIssue')).toEqual([]);
  });

  it('QGF-118.AC4 resolve performs zero writes and exits 0 when no labelled issue is open', async () => {
    const { resolveIncident } = await incident();
    const client = fakeClient([]);

    const code = await resolveIncident({ runUrl: RUN_URL, client, log: fakeLog() });

    expect(code).toBe(0);
    expect(client.writes()).toEqual([]);
  });

  it('QGF-118.AC5 the published job is schedule-only and holds exactly contents: read + issues: write', () => {
    const job = publishedJob();
    expect(job.name).toBe('Consumer resolution audit (published artifact)');
    expect(job.if).toBe("github.event_name == 'schedule'");
    expect(
      job.permissions,
      'issues: write is the elevation this job needs and the one no other job may hold',
    ).toEqual({ contents: 'read', issues: 'write' });
  });

  it('QGF-118.AC5 the audit step tees the combined streams to one $RUNNER_TEMP file and still fails the job', () => {
    const job = publishedJob();
    const step = stepRunning(job, /npm run audit:consumer/);
    expect(step, `${WORKFLOW_REL}: the published job runs no consumer audit`).toBeDefined();

    // One file, both streams, in one pipeline.
    expect(step.run).toMatch(/npm run audit:consumer[^\n]*2>&1[^\n]*\|\s*tee\s+"?\$RUNNER_TEMP\//);
    expect(runnerTempPaths(step.run)).toHaveLength(1);

    // `tee` exits 0 whatever the audit did, so without pipefail the gate stops
    // being a gate — and the failure step it feeds would never run.
    expect(step.run).toContain('set -euo pipefail');
    expect(step['continue-on-error']).toBeUndefined();
    expect(job['continue-on-error']).toBeUndefined();
    expect(step.run).not.toContain('|| true');
  });

  it('QGF-118.AC5 the failure step opens the incident from that same file, gated and tokened', () => {
    const job = publishedJob();
    const auditStep = stepRunning(job, /npm run audit:consumer/);
    const openStep = stepRunning(job, /advisory-incident\.mjs open\b/);
    expect(openStep, `${WORKFLOW_REL}: the published job has no incident-opening step`).toBeDefined();

    expect(openStep.if).toBe("failure() && github.event_name == 'schedule'");
    expect(openStep.env?.GH_TOKEN).toBe('${{ secrets.GITHUB_TOKEN }}');
    expect(openStep.run).toContain('node scripts/advisory-incident.mjs open');

    const logPath = runnerTempPaths(auditStep.run)[0];
    expect(
      openStep.run,
      'the step reads a different file than the audit wrote, so the incident would carry no output',
    ).toContain(logPath);
    expect(openStep.run).toContain('--audit-log');
    expect(openStep.run).toContain(
      '--run-url ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}',
    );
  });

  it('QGF-118.AC5 the success step resolves the incident under the same token and run URL', () => {
    const job = publishedJob();
    const step = stepRunning(job, /advisory-incident\.mjs resolve\b/);
    expect(step, `${WORKFLOW_REL}: nothing closes the issue when the closure audits clean`).toBeDefined();

    expect(step.if).toBe("success() && github.event_name == 'schedule'");
    expect(step.env?.GH_TOKEN).toBe('${{ secrets.GITHUB_TOKEN }}');
    expect(step.run).toContain('node scripts/advisory-incident.mjs resolve');
    expect(step.run).toContain(
      '--run-url ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}',
    );
  });

  it('QGF-118.AC6 the candidate job stays non-schedule, read-only, and names no incident script', () => {
    const job = workflow().jobs?.['consumer-audit-candidate'];
    expect(job).toBeDefined();
    expect(job.if).toBe("github.event_name != 'schedule'");
    expect(job.permissions).toEqual({ contents: 'read' });
    for (const step of stepsOf(job)) {
      expect(JSON.stringify(step)).not.toContain(INCIDENT_SCRIPT_REL);
    }
  });

  it('QGF-118.AC6 every step naming the incident script is gated on the schedule event', () => {
    const jobs = workflow().jobs ?? {};
    let gated = 0;
    for (const [id, job] of Object.entries(jobs) as Array<[string, any]>) {
      for (const step of stepsOf(job)) {
        if (typeof step?.run !== 'string' || !step.run.includes(INCIDENT_SCRIPT_REL)) continue;
        gated++;
        expect(
          String(step.if),
          `${WORKFLOW_REL}: job ${id} can reach the incident script on a non-schedule event`,
        ).toContain("github.event_name == 'schedule'");
      }
    }
    expect(gated, `${WORKFLOW_REL}: no step invokes ${INCIDENT_SCRIPT_REL}`).toBeGreaterThan(0);
  });

  it('QGF-118.AC6 no other workflow declares issues: write or names the incident script', () => {
    const dir = path.join(repoRoot(), '.github', 'workflows');
    for (const file of workflowFiles()) {
      if (file === path.basename(WORKFLOW_REL)) continue;
      const text = fs.readFileSync(path.join(dir, file), 'utf-8');
      expect(text, `${file} declares issues: write`).not.toMatch(/issues:\s*write/);
      expect(text, `${file} names ${INCIDENT_SCRIPT_REL}`).not.toContain(INCIDENT_SCRIPT_REL);
    }
  });
});
