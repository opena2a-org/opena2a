#!/usr/bin/env node
/**
 * The published-artifact advisory incident: one labelled GitHub issue per
 * failing scheduled consumer-resolution audit, closed when the closure audits
 * clean again.
 *
 * WHY THIS EXISTS
 *
 * `consumer-audit-published` in .github/workflows/security.yml measures the tree
 * a user resolves from npm right now. It is the one gate in this repository that
 * no pull request can turn green: a failure there means the ALREADY-SHIPPED
 * closure has drifted into an advisory, and it clears when a fix is RELEASED.
 * That job runs weekly, and until this script existed the only place its result
 * lived was the run log — a surface with no subscribers. A live high advisory
 * reaching users could therefore sit unread from one Monday to the next.
 *
 * So a red scheduled run becomes an issue: labelled `published-artifact-advisory`,
 * assigned to the code owner, titled with the version a user actually installs,
 * and carrying the advisory ids out of the run that captured them.
 *
 * WHAT IT READS, AND WHY IT IS THE COMBINED CAPTURE
 *
 * Everything in the record comes out of one file: the COMBINED stdout and stderr
 * of `npm run audit:consumer`, which the workflow tees into $RUNNER_TEMP. The two
 * halves are not interchangeable, and this is the defect that made the split
 * matter: the resolved version is printed by `console.log`
 * (scripts/audit-consumer-resolution.mjs:712-714) and the advisory ids are pushed
 * onto `failures` at :736 and printed by `console.error` at :811-813. A capture
 * of stdout alone yields an incident naming a version and no advisory — the
 * reader-facing half. The audit writes neither GITHUB_OUTPUT nor
 * GITHUB_STEP_SUMMARY, so its own output is the only place these facts exist.
 *
 * WHAT IT REFUSES
 *
 * A capture whose first banner is `[CANDIDATE] ` is the OTHER artifact — the
 * tarball a pull request would publish. It is measured on every PR, it is
 * fixable in the branch, and an incident filed from it would name a version no
 * user can install. This script performs no issue write of any kind on one.
 *
 * A capture with no `[PUBLISHED] Resolved ` line invents no version: the audit
 * threw before it measured anything, the title says `opena2a-cli@unknown`, and
 * the body carries the failure text. Guessing `latest` there would put a version
 * in the title that nothing measured.
 *
 * THE DEDUP INVARIANT
 *
 * At most one OPEN issue carries the label. A weekly job that creates an issue
 * per red run produces one issue per week for a drift nobody can fix by merging,
 * and the label stops meaning anything. So: create when none is open, comment
 * and re-title when exactly one is open, and when two or more are open comment
 * the lowest-numbered one and FAIL rather than adding a third.
 *
 * TESTS
 *
 * packages/cli/__tests__/security/advisory-incident.test.ts drives every branch
 * above with captured audit output and an injected issues client. Nothing here
 * reaches the network unless `ghIssuesClient` is the client in use, which only
 * `main` constructs.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

/** The label the incident is filed under. One control, one name. */
export const LABEL = 'published-artifact-advisory';

/** The repository's sole code owner (.github/CODEOWNERS). */
export const ASSIGNEE = 'thebenignhacker';

/**
 * The title's package name is a literal, not the parsed one. The scheduled job
 * audits `opena2a-cli@latest` (DEFAULT_TARGET), and a title assembled from a
 * name the capture happened to carry would silently re-point the incident if the
 * audit were ever aimed elsewhere. The parsed name goes in the body, where it can
 * disagree visibly.
 */
export const TITLE_PACKAGE = 'opena2a-cli';
const TITLE_PREFIX = 'Published-artifact consumer audit failing: ';
const UNKNOWN = 'unknown';

/** `[PUBLISHED] Resolved <name>@<version> — <n> packages in the production closure` */
const RESOLVED =
  /^\[PUBLISHED\] Resolved ([^@\s]+)@(\S+) — (\d+) packages in the production closure$/m;

/** `Unlisted <severity> advisory in the consumer tree: <id> (via <packages>).` */
const ADVISORY = /Unlisted \S+ advisory in the consumer tree: (\S+) \(via /g;

/** The first `[PUBLISHED] ` / `[CANDIDATE] ` banner decides which tree this was. */
const BANNER = /^\[(PUBLISHED|CANDIDATE)\] /m;

const FAILED_BANNER = /^\[(?:PUBLISHED|CANDIDATE)\] Consumer-resolution audit FAILED/m;

const UNMEASURED = 'The consumer tree was not measured, so this run produced no result:';

/**
 * How much of the capture the body quotes. A GitHub issue body caps at 65536
 * characters and a red audit prints one paragraph per finding, so the quote is
 * bounded — from the FAILED banner, which is where the findings start, so the
 * bound never cuts the reason off the front.
 */
const EXCERPT_LIMIT = 20000;

class IncidentError extends Error {}

function normalize(capture) {
  return String(capture ?? '').replace(/\r\n/g, '\n');
}

/**
 * Everything the record is built from, read out of one capture.
 *
 * `packageCount` stays the captured string: it is quoted back, never arithmetic.
 */
export function parseAuditCapture(capture) {
  const text = normalize(capture);
  const banner = BANNER.exec(text);
  const resolved = RESOLVED.exec(text);

  const advisoryIds = [];
  for (const match of text.matchAll(ADVISORY)) {
    if (!advisoryIds.includes(match[1])) advisoryIds.push(match[1]);
  }

  const unmeasuredAt = text.indexOf(UNMEASURED);
  let unmeasured = null;
  if (unmeasuredAt !== -1) {
    const rest = text.slice(unmeasuredAt);
    const end = rest.indexOf('\n\n');
    unmeasured = (end === -1 ? rest : rest.slice(0, end)).trimEnd();
  }

  return {
    mode: banner ? banner[1] : null,
    name: resolved ? resolved[1] : null,
    version: resolved ? resolved[2] : null,
    packageCount: resolved ? resolved[3] : null,
    advisoryIds,
    unmeasured,
    excerpt: excerptOf(text),
  };
}

/** The capture from its FAILED banner on: the findings and nothing before them. */
function excerptOf(text) {
  const banner = FAILED_BANNER.exec(text);
  const body = text.slice(banner ? banner.index : 0).trimEnd();
  if (body.length <= EXCERPT_LIMIT) return body;
  return `${body.slice(0, EXCERPT_LIMIT)}\n[truncated — the full log is in the run linked above]`;
}

export function incidentTitle(parsed) {
  return `${TITLE_PREFIX}${TITLE_PACKAGE}@${parsed.version ?? UNKNOWN}`;
}

/** The measured facts, in the order a reader needs them. */
function summary(parsed, runUrl) {
  const resolved = parsed.version
    ? `${parsed.name}@${parsed.version}`
    : `${TITLE_PACKAGE}@${UNKNOWN} (this capture carries no "[PUBLISHED] Resolved " line)`;
  return [
    `- Run: ${runUrl}`,
    `- Resolved: ${resolved}`,
    `- Packages in the production closure: ${parsed.packageCount ?? UNKNOWN}`,
    `- Advisories in the consumer tree: ${
      parsed.advisoryIds.length > 0 ? parsed.advisoryIds.join(', ') : 'none named in this capture'
    }`,
  ].join('\n');
}

function quotedCapture(parsed) {
  return ['Audit output (combined stdout and stderr of `npm run audit:consumer`):', '', '```', parsed.excerpt, '```'].join(
    '\n'
  );
}

function requirePublished(parsed) {
  if (parsed.mode === 'CANDIDATE') {
    throw new IncidentError(
      'This capture is a CANDIDATE run — the tarball a branch would publish, not the tree a ' +
        'user resolves from npm. Only the scheduled PUBLISHED audit opens an incident: a ' +
        'CANDIDATE failure is about the change under review and is fixable in its branch.'
    );
  }
}

function requireRunUrl(runUrl) {
  if (typeof runUrl !== 'string' || runUrl.trim() === '') {
    throw new IncidentError('--run-url is required: an incident that does not name its run cannot be checked.');
  }
}

/** The issue this capture asks for: title, labels, assignees, body. */
export function buildIncidentRecord({ capture, runUrl }) {
  requireRunUrl(runUrl);
  const parsed = parseAuditCapture(capture);
  requirePublished(parsed);

  const body = [
    'The scheduled PUBLISHED consumer-resolution audit failed. This measures the tree a user',
    'resolves from npm right now, so it is NOT fixable by merging — it clears when a fix is',
    'released.',
    '',
    summary(parsed, runUrl),
    '',
    'This issue is closed automatically by the next scheduled run whose published closure audits clean.',
    '',
    quotedCapture(parsed),
  ].join('\n');

  return { title: incidentTitle(parsed), labels: [LABEL], assignees: [ASSIGNEE], body };
}

/** What a still-open incident is told about a later red run. */
export function buildFollowUpComment({ capture, runUrl }) {
  requireRunUrl(runUrl);
  const parsed = parseAuditCapture(capture);
  requirePublished(parsed);
  return [
    'The scheduled PUBLISHED consumer-resolution audit failed again.',
    '',
    summary(parsed, runUrl),
    '',
    quotedCapture(parsed),
  ].join('\n');
}

/** What closes an incident: the run that measured the tree clean. */
export function buildResolutionComment(runUrl) {
  requireRunUrl(runUrl);
  return [
    'The published closure audits clean: the scheduled PUBLISHED consumer-resolution audit',
    'passed, so the tree a user resolves from npm carries no unlisted high or critical advisory.',
    '',
    `- Run: ${runUrl}`,
    '',
    'Closing. A later scheduled failure opens a new issue under the same label.',
  ].join('\n');
}

const CONSOLE = { out: (line) => console.log(line), err: (line) => console.error(line) };

function openIssuesByNumber(issues) {
  return [...(issues ?? [])].sort((a, b) => a.number - b.number);
}

/**
 * Open or update the one labelled incident. Returns the process exit code.
 *
 * The client is injected so that every decision here is testable without a
 * forge, and so that the only code that can write to GitHub is the client `main`
 * constructs.
 */
export async function openIncident({ capture, runUrl, client, log = CONSOLE }) {
  const parsed = parseAuditCapture(capture);
  if (parsed.mode === 'CANDIDATE') {
    // Before any client call, including the read: a CANDIDATE capture is not a
    // question this script answers.
    log.err(
      '::error::Refusing to file an incident from a CANDIDATE capture. That is the tarball a ' +
        'branch would publish, measured on every pull request and fixable in the branch; this ' +
        'incident is only for the PUBLISHED tree a user resolves from npm.'
    );
    return 2;
  }

  const record = buildIncidentRecord({ capture, runUrl });
  const open = openIssuesByNumber(await client.listOpenLabelled(LABEL));

  if (open.length === 0) {
    const created = await client.createIssue(record);
    log.out(`Opened ${created?.number ? `#${created.number}` : 'an issue'} — ${record.title}`);
    return 0;
  }

  const target = open[0];
  await client.commentIssue(target.number, buildFollowUpComment({ capture, runUrl }));

  if (open.length === 1) {
    // The title carries the version a reader sees first, and the one on a
    // week-old issue is a version nobody installs any more.
    await client.setIssueTitle(target.number, record.title);
    log.out(`Updated #${target.number} — ${record.title}`);
    return 0;
  }

  log.err(
    `::error::The at-most-one-open-labelled-issue invariant is broken: ${open.length} open issues ` +
      `carry the label ${LABEL} (${open.map((i) => `#${i.number}`).join(', ')}). At most one open ` +
      `issue may carry it. Commented on the lowest-numbered one (#${target.number}) and created ` +
      'nothing; close the duplicates and this passes again.'
  );
  return 1;
}

/**
 * Close every open labelled incident, because the closure audits clean.
 *
 * Every one, not just the lowest: if the invariant above was ever broken, a green
 * run is exactly the moment the extras should go, and leaving them open would
 * keep the label reading red for a tree that is not.
 */
export async function resolveIncident({ runUrl, client, log = CONSOLE }) {
  const open = openIssuesByNumber(await client.listOpenLabelled(LABEL));
  if (open.length === 0) {
    log.out(`No open issue carries the label ${LABEL}; nothing to close.`);
    return 0;
  }

  const comment = buildResolutionComment(runUrl);
  for (const issue of open) {
    await client.commentIssue(issue.number, comment);
    await client.closeIssue(issue.number);
    log.out(`Closed #${issue.number} — the published closure audits clean.`);
  }
  return 0;
}

// ---------------------------------------------------------------------------
// The real client. Constructed by `main` and by nothing else.
// ---------------------------------------------------------------------------

function ghExec(args, input) {
  return execFileSync('gh', args, { encoding: 'utf-8', input, maxBuffer: 16 * 1024 * 1024 });
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new IncidentError(`${name} is not set; this command runs inside a GitHub Actions job.`);
  return value;
}

/**
 * `gh`, which is on every GitHub runner and reads GH_TOKEN — the same shape
 * .github/workflows/pr-review.yml already uses. Bodies go over stdin
 * (`--body-file -`) so no issue text ever has to survive shell quoting.
 *
 * Nothing is resolved at construction time: a client that throws when it is
 * built could not be created on the CANDIDATE path, where the refusal must come
 * before anything else.
 */
export function ghIssuesClient({ exec = ghExec, repo = () => requiredEnv('GITHUB_REPOSITORY') } = {}) {
  const target = () => ['--repo', repo()];
  return {
    listOpenLabelled(label) {
      const out = exec([
        'issue',
        'list',
        ...target(),
        '--state',
        'open',
        '--label',
        label,
        '--json',
        'number,title',
        '--limit',
        '100',
      ]);
      const parsed = JSON.parse(String(out || '[]').trim() || '[]');
      return parsed.map((issue) => ({ number: issue.number, title: issue.title }));
    },
    createIssue({ title, body, labels, assignees }) {
      const args = ['issue', 'create', ...target(), '--title', title, '--body-file', '-'];
      for (const label of labels) args.push('--label', label);
      for (const assignee of assignees) args.push('--assignee', assignee);
      const out = String(exec(args, body) ?? '');
      const number = /\/issues\/(\d+)/.exec(out)?.[1];
      return { number: number ? Number(number) : undefined, url: out.trim() };
    },
    commentIssue(number, body) {
      exec(['issue', 'comment', String(number), ...target(), '--body-file', '-'], body);
    },
    setIssueTitle(number, title) {
      exec(['issue', 'edit', String(number), ...target(), '--title', title]);
    },
    closeIssue(number) {
      exec(['issue', 'close', String(number), ...target()]);
    },
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE = [
  'usage:',
  '  advisory-incident.mjs open --audit-log <file> --run-url <url>',
  '  advisory-incident.mjs resolve --run-url <url>',
].join('\n');

function readFlags(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) throw new IncidentError(`unexpected argument: ${arg}\n${USAGE}`);
    const eq = arg.indexOf('=');
    if (eq !== -1) {
      flags[arg.slice(2, eq)] = arg.slice(eq + 1);
      continue;
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) throw new IncidentError(`${arg} needs a value\n${USAGE}`);
    flags[arg.slice(2)] = value;
    i++;
  }
  return flags;
}

async function main(argv) {
  const [command, ...rest] = argv;
  const flags = readFlags(rest);

  if (command === 'open') {
    if (!flags['audit-log']) throw new IncidentError(`open needs --audit-log\n${USAGE}`);
    let capture;
    try {
      capture = readFileSync(flags['audit-log'], 'utf-8');
    } catch (e) {
      throw new IncidentError(
        `cannot read the audit log at ${flags['audit-log']}: ${e?.message ?? e}. The audit step ` +
          'writes it; a missing file means the capture, not the audit, is what broke.'
      );
    }
    return openIncident({ capture, runUrl: flags['run-url'], client: ghIssuesClient() });
  }

  if (command === 'resolve') {
    return resolveIncident({ runUrl: flags['run-url'], client: ghIssuesClient() });
  }

  throw new IncidentError(`unknown command: ${command ?? '(none)'}\n${USAGE}`);
}

const invokedDirectly =
  process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url;

if (invokedDirectly) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (e) => {
      console.error(`::error::${e?.message ?? e}`);
      process.exitCode = 2;
    }
  );
}
