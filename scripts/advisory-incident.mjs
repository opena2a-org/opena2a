#!/usr/bin/env node
/**
 * The published-artifact advisory incident: one labelled GitHub issue for a
 * failing scheduled consumer-resolution audit, closed when the audit passes
 * again.
 *
 * WHY THIS EXISTS
 *
 * `npm run audit:consumer` with its default target measures the tree a user
 * resolves from npm right now. It is the one gate in this repository that no
 * pull request can turn green: a failure means the ALREADY-SHIPPED closure has
 * drifted into an advisory, and it clears when a fix is RELEASED. It runs on a
 * weekly schedule, and a failed scheduled run is recorded in a run log, a
 * surface with no subscribers. A high advisory reaching users can sit there
 * unread from one Monday to the next.
 *
 * So a failed scheduled run becomes an issue: labelled
 * `published-artifact-advisory`, assigned, titled with the version a user
 * installs, and carrying the advisory ids out of the run that measured them.
 *
 * WHO RUNS IT
 *
 * A job that holds `issues: write` and runs this file and nothing else. The job
 * that runs the audit installs a registry tree, so it holds no write permission
 * and hands its output over as a file. That file is the only input here, and it
 * is treated as untrusted text throughout.
 *
 *   advisory-incident.mjs open --audit-log <file> --run-url <url>
 *   advisory-incident.mjs resolve --run-url <url>
 *
 * `gh` does the writing. It reads GH_TOKEN and GITHUB_REPOSITORY from the
 * environment, as it does in a GitHub Actions job.
 *
 * WHAT IT READS, AND WHY IT IS THE COMBINED CAPTURE
 *
 * Everything in the record comes out of one file: the COMBINED stdout and stderr
 * of `npm run audit:consumer`. The two halves are not interchangeable. The audit
 * prints `[PUBLISHED] Resolved <name>@<version>` with `console.log` and every
 * `Unlisted <severity> advisory in the consumer tree: <id>` with
 * `console.error`, so a capture of stdout alone yields a record naming a version
 * and no advisory. The audit writes neither GITHUB_OUTPUT nor
 * GITHUB_STEP_SUMMARY, so its own output is the only place these facts exist.
 *
 * WHAT LEAVES THE QUOTED BLOCK
 *
 * npm's stderr and a publisher's deprecation notice are part of the capture, and
 * an issue body is rendered as markup on a public repository. So the capture is
 * quoted inside a code fence that is longer than any run of backticks in it, and
 * the only values repeated outside that fence are ones that match a plain shape:
 * a package name, a version, a package count and an advisory id. A value that
 * does not match is counted and left inside the fence. Control characters are
 * removed and the quote is bounded, so nothing the audit printed can keep the
 * issue from being filed.
 *
 * WHAT IT REFUSES
 *
 * A capture whose first banner is `[CANDIDATE] ` is the OTHER artifact, the
 * tarball a pull request would publish. It is measured on every pull request,
 * it is fixable in the branch, and a record filed from it would name a version
 * no user can install. No `gh` call of any kind is made for one.
 *
 * A capture with no well-formed `[PUBLISHED] Resolved ` line invents no version:
 * the title says `opena2a-cli@unknown` and the body carries the failure text.
 *
 * An audit log that is a link, a directory, or larger than AUDIT_LOG_MAX_BYTES
 * is not read.
 *
 * THE INVARIANT
 *
 * At most one OPEN issue carries the label. A weekly job that creates an issue
 * per failing run produces one issue a week for a drift nobody can fix by
 * merging, and the label stops meaning anything. So: create when none is open,
 * comment and re-title when exactly one is open, and when two or more are open
 * comment on the lowest-numbered one and FAIL without adding a third.
 *
 * EXIT CODES
 *
 *   0  the issue was opened, updated or closed, or there was nothing to close
 *   1  more than one open issue carries the label; a person has to close the extras
 *   2  refused or failed: a CANDIDATE capture, an unusable argument or audit log,
 *      or a `gh` call that did not succeed. No exit 0 without the write having
 *      been made.
 *
 * TESTS
 *
 * scripts/__tests__/advisory-incident.test.mjs drives every branch above with
 * captured audit output and an injected issues client. Nothing here starts `gh`
 * unless `ghIssuesClient` is used with its default `exec`, which only `main`
 * does.
 */
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/** The label the incident is filed under. One control, one name. */
export const LABEL = 'published-artifact-advisory';

/** The owner named in .github/CODEOWNERS. */
export const ASSIGNEE = 'thebenignhacker';

/**
 * The title's package name is a literal, not the parsed one: the scheduled job
 * audits `opena2a-cli@latest`, and a title assembled from whatever name a
 * capture carried would re-point the incident without anyone deciding to.
 */
export const TITLE_PACKAGE = 'opena2a-cli';

/** An audit run prints a few kilobytes. A megabyte of it is not an audit log. */
export const AUDIT_LOG_MAX_BYTES = 1024 * 1024;

/**
 * How much of the capture the body quotes. GitHub refuses an issue body over
 * 65536 characters, and the worst case here is this many backticks inside two
 * fences one longer, so the bound leaves room for three times itself.
 */
export const EXCERPT_LIMIT = 16000;

const TITLE_PREFIX = 'Published-artifact consumer audit failing: ';
const UNKNOWN = 'unknown';
const MAX_LISTED_ADVISORIES = 50;

/** `[PUBLISHED] Resolved <name>@<version> — <n> packages in the production closure` */
const RESOLVED =
  /^\[PUBLISHED\] Resolved ((?:@[a-z0-9][a-z0-9._-]{0,99}\/)?[a-z0-9][a-z0-9._-]{0,99})@(\d{1,9}\.\d{1,9}\.\d{1,9}(?:[-+][0-9A-Za-z.+-]{1,64})?) — (\d{1,9}) packages in the production closure$/m;

/** `Unlisted <severity> advisory in the consumer tree: <id> (via <packages>).` */
const ADVISORY = /Unlisted \S+ advisory in the consumer tree: (\S+) \(via /g;

/** What an advisory id may look like to be repeated outside the quoted block. */
const PLAIN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** The first `[PUBLISHED] ` / `[CANDIDATE] ` banner decides which tree this was. */
const BANNER = /^\[(PUBLISHED|CANDIDATE)\] /m;

const FAILED_BANNER = /^\[(?:PUBLISHED|CANDIDATE)\] Consumer-resolution audit FAILED/m;

/** `[PUBLISHED] Consumer-resolution audit passed (<name>).` */
const PASSED = /^\[PUBLISHED\] Consumer-resolution audit passed \(/m;

/** `<server>/<owner>/<repo>/actions/runs/<id>`, and nothing after it. */
const RUN_URL = /^https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/actions\/runs\/\d+$/;

class IncidentError extends Error {}
class UsageError extends IncidentError {}

/** One newline convention, no colour codes, no control characters. */
function clean(capture) {
  return String(capture ?? '')
    .replace(/\r\n?/g, '\n')
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '');
}

/**
 * Everything the record is built from, read out of one capture.
 *
 * `packageCount` stays the captured string: it is quoted back, never arithmetic.
 * `withheldAdvisoryLines` counts advisory lines whose id is not a plain token;
 * they stay in the excerpt and are never dropped without being counted.
 * `auditPassed` is true when the output reports a pass and no failure: the
 * audit was not what failed the run, and the record has to say so.
 */
export function parseAuditCapture(capture) {
  const text = clean(capture);
  const banner = BANNER.exec(text);
  const resolved = RESOLVED.exec(text);

  const advisoryIds = new Set();
  let withheldAdvisoryLines = 0;
  for (const [, id] of text.matchAll(ADVISORY)) {
    if (PLAIN_ID.test(id)) advisoryIds.add(id);
    else withheldAdvisoryLines++;
  }

  return {
    mode: banner ? banner[1] : null,
    name: resolved ? resolved[1] : null,
    version: resolved ? resolved[2] : null,
    packageCount: resolved ? resolved[3] : null,
    advisoryIds: [...advisoryIds],
    withheldAdvisoryLines,
    auditPassed: PASSED.test(text) && !FAILED_BANNER.test(text),
    excerpt: excerptOf(text),
  };
}

/**
 * The capture from its FAILED banner on: the findings, and nothing before them.
 * A capture with no such banner is a run that died before it could report, and
 * what explains that is at the end, so the end is what is kept.
 */
function excerptOf(text) {
  const banner = FAILED_BANNER.exec(text);
  if (banner) {
    const findings = text.slice(banner.index).trimEnd();
    if (findings.length <= EXCERPT_LIMIT) return findings;
    return `${findings.slice(0, EXCERPT_LIMIT)}\n[cut here; the full output is in the run]`;
  }
  const all = text.trim();
  if (all.length <= EXCERPT_LIMIT) return all;
  return `[the start is cut; the full output is in the run]\n${all.slice(-EXCERPT_LIMIT)}`;
}

export function incidentTitle(parsed) {
  // A version of some other package is not a version of this one.
  const version = parsed.name === TITLE_PACKAGE ? parsed.version : null;
  return `${TITLE_PREFIX}${TITLE_PACKAGE}@${version ?? UNKNOWN}`;
}

/** The measured facts, in the order a reader needs them. */
function facts(parsed, runUrl) {
  const lines = [`- Run: ${runUrl}`];

  if (parsed.auditPassed) {
    lines.push('- The output shows the audit passing, so this run failed in another step; the run has the reason');
  }

  if (parsed.version === null) {
    lines.push('- Resolved: not measured (the output carries no well-formed `[PUBLISHED] Resolved` line)');
  } else {
    // A code span: a scoped name begins with `@`, and outside one it would
    // notify whoever holds that name.
    const other = parsed.name === TITLE_PACKAGE ? '' : ` (not ${TITLE_PACKAGE}, so the title names no version)`;
    lines.push(`- Resolved: \`${parsed.name}@${parsed.version}\`${other}`);
    lines.push(`- Packages in the production closure: ${parsed.packageCount}`);
  }

  const listed = parsed.advisoryIds.slice(0, MAX_LISTED_ADVISORIES);
  const more = parsed.advisoryIds.length - listed.length;
  const withheld = parsed.withheldAdvisoryLines;
  if (listed.length > 0) {
    lines.push(
      `- Advisories not on the audit's allowlist: ${listed.join(', ')}` +
        (more > 0 ? ` and ${more} more in the output below` : '')
    );
  } else if (withheld === 0) {
    lines.push("- Advisories not on the audit's allowlist: none named in the output");
  }
  if (withheld > 0) {
    lines.push(
      `- ${withheld} advisory ${withheld === 1 ? 'line carries' : 'lines carry'} an id that is not a ` +
        'plain token; see the output below'
    );
  }
  return lines.join('\n');
}

function longestBacktickRun(text) {
  let longest = 0;
  for (const run of text.matchAll(/`+/g)) longest = Math.max(longest, run[0].length);
  return longest;
}

/**
 * The excerpt inside a code fence it cannot close. A fence is closed only by a
 * run of backticks at least as long as the one that opened it, so the fence is
 * one longer than the longest run in the excerpt.
 */
function quoted(parsed) {
  const excerpt = parsed.excerpt === '' ? '(the run captured no output)' : parsed.excerpt;
  const fence = '`'.repeat(Math.max(3, longestBacktickRun(excerpt) + 1));
  return ['Audit output (combined stdout and stderr of `npm run audit:consumer`):', '', fence, excerpt, fence].join('\n');
}

function requirePublished(parsed) {
  if (parsed.mode === 'CANDIDATE') {
    throw new IncidentError(
      'This capture is a CANDIDATE run: the tarball a branch would publish, not the tree a ' +
        'user resolves from npm. Only the scheduled PUBLISHED audit opens an incident; a ' +
        'CANDIDATE failure is about the change under review and is fixable in its branch.'
    );
  }
}

function requireRunUrl(runUrl) {
  if (typeof runUrl !== 'string' || !RUN_URL.test(runUrl)) {
    throw new IncidentError(
      '--run-url must be the https URL of one Actions run (<server>/<owner>/<repo>/actions/runs/<id>): ' +
        'a record that does not name its run cannot be checked.'
    );
  }
  return runUrl;
}

/** The issue this capture asks for: title, labels, assignees, body. */
export function buildIncidentRecord({ capture, runUrl }) {
  const url = requireRunUrl(runUrl);
  const parsed = parseAuditCapture(capture);
  requirePublished(parsed);

  // One line per paragraph: an issue body renders a single newline as a break.
  const body = [
    'The scheduled consumer-resolution audit of the published package failed. ' +
      `It measures the dependency tree a user resolves when installing \`${TITLE_PACKAGE}\` from npm today, ` +
      'so merging a change does not clear it: it clears when a release carrying the fix is published.',
    '',
    facts(parsed, url),
    '',
    'To reproduce, run `npm run audit:consumer` in a checkout of this repository. ' +
      `It audits what npm resolves for \`${TITLE_PACKAGE}@latest\` at that moment. ` +
      "The output quoted below is the audit's own account of each finding.",
    '',
    'The next scheduled run comments here while the audit still fails, and closes this issue when it passes.',
    '',
    quoted(parsed),
  ].join('\n');

  return { title: incidentTitle(parsed), labels: [LABEL], assignees: [ASSIGNEE], body };
}

/** What a still-open incident is told about a later failing run. */
export function buildFollowUpComment({ capture, runUrl }) {
  const url = requireRunUrl(runUrl);
  const parsed = parseAuditCapture(capture);
  requirePublished(parsed);
  return [
    'The scheduled consumer-resolution audit of the published package failed again.',
    '',
    facts(parsed, url),
    '',
    quoted(parsed),
  ].join('\n');
}

/** What closes an incident: the run that measured the tree and passed. */
export function buildResolutionComment(runUrl) {
  const url = requireRunUrl(runUrl);
  return [
    'The scheduled consumer-resolution audit of the published package passed.',
    '',
    `- Run: ${url}`,
    '',
    'Closing this issue. A later failing run opens a new one under the same label.',
  ].join('\n');
}

const CONSOLE = { out: (line) => console.log(line), err: (line) => console.error(line) };

function byNumber(issues) {
  return [...(issues ?? [])].sort((a, b) => a.number - b.number);
}

/**
 * Open or update the one labelled incident. Returns the process exit code.
 *
 * The client is injected so that every decision here is testable without a
 * forge, and so that the only code able to write to GitHub is the client `main`
 * constructs. A client call that throws is not caught: a write that did not
 * happen is a failure of this command, never a quiet 0.
 */
export async function openIncident({ capture, runUrl, client, log = CONSOLE }) {
  if (parseAuditCapture(capture).mode === 'CANDIDATE') {
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
  const open = byNumber(await client.listOpenLabelled(LABEL));

  if (open.length === 0) {
    const created = await client.createIssue(record);
    log.out(`Opened #${created.number}: ${record.title}`);
    return 0;
  }

  const target = open[0];
  await client.commentIssue(target.number, buildFollowUpComment({ capture, runUrl }));

  if (open.length === 1) {
    // The title carries the version a reader sees first, and the one on a
    // week-old issue is a version nobody installs any more.
    await client.setIssueTitle(target.number, record.title);
    log.out(`Updated #${target.number}: ${record.title}`);
    return 0;
  }

  log.err(
    `::error::${open.length} open issues carry the label ${LABEL} ` +
      `(${open.map((issue) => `#${issue.number}`).join(', ')}), and at most one open issue may. ` +
      `Commented on #${target.number} and created nothing. Close the extra issues and the next ` +
      'run passes this check.'
  );
  return 1;
}

/**
 * Close every open labelled incident, because the audit passed.
 *
 * Every one, not just the lowest: if the invariant above was ever broken, a
 * passing run is the moment the extras should go, and leaving them open keeps
 * the label reading as a failure for a tree that has none.
 */
export async function resolveIncident({ runUrl, client, log = CONSOLE }) {
  const comment = buildResolutionComment(runUrl);
  const open = byNumber(await client.listOpenLabelled(LABEL));
  if (open.length === 0) {
    log.out(`No open issue carries the label ${LABEL}; nothing to close.`);
    return 0;
  }

  for (const issue of open) {
    await client.commentIssue(issue.number, comment);
    await client.closeIssue(issue.number);
    log.out(`Closed #${issue.number}: the published-artifact audit passed.`);
  }
  return 0;
}

// ---------------------------------------------------------------------------
// The audit log file
// ---------------------------------------------------------------------------

/**
 * Read the capture, if it is one regular file of a plausible size.
 *
 * The file is produced by a job that ran code resolved at run time, and what
 * this reads is quoted into a public issue. A link is refused whatever it
 * points at, so the file named is the file read.
 */
export function readAuditLog(file) {
  let stat;
  try {
    stat = lstatSync(file);
  } catch (e) {
    throw new IncidentError(
      `cannot read the audit log at ${file}: ${e?.code ?? e?.message ?? e}. The audit job ` +
        'writes it, so a missing file means the capture, not the audit, is what broke.'
    );
  }
  if (!stat.isFile()) {
    throw new IncidentError(`the audit log at ${file} is not a regular file (a link or a directory is refused).`);
  }
  if (stat.size > AUDIT_LOG_MAX_BYTES) {
    throw new IncidentError(
      `the audit log at ${file} is ${stat.size} bytes, larger than the ${AUDIT_LOG_MAX_BYTES}-byte limit.`
    );
  }
  try {
    return readFileSync(file, 'utf-8');
  } catch (e) {
    throw new IncidentError(`cannot read the audit log at ${file}: ${e?.code ?? e?.message ?? e}.`);
  }
}

// ---------------------------------------------------------------------------
// The real client. Constructed by `main` and by nothing else.
// ---------------------------------------------------------------------------

function ghExec(args, input) {
  return execFileSync('gh', args, {
    encoding: 'utf-8',
    input,
    maxBuffer: 16 * 1024 * 1024,
    timeout: 120000,
  });
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new IncidentError(`${name} is not set; this command runs inside a GitHub Actions job.`);
  return value;
}

/**
 * `gh`, which is on every GitHub-hosted runner and reads GH_TOKEN. Every value
 * is its own argument and every body goes over stdin (`--body-file -`), so no
 * text from a capture is ever parsed by a shell or by `gh` as a flag.
 *
 * `gh issue create` exits non-zero when it cannot apply a label or an assignee,
 * so an issue that would lack either is a failed create and not a created issue.
 *
 * Nothing is resolved at construction time: a client that throws when it is
 * built could not be created on the CANDIDATE path, where the refusal comes
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
      let issues = null;
      try {
        issues = JSON.parse(String(out));
      } catch {
        // Falls through to the refusal below.
      }
      // Anything but a list is unknown, and unknown is not "none open": reading
      // it as an empty list is how a second issue gets created.
      if (!Array.isArray(issues) || issues.some((issue) => !Number.isInteger(issue?.number))) {
        throw new IncidentError(`gh did not return a list of open issues labelled ${label}.`);
      }
      return issues.map((issue) => ({ number: issue.number, title: issue.title }));
    },
    createIssue({ title, body, labels, assignees }) {
      const args = ['issue', 'create', ...target(), '--title', title, '--body-file', '-'];
      for (const label of labels) args.push('--label', label);
      for (const assignee of assignees) args.push('--assignee', assignee);
      const number = /\/issues\/(\d+)\s*$/.exec(String(exec(args, body) ?? ''))?.[1];
      if (!number) throw new IncidentError('gh issue create exited 0 but printed no issue URL.');
      return { number: Number(number) };
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

/** `--name value` pairs, each named in `allowed`, each given once. */
function readFlags(argv, allowed) {
  const flags = {};
  for (let i = 0; i < argv.length; i += 2) {
    const arg = argv[i];
    const name = arg.startsWith('--') ? arg.slice(2) : null;
    if (name === null || !allowed.includes(name)) throw new UsageError(`unexpected argument: ${arg}`);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) throw new UsageError(`${arg} needs a value`);
    if (name in flags) throw new UsageError(`${arg} was given twice`);
    flags[name] = value;
  }
  return flags;
}

async function main(argv) {
  const [command, ...rest] = argv;

  if (command === 'open') {
    const flags = readFlags(rest, ['audit-log', 'run-url']);
    if (!flags['audit-log']) throw new UsageError('open needs --audit-log <file>');
    const capture = readAuditLog(flags['audit-log']);
    return openIncident({ capture, runUrl: flags['run-url'], client: ghIssuesClient() });
  }

  if (command === 'resolve') {
    const flags = readFlags(rest, ['run-url']);
    return resolveIncident({ runUrl: flags['run-url'], client: ghIssuesClient() });
  }

  throw new UsageError(`unknown command: ${command ?? '(none)'}`);
}

/**
 * Whether this file is the program being run, compared by real path. Node
 * resolves a link before it loads the main module, so `import.meta.url` is the
 * real path while `process.argv[1]` is the path as typed; compared as written,
 * a checkout reached through a link would import this file, run nothing and
 * exit 0, which a caller reads as "there was no incident to file".
 */
function isEntryPoint() {
  if (process.argv[1] === undefined) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (e) => {
      console.error(`::error::${e?.message ?? e}`);
      if (e instanceof UsageError) console.error(USAGE);
      process.exitCode = 2;
    }
  );
}
