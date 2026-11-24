/**
 * The review report's single findings list: every analyzer's results in one
 * shape, with results that share a root cause and a fix merged. AI tools
 * running on this machine are not project findings.
 *
 * Recovery is the composite re-scored by scoreReview with the fix applied.
 * HMA reports no per-check weights, so HMA's share is named, never guessed.
 */

import { createHash } from 'node:crypto';
import * as path from 'node:path';
import { rebrandBundledCommands } from '../util/rebrand.js';
import { redactUrlPasswords } from '../util/redact-url-password.js';
import { ADAPTER_REGISTRY } from '../adapters/registry.js';
import { knownCommandNames } from '../natural/known-commands.js';
import type {
  CredentialPhaseData, DetectPhaseData, GuardPhaseData, HmaFinding, HmaPhaseData,
  InitPhaseData, RecoverySummary, ReviewFinding, ScoreDimension, ScoreResult, ScoreState,
  ShieldPhaseData,
} from './review.js';

export type FindingCategory =
  | 'Secrets' | 'Agent instructions' | 'MCP config' | 'Git hygiene' | 'Supply chain'
  | 'Dependencies' | 'Configuration' | 'Runtime' | 'Governance';

export type FindingSource = 'hma' | 'credential-scan' | 'shield' | 'shadow-ai' | 'hygiene' | 'guard' | 'advisories';

export interface ReportCommand {
  command: string;
  tool: 'opena2a' | 'git' | 'shell' | 'npm';
  /** What running it changes; null when that has not been established. */
  changes: string | null;
}

/** `expect`: what the output shows once the finding is fixed. */
export interface ReportVerify extends Omit<ReportCommand, 'changes'> { expect: string }

export interface ReportRecovery {
  /**
   * The fix may also move an analyzer this report cannot re-score (HMA, Shield Runtime Risk,
   * Project Governance) unless a floor holder it does not move pins the composite.
   * computed: nothing un-re-scorable is involved, or a holder pins the result; `points` > 0.
   * atLeast: something un-re-scorable is involved and the re-scored part gains `points` > 0;
   * that analyzer's share shows on the next run.
   * nextRun: something un-re-scorable is involved, no holder pins the result, and the
   * re-scored part gains nothing; `points` and `to` are null.
   * floorPinned: the fix moves a score input, but `holder` keeps the composite where it is.
   * none: the composite does not change and no floor holder is the reason; while a floor
   * holds, that means the fix moves no score input.
   */
  kind: 'computed' | 'atLeast' | 'none' | 'nextRun' | 'floorPinned';
  points: number | null;
  from: number;
  to: number | null;
  /** Set only for floorPinned: the floor holders this fix does not move. */
  holder?: string[];
}

export interface ReportFinding {
  /** 8 hex characters; the report links to a finding as `#f-<fingerprint>`. */
  fingerprint: string;
  title: string;
  severity: string;
  /** Null when the analyzer does not rate its confidence. */
  confidence: 'confirmed' | 'likely' | 'heuristic' | null;
  category: FindingCategory;
  foundBy: { source: FindingSource; checkId: string; lines: number[] }[];
  locations: { file: string; line: number | null }[];
  evidence: { file: string | null; line: number | null; text: string }[];
  reason: string | null;
  fix: ReportCommand | null;
  then: ReportCommand | null;
  verify: ReportVerify | null;
  /** The analyzer's remediation when it is advice rather than one command. */
  advice: string | null;
  recovery: ReportRecovery;
  occurrences: number;
}

/** An OpenA2A protection that is not enabled. Not a finding: nothing was detected. */
export interface HardeningItem {
  id: 'guard-sign' | 'shield-policy';
  title: string;
  reason: string;
  fix: ReportCommand;
  recovery: ReportRecovery;
}

export interface ScoreModel {
  weightSet: ScoreResult['weightSet'];
  weights: { dimension: ScoreDimension; weight: number; score: number | null }[];
  /** The weighted average before the dominant-analyzer floor. */
  weightedScore: number;
  floorBand: number;
  /** Analyzers whose score the composite is held at; empty when the floor does not apply. */
  floorHeldBy: string[];
}

export interface ReviewFindingsInput {
  targetDir: string;
  initData: InitPhaseData;
  credentialData: CredentialPhaseData;
  guardData: GuardPhaseData;
  shieldData: ShieldPhaseData;
  hmaData: HmaPhaseData;
  detectData: DetectPhaseData;
  /** aggregateFindings output: the credential-scan matches HMA did not already report. */
  findings: ReviewFinding[];
  state: ScoreState;
  score: (state: ScoreState) => ScoreResult;
  floorBand: number;
}

type Effect = (state: ScoreState) => ScoreState;
type DraftFields = 'title' | 'severity' | 'confidence' | 'category' | 'foundBy' | 'evidence' | 'reason' | 'fix' | 'verify';

interface Draft extends Omit<ReportFinding, 'fingerprint' | 'recovery'> {
  /** The fix applied to the score inputs; null when it changes none. */
  effect: Effect | null;
  /** Floor participants the fix may also move but that cannot be re-scored here. */
  uncomputed: string[];
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const CONFIDENCE_FACTOR = { confirmed: 1, likely: 0.9, heuristic: 0.7 } as const;
const UNRATED_FACTOR = 0.8;
/** Secrets and instruction injection first, then supply chain and config, then governance. */
const CATEGORY_CLASS: Record<FindingCategory, number> = {
  Secrets: 0, 'Agent instructions': 0, 'MCP config': 1, 'Git hygiene': 1, 'Supply chain': 1,
  Dependencies: 1, Configuration: 1, Runtime: 1, Governance: 2,
};

/** The finding sources behind each floor participant (buildFloorParticipants in review.ts). */
const HOLDER_SOURCES: Record<string, FindingSource[]> = {
  'Project Scan': ['hygiene'], Credentials: ['credential-scan'], 'Config Integrity': ['guard'],
  'HMA Scan': ['hma'], 'Project Governance': ['shadow-ai'], 'Shield Runtime Risk': ['shield'],
};

/** HMA check-ID prefixes that indicate a credential-related finding.
 *  Used to scope the prefer-HMA dedupe: only credential HMA findings
 *  suppress credential-scan matches. Non-credential HMA findings on the
 *  same file (e.g. GIT-002 on .gitignore) MUST NOT hide a credential that
 *  the credential scan found in that file. */
const HMA_CREDENTIAL_PREFIXES = [
  'CRED', 'AST-CRED', 'WEBCRED', 'SEM-CRED', 'AGENT-CRED',
  'ENVLEAK', 'CLIPASS', 'DRIFT',
];

export function isHmaCredentialFinding(checkId: string): boolean {
  const id = (checkId || '').toUpperCase();
  for (const p of HMA_CREDENTIAL_PREFIXES) {
    if (id === p || id.startsWith(p + '-')) return true;
  }
  return false;
}

/** HMA checks whose root cause is an env file git would stage. */
const ENV_STAGING_CHECKS = new Set(['GIT-003', 'SEM-CRED-002']);
const IGNORE_RULE_CHECKS = ['.gitignore', '.env protection'];

const PROTECT_DRY_RUN: ReportCommand = {
  command: 'opena2a protect --dry-run', tool: 'opena2a', changes: 'Lists the credentials protect would move into the vault; changes nothing.',
};
const COMMAND_CHANGES: Record<string, string> = {
  'opena2a secure --fix': "Applies the scanner's automatic fixes to files in this tree; `opena2a rollback .` undoes them.",
};
const BUNDLED_CITATION = /\b(?:hackmyagent|secretless-ai|ai-trust|cryptoserve)\b|\bnpx\s|npm install -g/;

/** The form of an npm package name, as review.ts checks it before a
 *  contribution: only these characters reach an advisory's install command. */
const NPM_NAME_FORM = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
/** Evidence lines the report keeps per finding. */
const EVIDENCE_LINES = 3;
const MASK = '••••';
const SECRET_WORD = '(?:key|token|secret|passw|pwd|auth|credential|private)';
const AUTH_SCHEME = '(?:(?:bearer|basic|token|digest)[ \\t]{1,16})?';
const NAMED_VALUE = new RegExp(`(${SECRET_WORD}[\\w.-]{0,64}["']?\\s*[:=]\\s*)(${AUTH_SCHEME}(?:"[^"]*"|'[^']*'|[^\\s,;}]+))`, 'gi');
const FLAG_VALUE = new RegExp(`(--?[\\w-]{0,64}${SECRET_WORD}[\\w-]{0,64}[ =])(${AUTH_SCHEME}\\S+)`, 'gi');
const ASSIGNMENT = /^(\s*(?:export\s+)?["']?[\w.-]+["']?\s*[:=]\s*)(\S.*)$/;
const LONG_TOKEN = /[A-Za-z0-9_+/-]{16,}/g;
/** Characters of a line read before masking; the report keeps 160 of them. */
const MASK_WINDOW = 2048;
const LINE_BREAKS = /[\r\n\u2028\u2029]+/;

/** A line from the tree with URL passwords and secret-named values masked; for
 *  a secret finding, every assigned value or long token too. Only the first
 *  MASK_WINDOW characters are read, so one long line costs bounded time; text
 *  cut off at the window's end counts as part of any URL password it ends in.
 *  A line break of any kind (CR, LF, CRLF) ends a part, and each part is masked
 *  on its own. The identifier and scheme runs in the patterns are bounded, and
 *  the URL-password scan is linear in its input. */
export function maskEvidenceLine(line: string, secret: boolean): string {
  const cut = line.length > MASK_WINDOW;
  let out = (cut ? `${line.slice(0, MASK_WINDOW)}@` : line)
    .split(LINE_BREAKS)
    .filter(part => part.length > 0)
    .map(part => maskPart(part, secret))
    .join(' ');
  // The closing @ only ends a URL password cut off by the window; it is not part of the line.
  if (cut) out = out.replace(/@$/, '');
  if (out.length > 160) return `${out.slice(0, 159)}…`;
  return cut ? `${out}…` : out;
}

function maskPart(part: string, secret: boolean): string {
  let out = redactUrlPasswords(part, MASK).replace(NAMED_VALUE, `$1${MASK}`).replace(FLAG_VALUE, `$1${MASK}`);
  if (secret) {
    const assigned = ASSIGNMENT.exec(out);
    out = assigned ? (assigned[2].includes(MASK) ? out : assigned[1] + MASK) : out.replace(LONG_TOKEN, MASK);
  }
  return out;
}

const SAFE_PATH = /^[\w.][\w./-]*$/;
const CONTROL_CHARS = /[\x00-\x1f\x7f]/;

/** A path as one shell word. A name with a control character is written in
 *  $'…' form so the command stays on one line and keeps the exact name. */
function shellWord(p: string): string {
  if (SAFE_PATH.test(p)) return p;
  if (CONTROL_CHARS.test(p)) {
    return `$'${p.replace(/[\\']/g, '\\$&').replace(/[\x00-\x1f\x7f]/g, c => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`)}'`;
  }
  return `'${p.replace(/'/g, `'\\''`)}'`;
}

/** A gitignore rule for exactly this path: a leading ! or # and any of [*?\ would
 *  otherwise read as negation, comment or pattern; a trailing space would be dropped.
 *  A rule cannot hold a control character, so each one is matched by `?`. */
function ignorePattern(rel: string): string {
  return rel.replace(/[[*?\\]/g, '\\$&').replace(/^[!#]/, '\\$&').replace(/ $/, '\\ ')
    .replace(/[\x00-\x1f\x7f]/g, '?');
}

/** The leading newline keeps a last rule with no newline intact. */
function ignoreRuleFix(rel: string): ReportCommand {
  return {
    command: SAFE_PATH.test(rel)
      ? `printf '\\n${rel}\\n' >> .gitignore`
      : `printf '\\n%s\\n' ${shellWord(ignorePattern(rel))} >> .gitignore`,
    tool: 'shell',
    changes: 'Appends one ignore rule to .gitignore, creating the file if needed.',
  };
}

/** An analyzer's remediation as one registered opena2a command (bundled-tool
 *  citations rewritten first), else as advice; text citing another tool is dropped. */
function parseRemediation(text: string | undefined): { fix: ReportCommand | null; advice: string | null } {
  const rebranded = rebrandBundledCommands((text ?? '').trim());
  if (!rebranded) return { fix: null, advice: null };
  const [head, ...rest] = rebranded.split(/\s+(?:—|–|--)\s+/);
  const verb = /^opena2a ([a-z][a-z-]*)(?: [\w./=:@-]+)*$/.exec(head)?.[1];
  if (verb && registeredVerbs().has(verb)) {
    const said = rest.join(' — ');
    const changes = said && !BUNDLED_CITATION.test(said) ? said : COMMAND_CHANGES[head] ?? null;
    return { fix: { command: head, tool: 'opena2a', changes }, advice: null };
  }
  return { fix: null, advice: BUNDLED_CITATION.test(rebranded) ? null : rebranded };
}

let verbs: Set<string> | null = null;
/** Top-level commands and aliases this CLI registers. */
function registeredVerbs(): Set<string> {
  verbs ??= new Set([...knownCommandNames(), ...Object.values(ADAPTER_REGISTRY).flatMap(a => a.aliases ?? [])]);
  return verbs;
}

function hmaCategory(category: string): FindingCategory {
  const c = (category || '').toLowerCase();
  if (/cred|secret/.test(c)) return 'Secrets';
  if (c === 'git') return 'Git hygiene';
  if (c.includes('mcp')) return 'MCP config';
  if (/governance/.test(c)) return 'Governance';
  if (/supply|nemo-integrity|deserial/.test(c)) return 'Supply chain';
  if (/dependenc|cve/.test(c)) return 'Dependencies';
  if (/skill|instruction|prompt|soul|claude-code|memory|rag|stego|spoof|heartbeat|vscode|input|capability|scope|permission model/.test(c)) {
    return 'Agent instructions';
  }
  return 'Configuration';
}

function maxSeverity(a: string, b: string): string {
  return (SEV_RANK[b] ?? 0) > (SEV_RANK[a] ?? 0) ? b : a;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

/** Why an env file `git add .` covers is a finding. `assignments` is null when the file was not read. */
function envReason(p: string, tracked: boolean, ignored: boolean, assignments: number | null): string {
  const one = assignments === 1;
  const values = assignments === null ? 'its values' : one ? 'the value it sets' : `the ${assignments} values it sets`;
  if (tracked) {
    const rule = ignored ? 'the ignore rule that matches it does not apply to a tracked file' : 'no ignore rule matches it';
    const held = assignments === 0 ? '' : ` Earlier commits keep ${values}: rotate ${one ? 'it' : 'each one'}.`;
    return `git tracks ${p}, so each commit records it, and ${rule}.${held}`;
  }
  const held = assignments === 0
    ? ''
    : ` Once committed and pushed, ${values} ${one ? 'stays' : 'stay'} in history: removing ${one ? 'it' : 'them'} takes a history rewrite and rotating ${one ? 'it' : 'each one'}.`;
  return `No .gitignore rule matches ${p}, so \`git add .\` stages it.${held}`;
}

function hmaEvidence(f: HmaFinding, secret: boolean): Draft['evidence'] {
  const ev = f.evidence;
  if (!ev) return [];
  const file = f.file ?? null;
  const positive = ev.kind === 'positive' ? ev.lines : ev.kind === 'mixed' ? ev.positive?.lines : [];
  const absence = ev.kind === 'absence' ? ev : ev.kind === 'mixed' ? ev.absence : null;
  // The scanner's JSON may list any number of lines: take at most the three the
  // report keeps from each list before joining them, so a long list is never copied.
  const firstThree = <T>(list: T[] | undefined): T[] => (Array.isArray(list) ? list.slice(0, EVIDENCE_LINES) : []);
  const entries: Array<{ n: number; content: string } | { constraint: string }> = [
    ...firstThree(positive),
    ...firstThree(absence?.observed?.lines),
    ...firstThree(absence?.expected),
  ];
  // Only the lines the report keeps are masked.
  return entries.slice(0, EVIDENCE_LINES).map(e => 'constraint' in e
    ? { file, line: null, text: `missing: ${e.constraint}` }
    : { file, line: e.n, text: maskEvidenceLine(String(e.content ?? ''), secret) });
}

function draft(fields: Pick<Draft, DraftFields> & Partial<Draft>): Draft {
  return { locations: [], then: null, advice: null, occurrences: 1, effect: null, uncomputed: [], ...fields };
}

const passChecks = (labels: string[]): Effect => s => ({
  ...s,
  hygieneChecks: s.hygieneChecks.map(c => (labels.includes(c.label) ? { ...c, status: 'pass' as const } : c)),
});

/** Signing writes .opena2a/guard/signatures.json, which also passes the "Security config" check. */
const signGuard: Effect = s => passChecks(['Security config'])({ ...s, guard: { ...s.guard, signatureStatus: 'valid', tamperedFiles: [] } });

/** Participants the composite is held at by the dominant-analyzer floor. */
export function floorHolders(result: ScoreResult): string[] {
  if (result.composite >= result.weighted) return [];
  return result.participants.filter(p => p.ran && p.score === result.composite).map(p => p.name);
}

export function buildReviewFindings(input: ReviewFindingsInput): {
  reportFindings: ReportFinding[]; fixFirst: string[]; optionalHardening: HardeningItem[];
  scoreModel: ScoreModel; recoverySummary: RecoverySummary;
} {
  const { initData, hmaData, state, score } = input;
  const current = score(state);
  const recovery = (effect: Effect | null, uncomputed: string[]): ReportRecovery => {
    const from = current.composite;
    const after = effect ? score(effect(state)) : current;
    const points = after.composite - from;
    // A floor held by an analyzer this fix cannot move pins the result exactly.
    const holder = floorHolders(after).filter(h => !uncomputed.includes(h));
    const exact = uncomputed.length === 0 || holder.length > 0;
    if (exact && points > 0) return { kind: 'computed', points, from, to: after.composite };
    if (exact && holder.length > 0 && (uncomputed.length > 0 || movesAnInput(after))) {
      return { kind: 'floorPinned', points: 0, from, to: from, holder };
    }
    if (exact) return { kind: 'none', points: 0, from, to: from };
    return points > 0 ? { kind: 'atLeast', points, from, to: after.composite } : { kind: 'nextRun', points: null, from, to: null };
  };
  /** Whether a re-scored state differs from the current one in any dimension or floor input. */
  const movesAnInput = (after: ScoreResult) => (Object.keys(current.inputs) as ScoreDimension[]).some(d => after.inputs[d] !== current.inputs[d])
    || after.participants.some((p, i) => p.score !== current.participants[i].score || p.ran !== current.participants[i].ran);

  const drafts: Draft[] = [];
  const hmaFailed = hmaData.available ? hmaData.allFailedFindings : [];
  const merged = new Set<HmaFinding>();
  const hmaShare = hmaData.available ? ['HMA Scan'] : [];
  const warns = (label: string) => initData.hygieneChecks.find(c => c.label === label)?.status === 'warn';
  const ruleChecks = IGNORE_RULE_CHECKS.filter(warns);
  const ruleEffect = ruleChecks.length > 0 ? passChecks(ruleChecks) : null;

  // Env files `git add .` covers, merged with every check reporting the same exposure.
  let ruleCarried = false;
  for (const fact of initData.envFiles) {
    if (fact.stagedByAddAll !== true) continue;
    const p = fact.path;
    const tracked = fact.gitTracked === true;
    // A tracked file a rule already matches needs no new rule: only untracking it.
    const ruleStep = !tracked || fact.gitIgnored !== true;
    // The ignore-rule effect is credited only to a finding that lists the rule as a step.
    const credited = ruleStep && ruleEffect !== null;
    ruleCarried ||= credited;
    const members = hmaFailed.filter(f => !merged.has(f) && f.file === p && ENV_STAGING_CHECKS.has(f.checkId));
    members.forEach(f => merged.add(f));
    const values = fact.assignments ?? 0;
    const foundBy: Draft['foundBy'] = credited ? ruleChecks.map(label => ({ source: 'hygiene', checkId: label, lines: [] })) : [];
    for (const f of members) {
      const entry = foundBy.find(b => b.source === 'hma' && b.checkId === f.checkId);
      const lines = f.line != null ? [f.line] : [];
      if (entry) entry.lines.push(...lines); else foundBy.push({ source: 'hma', checkId: f.checkId, lines });
    }
    drafts.push(draft({
      title: `${p} is ${tracked ? 'tracked' : 'not ignored'} by git${values > 0 ? ` and sets ${plural(values, 'value')}` : ''}`,
      severity: members.reduce((sev, f) => maxSeverity(sev, f.severity), tracked || values > 0 ? 'high' : 'medium'),
      confidence: 'confirmed',
      category: values > 0 ? 'Secrets' : 'Git hygiene',
      foundBy,
      locations: [{ file: p, line: null }],
      evidence: [
        tracked ? { file: p, line: null, text: "in git's index" } : { file: '.gitignore', line: null, text: `no rule matches ${p}` },
        ...(fact.assignments !== null ? [{ file: p, line: null, text: `${plural(values, 'line')} ${values === 1 ? 'assigns' : 'assign'} a value (values are not read)` }] : []),
        ...members.flatMap(f => hmaEvidence(f, true)),
      ].slice(0, EVIDENCE_LINES),
      reason: envReason(p, tracked, fact.gitIgnored === true, fact.assignments),
      fix: tracked
        ? { command: `git rm --cached -- ${shellWord(p)}`, tool: 'git', changes: 'Stops tracking the file and keeps it on disk; earlier commits still hold its contents.' }
        : ignoreRuleFix(p),
      then: tracked ? (ruleStep ? ignoreRuleFix(p) : null) : values > 0 ? PROTECT_DRY_RUN : null,
      verify: tracked
        ? { command: `git ls-files -- ${shellWord(p)}`, tool: 'git', expect: 'no output' }
        : { command: `git check-ignore -v -- ${shellWord(p)}`, tool: 'git', expect: `.gitignore:<line>:${p}  ${p}` },
      occurrences: 1 + members.length,
      effect: credited ? ruleEffect : null,
      uncomputed: members.length > 0 ? hmaShare : [],
    }));
  }

  // HMA, one finding per failed result not merged above.
  const hmaDrafts = new Map<HmaFinding, Draft>();
  for (const f of hmaFailed) {
    if (merged.has(f)) continue;
    const category = hmaCategory(f.category);
    const where = f.file ? (f.line != null ? `${f.file}:${f.line}` : f.file) : null;
    const mode = initData.envFiles.find(e => e.path === f.file)?.mode ?? null;
    const readable = f.checkId === 'PERM-001' && f.file && mode && (mode[4] === 'r' || mode[7] === 'r');
    const remedy = readable ? { fix: null, advice: null } : parseRemediation(f.fix);
    const d = draft({
      title: where ? `${f.name} (${where})` : f.name,
      severity: f.severity,
      confidence: null,
      category,
      foundBy: [{ source: 'hma', checkId: f.checkId, lines: f.line != null ? [f.line] : [] }],
      locations: f.file ? [{ file: f.file, line: f.line ?? null }] : [],
      evidence: hmaEvidence(f, category === 'Secrets'),
      reason: readable
        ? `${f.file} has mode ${mode}, so ${mode![7] === 'r' ? 'every user on this machine' : 'its group'} can read it.`
        : f.rationale?.plainEnglish || f.guidance || null,
      fix: readable ? { command: `chmod 600 -- ${shellWord(f.file!)}`, tool: 'shell', changes: 'Leaves read and write access to the owner only.' } : remedy.fix,
      verify: readable
        ? { command: `ls -l -- ${shellWord(f.file!)}`, tool: 'shell', expect: 'the line starts with -rw-------' }
        : { command: 'opena2a secure', tool: 'opena2a', expect: `${f.checkId} is not reported${f.file ? ` for ${f.file}` : ''}` },
      advice: remedy.advice,
      uncomputed: hmaShare,
    });
    hmaDrafts.set(f, d);
    drafts.push(d);
  }

  // Built-in credential scan; a match HMA reports at the same place joins that finding.
  const resolvedTarget = path.resolve(input.targetDir);
  for (const m of input.credentialData.matches) {
    // A match outside the reviewed tree is not listed (aggregateFindings drops it too).
    const resolvedFile = path.resolve(m.filePath);
    if (resolvedFile !== resolvedTarget && !resolvedFile.startsWith(resolvedTarget + path.sep)) continue;
    const rel = path.relative(resolvedTarget, resolvedFile);
    const reported = input.findings.some(f => f.source === 'credential-scan' && f.id === m.findingId && f.detail === `${rel}:${m.line}`);
    // Moving the value out of the file lowers the credential count it adds.
    const removeMatch: Effect = s => {
      const bySeverity = { ...s.credentials.bySeverity, [m.severity]: Math.max(0, (s.credentials.bySeverity[m.severity] ?? 0) - 1) };
      return { ...s, credentials: { ...s.credentials, bySeverity } };
    };
    // HMA reported this match too (aggregateFindings kept its credential finding at this
    // line, else in this file): that finding carries it, its effect included.
    const atFile = reported ? [] : [...hmaDrafts.entries()]
      .filter(([f]) => f.file === rel && isHmaCredentialFinding(f.checkId)).map(([, d]) => d);
    const host = atFile.find(d => d.locations[0].line === m.line) ?? atFile[0];
    if (host) {
      const entry = host.foundBy.find(b => b.source === 'credential-scan' && b.checkId === m.findingId);
      if (!entry) host.foundBy.push({ source: 'credential-scan', checkId: m.findingId, lines: [m.line] });
      else if (!entry.lines.includes(m.line)) entry.lines.push(m.line);
      host.severity = maxSeverity(host.severity, m.severity);
      const prior = host.effect;
      host.effect = prior ? s => removeMatch(prior(s)) : removeMatch;
      continue;
    }
    drafts.push(draft({
      title: `${m.title} in ${rel}`,
      severity: m.severity,
      confidence: 'likely',
      category: 'Secrets',
      foundBy: [{ source: 'credential-scan', checkId: m.findingId, lines: [m.line] }],
      locations: [{ file: rel, line: m.line }],
      evidence: [{ file: rel, line: m.line, text: `value ${m.value}` }],
      reason: m.explanation ?? null,
      fix: { command: 'opena2a protect', tool: 'opena2a', changes: `Moves the value into the encrypted vault and replaces it in the file with a reference to ${m.envVar}.` },
      verify: { command: 'opena2a protect --dry-run', tool: 'opena2a', expect: `${rel}:${m.line} is not listed` },
      effect: removeMatch,
      // HMA did not report a credential-scan-only match, so its fix moves no HMA input. A
      // match HMA reported in a file whose credential finding joined an env file group is
      // listed on its own, with HMA's share measured on the next run.
      uncomputed: reported ? [] : hmaShare,
    }));
  }

  for (const cf of input.shieldData.classifiedFindings) {
    drafts.push(draft({
      title: cf.finding.title,
      severity: cf.finding.severity,
      confidence: null,
      category: 'Runtime',
      foundBy: [{ source: 'shield', checkId: cf.finding.id, lines: [] }],
      evidence: [{ file: null, line: null, text: `${plural(cf.count, 'event')}, ${cf.firstSeen} to ${cf.lastSeen}` }],
      // The step no command performs (revoking a key, or the condition for a
      // follow-up step) comes before the Fix command, as on the Shield page.
      reason: [cf.finding.description, cf.finding.remediationNote].filter(Boolean).join(' ') || null,
      ...parseRemediation(cf.finding.remediation),
      verify: null,
      occurrences: cf.count,
      uncomputed: ['Shield Runtime Risk'],
    }));
  }

  // The project's own MCP and AI config files (Project Governance's floor signals).
  for (const s of input.detectData.mcpServers) {
    if (s.risk !== 'critical' || s.verified || !s.source.includes('(project)')) continue;
    const file = s.source.replace(/\s*\(project\)\s*$/, '');
    drafts.push(draft({
      title: `MCP server ${s.name} has sensitive access (${file})`,
      severity: 'critical',
      confidence: 'heuristic',
      category: 'MCP config',
      foundBy: [{ source: 'shadow-ai', checkId: 'mcp-server', lines: [] }],
      locations: [{ file, line: null }],
      evidence: [{ file, line: null, text: `${s.name} (${s.transport}): ${s.capabilities.join(', ') || 'no capabilities inferred'}` }],
      reason: `There is no identity file for ${s.name} from opena2a mcp sign.`,
      fix: { command: 'opena2a mcp audit', tool: 'opena2a', changes: 'Lists the MCP servers and their identity status; changes nothing.' },
      verify: { command: 'opena2a detect', tool: 'opena2a', expect: `${s.name} is not listed at critical risk` },
      advice: `Remove ${s.name} from ${file} if this project does not use it, or narrow the command and arguments it runs with.`,
      uncomputed: ['Project Governance'],
    }));
  }
  for (const c of input.detectData.aiConfigs) {
    if (c.risk !== 'critical') continue;
    drafts.push(draft({
      title: `${c.file} references a credential`,
      severity: 'critical',
      confidence: 'heuristic',
      category: 'Secrets',
      foundBy: [{ source: 'shadow-ai', checkId: 'ai-config', lines: [] }],
      locations: [{ file: c.file, line: null }],
      evidence: [{ file: c.file, line: null, text: c.details }],
      reason: null,
      fix: null,
      verify: { command: 'opena2a detect', tool: 'opena2a', expect: `${c.file} is not listed at critical risk` },
      advice: `Move the credential out of ${c.file} into an environment variable, then rotate it.`,
      uncomputed: ['Project Governance'],
    }));
  }

  // Hygiene checks no finding above already carries.
  if (ruleEffect && !ruleCarried) {
    const noGitignore = ruleChecks.includes('.gitignore');
    drafts.push(draft({
      title: noGitignore ? 'No .gitignore in this directory' : '.gitignore has no rule for .env files',
      severity: 'low',
      confidence: 'confirmed',
      category: 'Git hygiene',
      foundBy: ruleChecks.map(label => ({ source: 'hygiene', checkId: label, lines: [] })),
      locations: [{ file: '.gitignore', line: null }],
      evidence: [{ file: '.gitignore', line: null, text: noGitignore ? 'not present' : 'no line mentions .env' }],
      reason: initData.envFiles.length === 0 ? 'No env file exists here yet; one added later would be committed with the rest of the tree.' : null,
      fix: ignoreRuleFix('.env'),
      verify: { command: 'grep -nxF .env .gitignore', tool: 'shell', expect: '<line>:.env' },
      effect: ruleEffect,
    }));
  }
  if (warns('Lock file') && !initData.projectType.startsWith('Unknown')) {
    const node = initData.projectType.startsWith('Node.js');
    drafts.push(draft({
      title: 'No dependency lock file',
      severity: 'low',
      confidence: 'confirmed',
      category: 'Supply chain',
      foundBy: [{ source: 'hygiene', checkId: 'Lock file', lines: [] }],
      evidence: [{ file: null, line: null, text: 'no lock file in this directory' }],
      reason: 'Without a lock file, two installs of this project can resolve different dependency versions.',
      fix: node ? { command: 'npm install --package-lock-only', tool: 'npm', changes: 'Writes package-lock.json from package.json without installing packages.' } : null,
      verify: node ? { command: 'ls -- package-lock.json', tool: 'shell', expect: 'package-lock.json' } : null,
      advice: node ? null : 'Commit the lock file your package manager writes.',
      effect: passChecks(['Lock file']),
    }));
  }

  const guard = input.guardData;
  if (guard.signatureStatus === 'tampered') {
    drafts.push(draft({
      title: `${plural(guard.tamperedFiles.length, 'signed config file')} changed since signing`,
      severity: 'high',
      confidence: 'confirmed',
      category: 'Configuration',
      foundBy: [{ source: 'guard', checkId: 'tampered', lines: [] }],
      locations: guard.tamperedFiles.map(file => ({ file, line: null })),
      evidence: [{ file: '.opena2a/guard/signatures.json', line: null, text: `hash differs: ${guard.tamperedFiles.join(', ')}` }],
      reason: 'They no longer match the hashes recorded at signing, so they were edited after it.',
      fix: { command: 'opena2a guard diff', tool: 'opena2a', changes: 'Shows what changed in each file; changes nothing.' },
      then: { command: 'opena2a guard resign', tool: 'opena2a', changes: 'Records the current contents as signed; run it only after reviewing the diff.' },
      verify: { command: 'opena2a guard verify', tool: 'opena2a', expect: 'no file is reported as tampered' },
      occurrences: guard.tamperedFiles.length,
      effect: s => ({ ...s, guard: { ...s.guard, signatureStatus: 'valid', tamperedFiles: [] } }),
    }));
  }

  for (const a of initData.advisories) {
    const packages = a.packages.filter(p => initData.matchedPackages.includes(p));
    const named = (packages.length > 0 ? packages : a.packages).join(', ');
    const fixed = a.fixed ?? [];
    // One npm package with one fixed version gets the install command; the
    // name must have npm's form, since it becomes part of a shell command.
    const npmFix = packages.length === 1 && fixed.length === 1 && fixed[0].package === packages[0]
      && fixed[0].ecosystem.toLowerCase() === 'npm' && fixed[0].versions.length === 1
      && NPM_NAME_FORM.test(packages[0])
      ? { pkg: packages[0], version: fixed[0].versions[0].replace(/^v/, '') }
      : null;
    const fixedText = fixed.map(f => `${f.package} ${f.versions.join(' or ')}`).join(', ');
    drafts.push(draft({
      title: `${named}: ${a.summary}`,
      severity: ({ CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' } as Record<string, string>)[a.severity ?? ''] ?? 'medium',
      confidence: 'likely',
      category: 'Dependencies',
      foundBy: [{ source: 'advisories', checkId: a.id, lines: [] }],
      evidence: [{ file: null, line: null, text: `${a.id}${a.severity ? ` (${a.severity})` : ''}${fixedText ? `; fixed in ${fixedText}` : ''}` }],
      reason: null,
      fix: npmFix
        ? { command: `npm install ${npmFix.pkg}@${npmFix.version}`, tool: 'npm', changes: `Installs ${npmFix.pkg} ${npmFix.version} and records it in package.json and package-lock.json.` }
        : null,
      verify: npmFix
        ? { command: `npm ls ${npmFix.pkg}`, tool: 'npm', expect: `${npmFix.pkg}@${npmFix.version} or later` }
        : null,
      advice: npmFix
        ? null
        : fixedText
          ? `Upgrade to the version ${a.id} names as fixed: ${fixedText}, or later.`
          : `Upgrade ${named} to a version ${a.id} does not affect.`,
    }));
  }

  const seen = new Set<string>();
  const ranked = drafts.map((d, index) => {
    const { effect, uncomputed, ...rest } = d;
    const finding: ReportFinding = { fingerprint: fingerprintOf(d, seen), ...rest, recovery: recovery(effect, uncomputed) };
    return { finding, index };
  });
  const weight = (f: ReportFinding) => (SEV_RANK[f.severity] ?? 0) * (f.confidence ? CONFIDENCE_FACTOR[f.confidence] : UNRATED_FACTOR);
  ranked.sort((x, y) => weight(y.finding) - weight(x.finding)
    || CATEGORY_CLASS[x.finding.category] - CATEGORY_CLASS[y.finding.category]
    || Number(y.finding.fix !== null) - Number(x.finding.fix !== null)
    || (y.finding.recovery.points ?? 0) - (x.finding.recovery.points ?? 0)
    || x.index - y.index);
  const reportFindings = ranked.map(r => r.finding);

  const optionalHardening: HardeningItem[] = [];
  const signable = guard.signatureStatus === 'unsigned' && guard.candidates.length > 0;
  if (signable) {
    const n = guard.candidates.length;
    optionalHardening.push({
      id: 'guard-sign',
      title: `Sign the ${plural(n, 'config file')} that ${n === 1 ? 'decides' : 'decide'} what runs here`,
      reason: `${guard.candidates.join(', ')} ${n === 1 ? 'is' : 'are'} not signed, so an edit by a dependency's install script or an agent session goes unnoticed. After signing, \`opena2a guard verify\` reports any change.`,
      fix: { command: 'opena2a guard sign', tool: 'opena2a', changes: 'Writes .opena2a/guard/signatures.json; deleting that file undoes it.' },
      recovery: recovery(signGuard, []),
    });
  }
  if (!input.shieldData.policyLoaded) {
    optionalHardening.push({
      id: 'shield-policy',
      title: 'Load a Shield policy',
      reason: `No Shield policy is loaded, so agent actions in this project are not checked against rules (Shield recorded ${plural(input.shieldData.eventCount, 'event')} for it).`,
      fix: { command: 'opena2a shield init', tool: 'opena2a', changes: null },
      // The composite does not read the policy state, so loading one moves no score input.
      recovery: recovery(s => s, []),
    });
  }

  // Summary actions: commands that change a score input, each re-scored alone, then all together.
  const actions: { dimension: string; action: string; effect: Effect }[] = [];
  if (input.credentialData.totalFindings > 0) {
    actions.push({ dimension: 'Credentials', action: 'opena2a protect', effect: s => ({ ...s, credentials: { ...s.credentials, bySeverity: {} } }) });
  }
  if (signable) actions.push({ dimension: 'Config integrity', action: 'opena2a guard sign', effect: signGuard });
  const gains = actions
    .map(a => ({ ...a, points: score(a.effect(state)).composite - current.composite }))
    .filter(a => a.points > 0)
    .sort((a, b) => b.points - a.points);
  const potentialScore = score(gains.reduce((s, a) => a.effect(s), state)).composite;
  const floorHeldBy = floorHolders(current);
  // No action re-scores a gain while a floor holds the score: name each holder and
  // what moves it, and leave the potential score to the next run rather than print
  // the current score as the best this tree can reach.
  const held = gains.length === 0 && floorHeldBy.length > 0;
  const cited = new Set(reportFindings.flatMap(f => [f.fix?.command, f.then?.command]));
  const holderAction = (holder: string): string => {
    if (holder === 'Credentials' && cited.has('opena2a protect')) return 'opena2a protect';
    const sources = HOLDER_SOURCES[holder] ?? [];
    const own = reportFindings.filter(f => f.foundBy.some(b => sources.includes(b.source)));
    const severity = ['critical', 'high'].find(sev => own.some(f => f.severity === sev));
    const counted = severity ? own.filter(f => f.severity === severity) : own;
    if (counted.length === 0) return `address what ${holder} reports`;
    return `address the ${plural(counted.length, severity ? `${severity} finding` : 'finding')} under ${holder}`;
  };
  const opportunities: RecoverySummary['opportunities'] = held
    ? floorHeldBy.map(holder => ({ dimension: holder, pointsRecoverable: null, action: holderAction(holder), kind: 'nextRun' as const }))
    : gains.map(a => ({ dimension: a.dimension, pointsRecoverable: a.points, action: a.action }));

  return {
    reportFindings,
    fixFirst: reportFindings.slice(0, 3).map(f => f.fingerprint),
    optionalHardening,
    scoreModel: {
      weightSet: current.weightSet,
      weights: (Object.keys(current.weights) as ScoreDimension[]).map(dimension => ({
        dimension,
        weight: current.weights[dimension],
        score: (dimension === 'hma' && current.weightSet === 'withoutHma')
          || (dimension === 'credentials' && current.credentialsRead === false)
          ? null : current.inputs[dimension],
      })),
      weightedScore: current.weighted,
      floorBand: input.floorBand,
      floorHeldBy,
    },
    recoverySummary: {
      currentScore: current.composite,
      potentialScore: held ? null : potentialScore,
      totalRecoverable: held ? null : potentialScore - current.composite,
      opportunities,
    },
  };
}

/** Stable on an unchanged tree: checks, first location, masked evidence. */
function fingerprintOf(d: Draft, seen: Set<string>): string {
  const base = JSON.stringify([
    d.foundBy.map(b => `${b.source}:${b.checkId}`).sort(),
    d.locations[0]?.file ?? null,
    d.locations[0]?.line ?? null,
    createHash('sha256').update(d.evidence.map(e => e.text).join('\n')).digest('hex'),
  ]);
  for (let n = 0; ; n++) {
    const fp = createHash('sha256').update(n === 0 ? base : `${base}#${n}`).digest('hex').slice(0, 8);
    if (!seen.has(fp)) {
      seen.add(fp);
      return fp;
    }
  }
}
