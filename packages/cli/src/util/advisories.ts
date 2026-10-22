/**
 * Advisory check utility -- fetches security advisories from the OpenA2A Registry
 * and warns users about flagged tools in their project.
 *
 * Called during `opena2a init` and `opena2a review` to surface intelligence from
 * community scan reports.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { bold, red, yellow, dim, cyan, orange } from './colors.js';
import { printable } from './printable.js';
import { RegistryUrlRefusal, validateRegistryUrl } from './validate-registry-url.js';

// --- Types ---

interface OSVSeverity {
  type: string;
  score: string;
}

interface OSVAffected {
  package: {
    name: string;
    ecosystem: string;
  };
  ranges?: {
    type: string;
    events: { introduced?: string; fixed?: string }[];
  }[];
}

export interface Advisory {
  id: string;
  summary: string;
  severity: OSVSeverity[];
  affected: OSVAffected[];
  published: string;
  details?: string;
  databaseSpecific?: Record<string, any>;
}

interface AdvisoryResponse {
  advisories: Advisory[];
  total: number;
  format: string;
}

export interface AdvisoryCheck {
  advisories: Advisory[];
  matchedPackages: string[];
  /** The number of advisories the Registry reported for the request. */
  total: number;
  /** The number of advisories in the list that was read. Below `total` when
   *  the Registry holds more than the request asks for. */
  listed: number;
  fromCache: boolean;
  /** Whether an advisory list was read, from the Registry or the cache. When
   *  false no dependency was compared, so the result is "not checked", not
   *  "no advisories found". */
  checked: boolean;
  /** Why no advisory list was read, in one line; null when one was read. */
  reason: string | null;
  /** True when OPENA2A_ADVISORIES=off turned the request off. */
  turnedOff: boolean;
}

/** The request reads the advisories published in this many days... */
export const ADVISORY_WINDOW_DAYS = 30;
/** ...and at most this many of them. */
export const ADVISORY_LIMIT = 100;
const ADVISORY_TIMEOUT_MS = 5_000;

/** Set to `off` to make `review` and `init` skip the advisory request. */
export const ADVISORIES_ENV = 'OPENA2A_ADVISORIES';

/** The result when no advisory list was read. */
export function advisoriesNotChecked(reason: string | null = null, turnedOff = false): AdvisoryCheck {
  return { advisories: [], matchedPackages: [], total: 0, listed: 0, fromCache: false, checked: false, reason, turnedOff };
}

function advisoriesTurnedOff(): boolean {
  return ['off', '0', 'false', 'no'].includes((process.env[ADVISORIES_ENV] ?? '').trim().toLowerCase());
}

/** The Registry URL without a trailing `/`, so the request path is joined
 *  with one slash. */
function normalizeRegistryUrl(registryUrl: string): string {
  return registryUrl.trim().replace(/\/+$/, '');
}

/** The parsed origin and path of a Registry URL, without a trailing `/`;
 *  null when it does not parse or when an `@` follows its host. The parser
 *  takes everything before the last `@` of the host part as the user name
 *  and password, so neither is in the origin or path. An `@` after the host
 *  means the parser read the text before it as a host, port or path, and
 *  that text can be a user name and password (`http://user:12/pw@host` is
 *  host `user`, port 12 and path `/pw@host`), so that URL is not named by
 *  its parts. */
function urlParts(registryUrl: string): string | null {
  try {
    const u = new URL(registryUrl);
    if (`${u.pathname}${u.search}${u.hash}`.includes('@')) return null;
    return `${u.origin}${u.pathname}`.replace(/\/+$/, '');
  } catch {
    return null;
  }
}

/** The Registry URL as it is named in a reason: origin and path only, no
 *  credentials. */
function shownUrl(registryUrl: string): string {
  return urlParts(registryUrl) ?? 'the configured Registry';
}

/** Why a configured Registry URL was refused, in one line. The line is built
 *  from the refusal's kind and the URL's parsed origin and path, never from
 *  the configured text or the refusal's message, which repeats that text
 *  whole, so a user name and password in it are not shown, whatever
 *  characters the password holds. An error that is not the validator's
 *  refusal is named without its message. The line is shown in the terminal
 *  and the report. */
function refusalReason(err: unknown): string {
  if (err instanceof RegistryUrlRefusal && err.kind === 'plain-http') {
    const parts = urlParts(err.url);
    return parts ? `Registry URL must use HTTPS: ${parts}` : 'the configured registry.url must use HTTPS';
  }
  if (err instanceof RegistryUrlRefusal) return 'the configured registry.url is not a valid URL';
  return 'the configured registry.url was refused';
}

/** The first line of a request error's message. fetch repeats the URL as
 *  given when it refuses one that carries a user name and password, so the
 *  Registry URL, as configured and as the parser writes it, is replaced by
 *  its `shownUrl` name wherever it appears, and anything still left between
 *  `//` and an `@` on the line is removed. */
function firstLine(err: unknown, registryUrl: string): string {
  let message = err instanceof Error ? err.message : String(err);
  const shown = shownUrl(registryUrl);
  for (const form of [registryUrl, parsedHref(registryUrl)]) {
    if (form) message = message.split(form).join(shown);
  }
  return (message.split('\n')[0] ?? '').replace(/\/\/[^/]*@/g, '//').trim();
}

/** The URL as the parser writes it, without a trailing `/`; '' when it does
 *  not parse. */
function parsedHref(registryUrl: string): string {
  try {
    return new URL(registryUrl).href.replace(/\/$/, '');
  } catch {
    return '';
  }
}

// --- Shape ---

// The Registry's answer and the cache file are outside data, so the list is
// checked as it is read, and the code after it reads only what passed.

type Fields = Record<string, unknown>;

function isFields(value: unknown): value is Fields {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The objects in `value` when it is a list; none when it is not. */
function objectsIn(value: unknown): Fields[] {
  return Array.isArray(value) ? value.filter(isFields) : [];
}

function textIn(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/**
 * The advisories of a list, holding the fields the CLI reads. An entry that
 * is not an object is left out, a list field that is not a list is read as
 * empty, and a text field that is not text as ''. Read as received, a `null`
 * entry, an `affected`, `ranges` or `events` field that was not a list, or an
 * ecosystem or ID that was not text stopped `review` and `init`.
 */
function readableAdvisories(list: unknown[]): Advisory[] {
  return objectsIn(list).map(entry => ({
    id: textIn(entry.id),
    summary: textIn(entry.summary),
    published: textIn(entry.published),
    severity: objectsIn(entry.severity)
      .filter(s => typeof s.score === 'string')
      .map(s => ({ type: textIn(s.type), score: textIn(s.score) })),
    affected: objectsIn(entry.affected).map(a => {
      const pkg: Fields = isFields(a.package) ? a.package : {};
      return {
        package: { name: textIn(pkg.name), ecosystem: textIn(pkg.ecosystem) },
        ranges: objectsIn(a.ranges).map(r => ({
          type: textIn(r.type),
          events: objectsIn(r.events).map(e => ({
            ...(typeof e.introduced === 'string' ? { introduced: e.introduced } : {}),
            ...(typeof e.fixed === 'string' ? { fixed: e.fixed } : {}),
          })),
        })),
      };
    }),
  }));
}

/** An answer, from the Registry or the cache, as the response the code reads;
 *  null when it holds no advisory list. Without a numeric total, the total is
 *  the number of entries the list holds, those left out included. */
function advisoryResponse(body: unknown): AdvisoryResponse | null {
  if (!isFields(body) || !Array.isArray(body.advisories)) return null;
  return {
    advisories: readableAdvisories(body.advisories),
    total: typeof body.total === 'number' && Number.isFinite(body.total) ? body.total : body.advisories.length,
    format: textIn(body.format),
  };
}

// --- Cache ---

// The advisory list is the Registry's, not the project's, so it is cached in
// the user's home: a review or init of a tree writes no cache into that tree.
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface CachedAdvisories {
  fetchedAt: number;
  registryUrl: string;
  data: AdvisoryResponse;
}

function getCachePath(): string {
  return path.join(os.homedir(), '.opena2a', 'cache', 'advisories.json');
}

function readCache(registryUrl: string): CachedAdvisories | null {
  const cachePath = getCachePath();
  if (!fs.existsSync(cachePath)) return null;

  try {
    const raw = fs.readFileSync(cachePath, 'utf-8');
    const cached: unknown = JSON.parse(raw);
    if (!isFields(cached)) return null;
    // A list read from another Registry is not this Registry's list.
    const data = cached.registryUrl === registryUrl ? advisoryResponse(cached.data) : null;
    if (data && typeof cached.fetchedAt === 'number' && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
      return { fetchedAt: cached.fetchedAt, registryUrl, data };
    }
  } catch {
    // Corrupted cache
  }
  return null;
}

function writeCache(registryUrl: string, data: AdvisoryResponse): void {
  const cachePath = getCachePath();
  const cacheDir = path.dirname(cachePath);
  try {
    // On a first run this write creates ~/.opena2a, so it sets the mode of the
    // directory the other files there rely on: owner only, as their writers do.
    fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(cachePath, JSON.stringify({
      fetchedAt: Date.now(),
      registryUrl,
      data,
    } as CachedAdvisories), { encoding: 'utf-8', mode: 0o600 });
  } catch {
    // Cache write failure is non-critical
  }
}

// --- Fetch ---

/**
 * Read the advisory list. The request names a date and a count and nothing
 * about the project: dependencies are matched against the list here, on this
 * machine. When no list is read, `reason` says why in one line.
 */
async function fetchAdvisories(registryUrl: string): Promise<{ data: AdvisoryResponse } | { reason: string }> {
  // The validator accepts an empty URL, which would build a relative one.
  if (!registryUrl) return { reason: 'no Registry URL is configured' };
  try {
    validateRegistryUrl(registryUrl);
  } catch (err) {
    return { reason: refusalReason(err) };
  }
  const where = shownUrl(registryUrl);
  const since = new Date(Date.now() - ADVISORY_WINDOW_DAYS * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const url = `${registryUrl}/api/v1/trust/advisories?since=${since}&limit=${ADVISORY_LIMIT}`;
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(ADVISORY_TIMEOUT_MS),
    });

    if (!response.ok) return { reason: `${where} answered HTTP ${response.status}` };
    const data = advisoryResponse(await response.json());
    // A body without an advisory list is not a list that was read.
    if (!data) return { reason: `${where} answered without an advisory list` };
    return { data };
  } catch (err) {
    if (err instanceof Error && err.name === 'TimeoutError') {
      return { reason: `${where} did not answer within ${ADVISORY_TIMEOUT_MS / 1000} seconds` };
    }
    // A URL that is not named by its parts can hold a user name and password
    // the parser read as its host or port, which a request error names.
    if (urlParts(registryUrl) === null) return { reason: `${where} could not be read` };
    const cause = err instanceof Error && err.cause instanceof Error ? `: ${firstLine(err.cause, registryUrl)}` : '';
    return { reason: `${where} could not be read (${firstLine(err, registryUrl)}${cause})` };
  }
}

// --- Package detection ---

function detectProjectPackages(dir: string): string[] {
  const packages: string[] = [];

  // Read package.json dependencies
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const deps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.optionalDependencies,
      };
      packages.push(...Object.keys(deps ?? {}));
    } catch {
      // Invalid package.json
    }
  }

  // Read go.mod dependencies
  const goModPath = path.join(dir, 'go.mod');
  if (fs.existsSync(goModPath)) {
    try {
      const content = fs.readFileSync(goModPath, 'utf-8');
      const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
      if (requireBlock) {
        const lines = requireBlock[1].split('\n');
        for (const line of lines) {
          const match = line.trim().match(/^(\S+)\s/);
          if (match) packages.push(match[1]);
        }
      }
    } catch {
      // Invalid go.mod
    }
  }

  // Read requirements.txt
  const reqPath = path.join(dir, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    try {
      const content = fs.readFileSync(reqPath, 'utf-8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
          const name = trimmed.split(/[=<>!~]/)[0].trim();
          if (name) packages.push(name);
        }
      }
    } catch {
      // Invalid requirements.txt
    }
  }

  return packages;
}

// --- Main check ---

/**
 * Read the Registry's advisory list and match it against the packages `dir`
 * depends on. The Registry URL is required: the caller passes the one
 * `getRegistryUrl()` resolved, so the check cannot run against no Registry
 * and report an empty list as "no advisories".
 */
export async function checkAdvisories(
  dir: string,
  configuredUrl: string,
): Promise<AdvisoryCheck> {
  const registryUrl = normalizeRegistryUrl(configuredUrl);
  // Check cache first
  const cached = readCache(registryUrl);
  let data: AdvisoryResponse;
  let fromCache = false;

  if (cached) {
    data = cached.data;
    fromCache = true;
  } else {
    const fetched = await fetchAdvisories(registryUrl);
    if ('reason' in fetched) return advisoriesNotChecked(fetched.reason);
    data = fetched.data;
    writeCache(registryUrl, data);
  }

  const listed = data.advisories.length;
  // A missing or malformed total is read as the length of the list.
  const total = typeof data.total === 'number' && Number.isFinite(data.total) ? Math.max(data.total, listed) : listed;

  if (listed === 0) {
    return { advisories: [], matchedPackages: [], total, listed, fromCache, checked: true, reason: null, turnedOff: false };
  }

  // Match advisories against project packages
  const projectPackages = new Set(detectProjectPackages(dir));
  const matched: Advisory[] = [];
  const matchedNames: string[] = [];

  for (const advisory of data.advisories) {
    for (const affected of advisory.affected ?? []) {
      const pkgName = affected.package?.name;
      if (pkgName && projectPackages.has(pkgName)) {
        matched.push(advisory);
        if (!matchedNames.includes(pkgName)) {
          matchedNames.push(pkgName);
        }
        break;
      }
    }
  }

  return {
    advisories: matched,
    matchedPackages: matchedNames,
    total,
    listed,
    fromCache,
    checked: true,
    reason: null,
    turnedOff: false,
  };
}

/**
 * The advisory check `review` and `init` run: skipped when
 * OPENA2A_ADVISORIES=off, otherwise read from the Registry `resolveRegistryUrl`
 * names. A configured URL the resolver refuses leaves the advisories not
 * checked, with the refusal, named without the URL's user name and
 * password, as the reason.
 */
export async function readAdvisories(
  dir: string,
  resolveRegistryUrl: () => Promise<string>,
): Promise<AdvisoryCheck> {
  if (advisoriesTurnedOff()) {
    return advisoriesNotChecked(`the advisory request is turned off (${ADVISORIES_ENV}=off)`, true);
  }
  let registryUrl: string;
  try {
    registryUrl = await resolveRegistryUrl();
  } catch (err) {
    return advisoriesNotChecked(refusalReason(err));
  }
  // The advisory check never stops review or init: an error the read or the
  // comparison throws leaves the advisories not checked. Its message is not
  // shown, since it could repeat the configured URL.
  try {
    return await checkAdvisories(dir, registryUrl);
  } catch {
    return advisoriesNotChecked('the advisory list could not be read or compared');
  }
}

/**
 * The fixed versions an advisory names for `pkg`, from its OSV ranges, in the
 * order given. Only plain version strings are kept: the value is shown in
 * the report and can become part of an install command.
 */
export function fixedVersions(advisory: Advisory, pkg: string): string[] {
  const versions: string[] = [];
  for (const affected of advisory.affected ?? []) {
    if (affected.package?.name !== pkg) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        const v = event?.fixed;
        if (typeof v === 'string' && /^v?\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.-]+)?$/.test(v) && !versions.includes(v)) {
          versions.push(v);
        }
      }
    }
  }
  return versions;
}

// --- Output ---

export function printAdvisoryWarnings(check: AdvisoryCheck): void {
  if (check.advisories.length === 0) return;

  process.stdout.write('\n');
  process.stdout.write(red(bold('  Security Advisories')) + '\n');
  process.stdout.write(dim('  ' + '-'.repeat(47)) + '\n');

  // Every advisory field is Registry text, so each is cut to one printable
  // line before it reaches the terminal.
  const text = (value: unknown): string => printable(typeof value === 'string' ? value : String(value ?? ''));
  for (const advisory of check.advisories) {
    const severity = text(advisory.severity?.[0]?.score ?? 'UNKNOWN');
    const severityColor = severity === 'CRITICAL' ? red
      : severity === 'HIGH' ? orange
      : severity === 'MODERATE' ? yellow
      : dim;

    const packages = (advisory.affected ?? []).map(a => a.package?.name).filter(Boolean).map(text);

    process.stdout.write(`  ${severityColor(`[${severity}]`.padEnd(12))} ${text(advisory.summary)}\n`);
    process.stdout.write(`  ${' '.repeat(12)} ${dim(`ID: ${text(advisory.id)}  Packages: ${packages.join(', ')}`)}\n`);
  }

  process.stdout.write(dim('  ' + '-'.repeat(47)) + '\n');
  process.stdout.write(`  ${yellow(`${check.advisories.length} advisory(ies)`)} affecting ${cyan(check.matchedPackages.map(text).join(', '))}\n`);
  // The package is a shell parameter that refuses when unset: pasted before
  // PACKAGE is set, the shell prints the message and runs nothing.
  process.stdout.write(dim('  For details, run: opena2a verify --package "${PACKAGE:?set PACKAGE to a package named above}"\n'));
  process.stdout.write('\n');
}
