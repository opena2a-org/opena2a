/**
 * opena2a admin sensors -- Operate the telemetry sensor-network enrollment inbox.
 *
 * Thin admin consumer over the Registry's internal vetting endpoints. Lets a
 * human admin list self-serve enrollments awaiting approval, promote one to a
 * verified telemetry sensor, or reject (revoke) one -- without hand-rolling curl
 * and the internal master key.
 *
 * Usage:
 *   opena2a admin sensors list-pending
 *   opena2a admin sensors approve <sensorId>
 *   opena2a admin sensors reject <sensorId>
 *   opena2a admin sensors list-pending --json
 *
 * Auth: requires the Registry internal admin key, read from (in order)
 *   --api-key <key>  |  OPENA2A_INTERNAL_API_KEY  |  INTERNAL_API_KEY
 * The key is NEVER printed. Approving mints a VERIFIED sensor (ingest weight
 * 0.85) -- the only path that does -- so approve/reject confirm before acting
 * unless --yes is passed.
 */

import { bold, green, yellow, red, dim, cyan, gray } from '../util/colors.js';
import { validateRegistryUrl } from '../util/validate-registry-url.js';

// --- Types ---

export interface AdminOptions {
  subcommand?: string;
  args?: string[];
  registryUrl?: string;
  apiKey?: string;
  yes?: boolean;
  ci?: boolean;
  format?: 'text' | 'json';
  json?: boolean;
  verbose?: boolean;
}

export interface PendingEnrollment {
  sensorId: string;
  publicKey: string;
  createdAt: string;
}

interface ApiResult<T> {
  ok: boolean;
  status: number;
  data?: T;
  /** Server-provided error string (already safe to echo), if any. */
  error?: string;
}

// --- Constants ---

const DEFAULT_REGISTRY_URL = 'https://api.oa2a.org';
const REQUEST_TIMEOUT_MS = 15_000;
// RFC 4122 UUID (any version). The sensorId is the service-account UUID.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// --- Testable internals (HTTP boundary; mock these in tests) ---

export const _internals = {
  async listPending(
    registryUrl: string,
    apiKey: string,
  ): Promise<ApiResult<{ pending: PendingEnrollment[]; count: number }>> {
    return _internals.request('GET', `${registryUrl}/internal/telemetry/sensors/pending`, apiKey);
  },

  async approve(
    registryUrl: string,
    apiKey: string,
    sensorId: string,
  ): Promise<ApiResult<{ sensorId: string; state: string }>> {
    return _internals.request(
      'POST',
      `${registryUrl}/internal/telemetry/sensors/${encodeURIComponent(sensorId)}/approve`,
      apiKey,
    );
  },

  async reject(
    registryUrl: string,
    apiKey: string,
    sensorId: string,
  ): Promise<ApiResult<unknown>> {
    return _internals.request(
      'DELETE',
      `${registryUrl}/internal/service-accounts/${encodeURIComponent(sensorId)}`,
      apiKey,
    );
  },

  async request<T>(
    method: string,
    url: string,
    apiKey: string,
  ): Promise<ApiResult<T>> {
    const response = await fetch(url, {
      method,
      headers: {
        // The internal master key OR a scoped service-account token. Bearer only;
        // the value is never logged.
        Authorization: `Bearer ${apiKey}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    let body: any = undefined;
    try {
      body = await response.json();
    } catch {
      /* empty / non-JSON body (e.g. some 204s) */
    }

    if (!response.ok) {
      const error =
        body && typeof body.error === 'string' ? body.error : undefined;
      return { ok: false, status: response.status, error };
    }
    return { ok: true, status: response.status, data: body as T };
  },

  confirm(promptText: string): Promise<boolean> {
    return new Promise((resolve) => {
      process.stdout.write(promptText);
      const { createInterface } =
        require('node:readline') as typeof import('node:readline');
      const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: false });
      rl.once('line', (answer: string) => {
        rl.close();
        const a = answer.trim().toLowerCase();
        resolve(a === 'y' || a === 'yes');
      });
      rl.once('close', () => resolve(false));
    });
  },
};

// --- Helpers ---

/**
 * Resolve the registry base URL for an admin call. Throws if the value is not a
 * valid registry URL (caught by the caller and rendered as a clean error).
 *
 * SECURITY: this command transmits the Registry internal admin key as a Bearer
 * token, so the destination is deliberately NOT inherited from the ambient
 * OPENA2A_REGISTRY_URL env var or the user-config `registry.url` -- either could
 * be set by an unrelated flow and would silently exfiltrate the master key to a
 * hostile host. The destination is either the hardcoded default or a host the
 * operator EXPLICITLY types via --registry (a conscious choice, same as curl).
 * Unlike the other registry commands, which legitimately follow ambient config.
 */
export function resolveRegistryUrl(explicit?: string): string {
  if (explicit) {
    const url = explicit.replace(/\/$/, '');
    validateRegistryUrl(url);
    return url;
  }
  return DEFAULT_REGISTRY_URL;
}

/** True for the canonical production registry or a localhost dev/self-host. */
function isTrustedAdminHost(registryUrl: string): boolean {
  let host: string;
  try {
    host = new URL(registryUrl).hostname;
  } catch {
    return false;
  }
  return (
    host === 'api.oa2a.org' ||
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '::1'
  );
}

/**
 * Warn (once, to stderr) when the admin key is about to be sent somewhere other
 * than the canonical registry or localhost. Helps an operator catch a typo'd or
 * hostile --registry before the master key leaves the machine. Never prints the
 * key. Suppressed in --json mode so it can't corrupt a parsed stream.
 */
function maybeWarnNonDefaultHost(registryUrl: string, isJson: boolean): void {
  if (isJson || isTrustedAdminHost(registryUrl)) return;
  process.stderr.write(
    yellow('Warning: ') +
      `sending the internal admin key to ${registryUrl} (not the default registry). ` +
      'Make sure you trust this host.\n',
  );
}

/**
 * Resolve the internal admin key without ever surfacing its value. Precedence:
 * explicit flag, namespaced env var, then the registry's own var name (which the
 * documented `INTERNAL_API_KEY=... opena2a ...` operator pattern sets).
 */
export function resolveApiKey(explicit?: string): string | null {
  const key =
    explicit ||
    process.env.OPENA2A_INTERNAL_API_KEY ||
    process.env.INTERNAL_API_KEY ||
    '';
  return key.trim() ? key.trim() : null;
}

function emitJson(value: unknown): void {
  process.stdout.write(JSON.stringify(value) + '\n');
}

function missingKeyMessage(isJson: boolean): number {
  const msg =
    'No internal admin key found. Set OPENA2A_INTERNAL_API_KEY (or INTERNAL_API_KEY), or pass --api-key.';
  if (isJson) {
    emitJson({ error: msg });
  } else {
    process.stderr.write(red('Error: ') + msg + '\n');
    process.stderr.write(
      dim('  Example: INTERNAL_API_KEY="$INTERNAL_API_KEY_registry_prod" opena2a admin sensors list-pending\n'),
    );
  }
  return 1;
}

/** Map an HTTP failure to an actionable, key-safe message. */
function httpErrorMessage(verb: string, res: ApiResult<unknown>): string {
  switch (res.status) {
    case 401:
    case 403:
      return `${verb} rejected (HTTP ${res.status}): the admin key is missing, invalid, or lacks internal:admin scope.`;
    case 404:
      return res.error
        ? `${verb} failed (HTTP 404): ${res.error}`
        : `${verb} failed (HTTP 404): no matching pending enrollment for that sensor id.`;
    case 409:
      return `${verb} conflict (HTTP 409): ${res.error ?? 'the enrollment is in a state that cannot be changed.'}`;
    default:
      return res.error
        ? `${verb} failed (HTTP ${res.status}): ${res.error}`
        : `${verb} failed (HTTP ${res.status}).`;
  }
}

function renderPending(list: PendingEnrollment[]): void {
  const out = process.stdout;
  out.write('\n' + bold('Pending sensor enrollments') + '\n');
  if (list.length === 0) {
    out.write(green('  Inbox clear -- no enrollments awaiting approval.\n\n'));
    return;
  }
  out.write(gray(`  ${list.length} awaiting approval (newest first)\n\n`));
  for (const e of list) {
    out.write('  ' + bold(e.sensorId) + '\n');
    out.write('    ' + dim('key:     ') + e.publicKey + '\n');
    out.write('    ' + dim('enrolled:') + ' ' + e.createdAt + '\n');
    out.write('    ' + cyan(`approve: opena2a admin sensors approve ${e.sensorId}`) + '\n');
    out.write('    ' + gray(`reject:  opena2a admin sensors reject ${e.sensorId}`) + '\n\n');
  }
  out.write(
    yellow('  Approving mints a VERIFIED sensor (ingest weight 0.85). Vet before approving.\n\n'),
  );
}

// --- Subcommand handlers ---

async function handleListPending(
  registryUrl: string,
  apiKey: string,
  isJson: boolean,
): Promise<number> {
  let res: ApiResult<{ pending: PendingEnrollment[]; count: number }>;
  try {
    res = await _internals.listPending(registryUrl, apiKey);
  } catch (err) {
    const msg = `Could not reach the registry at ${registryUrl}: ${(err as Error).message}`;
    if (isJson) emitJson({ error: msg });
    else process.stderr.write(red('Error: ') + msg + '\n');
    return 1;
  }

  if (!res.ok) {
    const msg = httpErrorMessage('List', res);
    if (isJson) emitJson({ error: msg, status: res.status });
    else process.stderr.write(red('Error: ') + msg + '\n');
    return 1;
  }

  const pending = res.data?.pending ?? [];
  if (isJson) {
    emitJson({ pending, count: res.data?.count ?? pending.length });
  } else {
    renderPending(pending);
  }
  return 0;
}

async function handleApprove(
  registryUrl: string,
  apiKey: string,
  sensorId: string | undefined,
  opts: AdminOptions,
  isJson: boolean,
): Promise<number> {
  const idErr = requireSensorId(sensorId, 'approve', isJson);
  if (idErr !== null) return idErr;
  const id = sensorId as string;

  const consent = await confirmDestructive(
    `Approve sensor ${id} -> VERIFIED (ingest weight 0.85)? [y/N] `,
    opts,
    isJson,
    'approve',
  );
  if (consent !== 'consented') return abortFor(consent, isJson);

  let res: ApiResult<{ sensorId: string; state: string }>;
  try {
    res = await _internals.approve(registryUrl, apiKey, id);
  } catch (err) {
    return networkError(registryUrl, err as Error, isJson);
  }

  if (!res.ok) {
    const msg = httpErrorMessage('Approve', res);
    if (isJson) emitJson({ error: msg, status: res.status });
    else process.stderr.write(red('Error: ') + msg + '\n');
    return 1;
  }

  const state = res.data?.state ?? 'verified';
  if (isJson) {
    emitJson({ sensorId: id, state });
  } else {
    process.stdout.write(green('Approved. ') + `Sensor ${bold(id)} is now ${bold(state)}.\n`);
  }
  return 0;
}

async function handleReject(
  registryUrl: string,
  apiKey: string,
  sensorId: string | undefined,
  opts: AdminOptions,
  isJson: boolean,
): Promise<number> {
  const idErr = requireSensorId(sensorId, 'reject', isJson);
  if (idErr !== null) return idErr;
  const id = sensorId as string;

  // Guard: `reject` wraps the generic DELETE /internal/service-accounts/:id,
  // which revokes ANY service account -- including verified production sensors
  // or unrelated internal accounts. The verb only promises to reject a *pending
  // enrollment*, so refuse anything that is not currently in the inbox. This
  // closes the footgun of revoking a live account by pasting the wrong UUID.
  // NOTE: this is a best-effort client-side check with a small TOCTOU window
  // (an id approved between this list and the DELETE would still be revoked); the
  // authoritative fix is a pending-scoped reject endpoint, tracked server-side.
  let inbox: ApiResult<{ pending: PendingEnrollment[]; count: number }>;
  try {
    inbox = await _internals.listPending(registryUrl, apiKey);
  } catch (err) {
    return networkError(registryUrl, err as Error, isJson);
  }
  if (!inbox.ok) {
    const msg = httpErrorMessage('Reject', inbox);
    if (isJson) emitJson({ error: msg, status: inbox.status });
    else process.stderr.write(red('Error: ') + msg + '\n');
    return 1;
  }
  const isPending = (inbox.data?.pending ?? []).some((e) => e.sensorId === id);
  if (!isPending) {
    const msg =
      `${id} is not a pending enrollment; refusing to revoke. ` +
      `Only enrollments currently in 'list-pending' can be rejected. ` +
      `To revoke an active service account, use the registry admin API directly.`;
    if (isJson) emitJson({ error: msg });
    else process.stderr.write(red('Error: ') + msg + '\n');
    return 1;
  }

  const consent = await confirmDestructive(
    `Reject (revoke) pending enrollment ${id}? This deletes the service account. [y/N] `,
    opts,
    isJson,
    'reject',
  );
  if (consent !== 'consented') return abortFor(consent, isJson);

  let res: ApiResult<unknown>;
  try {
    res = await _internals.reject(registryUrl, apiKey, id);
  } catch (err) {
    return networkError(registryUrl, err as Error, isJson);
  }

  if (!res.ok) {
    const msg = httpErrorMessage('Reject', res);
    if (isJson) emitJson({ error: msg, status: res.status });
    else process.stderr.write(red('Error: ') + msg + '\n');
    return 1;
  }

  if (isJson) {
    emitJson({ sensorId: id, state: 'rejected' });
  } else {
    process.stdout.write(green('Rejected. ') + `Enrollment ${bold(id)} revoked.\n`);
  }
  return 0;
}

// --- Shared subcommand helpers ---

function requireSensorId(
  sensorId: string | undefined,
  verb: string,
  isJson: boolean,
): number | null {
  if (!sensorId) {
    const msg = `A sensor id is required: opena2a admin sensors ${verb} <sensorId>`;
    if (isJson) emitJson({ error: msg });
    else process.stderr.write(red('Error: ') + msg + '\n');
    return 1;
  }
  if (!UUID_RE.test(sensorId)) {
    const msg = `'${sensorId}' is not a valid sensor id (expected a UUID).`;
    if (isJson) emitJson({ error: msg });
    else process.stderr.write(red('Error: ') + msg + '\n');
    return 1;
  }
  return null;
}

type Consent = 'consented' | 'declined' | 'refused';

/**
 * Gate a destructive/privileged action behind explicit confirmation. Only --yes
 * consents -- a global --ci makes the run non-interactive but does NOT imply
 * consent to mint/revoke a credential. In a non-interactive context without
 * --yes we REFUSE rather than silently proceed. Returns a discriminated result
 * so the caller emits exactly one message ('refused' already printed its own).
 */
async function confirmDestructive(
  promptText: string,
  opts: AdminOptions,
  isJson: boolean,
  verb: string,
): Promise<Consent> {
  if (opts.yes) return 'consented';
  if (isJson || opts.ci || !process.stdin.isTTY) {
    const msg = `Refusing to ${verb} non-interactively without confirmation. Re-run with --yes.`;
    if (isJson) emitJson({ error: msg });
    else process.stderr.write(red('Error: ') + msg + '\n');
    return 'refused';
  }
  return (await _internals.confirm(promptText)) ? 'consented' : 'declined';
}

/** Resolve a non-consenting result to an exit code, printing once if needed. */
function abortFor(consent: Consent, isJson: boolean): number {
  // 'refused' already printed its own error; only 'declined' needs a message.
  if (consent === 'declined' && !isJson) process.stdout.write(gray('Aborted.\n'));
  return 1;
}

function networkError(registryUrl: string, err: Error, isJson: boolean): number {
  const msg = `Could not reach the registry at ${registryUrl}: ${err.message}`;
  if (isJson) emitJson({ error: msg });
  else process.stderr.write(red('Error: ') + msg + '\n');
  return 1;
}

function usage(isJson: boolean): number {
  const lines = [
    'Usage: opena2a admin sensors <subcommand>',
    '',
    '  list-pending            List enrollments awaiting approval (alias: pending, ls)',
    '  approve <sensorId>      Promote a pending enrollment to a verified sensor',
    '  reject  <sensorId>      Reject (revoke) a pending enrollment',
    '',
    'Options: --json  --yes  --api-key <key>  --registry <url>',
  ];
  if (isJson) emitJson({ error: 'unknown or missing subcommand', usage: lines });
  else process.stdout.write(lines.join('\n') + '\n');
  return isJson ? 1 : 0;
}

// --- Entry point ---

export async function admin(options: AdminOptions): Promise<number> {
  const isJson = options.json === true || options.format === 'json';
  const args = options.args ?? [];

  // The only group today is `sensors`. Accept `admin sensors <verb>` and, as a
  // convenience, a bare `admin <verb>` that maps onto the sensors group.
  let group = options.subcommand;
  let rest = args;
  if (group === 'sensors') {
    group = args[0];
    rest = args.slice(1);
  }

  // The privileged verbs share a prelude: resolve the key (never inheriting it
  // into output) and the destination (host-pinned; warns on a non-default host).
  if (group === 'list-pending' || group === 'pending' || group === 'ls' ||
      group === 'approve' || group === 'reject') {
    const apiKey = resolveApiKey(options.apiKey);
    if (!apiKey) return missingKeyMessage(isJson);

    let registryUrl: string;
    try {
      registryUrl = resolveRegistryUrl(options.registryUrl);
    } catch (err) {
      // validateRegistryUrl messages already name the problem (bad URL / non-HTTPS).
      const msg = (err as Error).message;
      if (isJson) emitJson({ error: msg });
      else process.stderr.write(red('Error: ') + msg + '\n');
      return 1;
    }
    maybeWarnNonDefaultHost(registryUrl, isJson);

    switch (group) {
      case 'list-pending':
      case 'pending':
      case 'ls':
        return handleListPending(registryUrl, apiKey, isJson);
      case 'approve':
        return handleApprove(registryUrl, apiKey, rest[0], options, isJson);
      case 'reject':
        return handleReject(registryUrl, apiKey, rest[0], options, isJson);
    }
  }

  return usage(isJson);
}
