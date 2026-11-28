import {
  PackageNotFoundError,
  RegistryApiError,
  classifyHttpStatus,
} from "./errors.js";
import { TtlCache } from "./cache.js";
import type {
  BatchResponse,
  PackageQuery,
  PublishResponse,
  ScanSubmission,
  TrustAnswer,
} from "./types.js";
import type { FirstPartySigner } from "./signer.js";

const NULL_UUID = "00000000-0000-0000-0000-000000000000";
const MAX_PACKAGE_NAME_LENGTH = 512;
const MAX_ERROR_BODY_BYTES = 2048;
const TRUNCATED_MARKER = "... [truncated]";
/** Largest single-package or publish answer read, in bytes. */
const MAX_QUERY_BODY_BYTES = 1024 * 1024;
/** Largest batch answer read, in bytes. */
const MAX_BATCH_BODY_BYTES = 10 * 1024 * 1024;
const MIN_TRUST_LEVEL = 0;
const MAX_TRUST_LEVEL = 4;
const CONTROL_CHAR_RE = /[\x00-\x1F\x7F]/;

function validatePackageName(name: string): void {
  if (typeof name !== "string" || name.length === 0) {
    throw new TypeError("RegistryClient: package name must be a non-empty string");
  }
  if (name.length > MAX_PACKAGE_NAME_LENGTH) {
    throw new TypeError(
      `RegistryClient: package name exceeds ${MAX_PACKAGE_NAME_LENGTH} chars (got ${name.length})`,
    );
  }
  if (CONTROL_CHAR_RE.test(name)) {
    throw new TypeError(
      "RegistryClient: package name contains control characters",
    );
  }
}

export interface RegistryClientOptions {
  /** Base URL for the registry, e.g. https://api.oa2a.org */
  baseUrl: string;
  /**
   * User-Agent string. Required so registry telemetry can attribute per-CLI.
   * Format: `<cli-name>/<cli-version>`, e.g. `ai-trust/0.3.1`.
   */
  userAgent: string;
  /**
   * Per-request timeout in ms, covering the whole call: connecting, the headers
   * and reading the body. Default: 10000.
   */
  timeoutMs?: number;
  /** Enable in-memory TTL cache on read methods. Default: true. */
  cache?: boolean;
  /** TTL in ms for cached responses. Default: 60000. */
  cacheTtlMs?: number;
  /** Override fetch implementation (tests). */
  fetch?: typeof fetch;
}

interface RawBatchResponse {
  results: TrustAnswer[];
  total: number;
  queriedAt: string;
}

export class RegistryClient {
  private readonly baseUrl: string;
  private readonly userAgent: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly trustCache?: TtlCache<TrustAnswer>;
  private readonly batchCache?: TtlCache<BatchResponse>;

  constructor(options: RegistryClientOptions) {
    if (!options.baseUrl) {
      throw new TypeError("RegistryClient: baseUrl is required");
    }
    if (!options.userAgent) {
      throw new TypeError("RegistryClient: userAgent is required");
    }
    let parsed: URL;
    try {
      parsed = new URL(options.baseUrl);
    } catch {
      throw new TypeError(
        `RegistryClient: baseUrl must be a valid URL (got ${JSON.stringify(options.baseUrl)})`,
      );
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new TypeError(
        `RegistryClient: baseUrl must use http or https (got ${parsed.protocol})`,
      );
    }
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.userAgent = options.userAgent;
    this.timeoutMs = options.timeoutMs ?? 10000;
    this.fetchImpl = options.fetch ?? fetch;

    const cacheEnabled = options.cache ?? true;
    if (cacheEnabled) {
      const ttl = options.cacheTtlMs ?? 60000;
      this.trustCache = new TtlCache<TrustAnswer>(ttl);
      this.batchCache = new TtlCache<BatchResponse>(ttl);
    }
  }

  /** Clear all cached responses. */
  clearCache(): void {
    this.trustCache?.clear();
    this.batchCache?.clear();
  }

  async checkTrust(name: string, type?: string): Promise<TrustAnswer> {
    validatePackageName(name);
    if (type !== undefined && CONTROL_CHAR_RE.test(type)) {
      throw new TypeError("RegistryClient: type contains control characters");
    }
    const cacheKey = JSON.stringify([name, type ?? ""]);
    const hit = this.trustCache?.get(cacheKey);
    if (hit) return hit;

    const params = new URLSearchParams({
      name,
      includeProfile: "true",
      includeDeps: "true",
    });
    if (type) params.set("type", type);

    const url = `${this.baseUrl}/api/v1/trust/query?${params.toString()}`;
    const data = await this.request(url, { method: "GET" }, {
      maxBytes: MAX_QUERY_BODY_BYTES,
      validate: (body, status) => checkTrustAnswer(body, "trust answer", status),
      packageNameForNotFound: name,
    });
    data.found = !!data.packageId && data.packageId !== NULL_UUID;

    this.trustCache?.set(cacheKey, data);
    return data;
  }

  async batchQuery(packages: PackageQuery[]): Promise<BatchResponse> {
    for (const p of packages) {
      validatePackageName(p.name);
      if (p.type !== undefined && CONTROL_CHAR_RE.test(p.type)) {
        throw new TypeError("RegistryClient: type contains control characters");
      }
    }
    const cacheKey = canonicalBatchKey(packages);
    const hit = this.batchCache?.get(cacheKey);
    if (hit) return hit;

    const url = `${this.baseUrl}/api/v1/trust/batch`;
    const raw = await this.request(
      url,
      {
        method: "POST",
        body: JSON.stringify({ packages }),
        headers: { "Content-Type": "application/json" },
      },
      { maxBytes: MAX_BATCH_BODY_BYTES, validate: checkBatchAnswer },
    );

    for (const r of raw.results) {
      r.found = !!r.packageId && r.packageId !== NULL_UUID;
    }
    const found = raw.results.filter((r) => r.found).length;
    const response: BatchResponse = {
      results: raw.results,
      meta: {
        total: raw.total,
        found,
        notFound: raw.total - found,
      },
    };

    this.batchCache?.set(cacheKey, response);
    return response;
  }

  /**
   * Publish scan results to the registry. Never cached.
   *
   * Pass a {@link FirstPartySigner} to self-tag privileged provenance: the signer stamps
   * `source`/`nonce`/`signedAt`/`signature`/`publicKey` onto the submission over the
   * server's strong canonical. Without a signer the scan is published as community (the
   * safe default). A signed claim the server can't verify (key not allowlisted, stale,
   * replayed) is silently downgraded to community by the registry — never rejected.
   *
   * The returned `signing` field says whether a signature was attached (`"signed"`) or why
   * not (`"unsigned: <reason>"`).
   */
  async publishScan(
    submission: ScanSubmission,
    signer?: FirstPartySigner,
  ): Promise<PublishResponse> {
    let body: ScanSubmission = submission;
    let signing: NonNullable<PublishResponse["signing"]> = "unsigned: no signer provided";
    if (signer) {
      // Stamping provenance must never crash a publish. If the signer rejects the scan
      // (e.g. a non-integer score), the scan is published unsigned — the registry records
      // it as community, rather than dropping the scan — and the reason is returned in
      // `PublishResponse.signing`.
      try {
        body = { ...submission, ...signer.sign(submission) };
        signing = "signed";
      } catch (err) {
        body = submission;
        const reason = err instanceof Error ? err.message : String(err);
        signing = `unsigned: ${reason}`;
      }
    }
    const url = `${this.baseUrl}/api/v1/trust/publish`;
    const response = await this.request(
      url,
      {
        method: "POST",
        body: JSON.stringify(body),
        headers: { "Content-Type": "application/json" },
      },
      { maxBytes: MAX_QUERY_BODY_BYTES, validate: checkPublishAnswer },
    );
    return { ...response, signing };
  }

  private async request<T>(
    url: string,
    init: RequestInit,
    expect: ExpectedAnswer<T>,
  ): Promise<T> {
    // One deadline for the whole call: headers, body and parsing. Racing the
    // work against it means a body that stalls after the headers still ends.
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(
          new RegistryApiError(
            `Registry request timed out after ${this.timeoutMs}ms`,
            "timeout",
          ),
        );
        controller.abort();
      }, this.timeoutMs);
    });
    const work = this.exchange(url, init, controller.signal, expect);
    // When the deadline wins, the work's own rejection has no listener.
    work.catch(() => undefined);
    try {
      return await Promise.race([work, deadline]);
    } finally {
      clearTimeout(timer);
    }
  }

  private async exchange<T>(
    url: string,
    init: RequestInit,
    signal: AbortSignal,
    expect: ExpectedAnswer<T>,
  ): Promise<T> {
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        ...init,
        signal,
        headers: {
          Accept: "application/json",
          "User-Agent": this.userAgent,
          ...(init.headers ?? {}),
        },
      });
    } catch (err) {
      const isAbort =
        signal.aborted ||
        (err instanceof Error &&
          (err.name === "AbortError" || err.name === "TimeoutError"));
      throw new RegistryApiError(
        isAbort
          ? `Registry request timed out after ${this.timeoutMs}ms`
          : `Registry network error: ${err instanceof Error ? err.message : String(err)}`,
        isAbort ? "timeout" : "network",
      );
    }

    if (!response.ok) {
      if (response.status === 404 && expect.packageNameForNotFound) {
        throw new PackageNotFoundError(expect.packageNameForNotFound);
      }
      const body = await safeText(response, signal);
      throw new RegistryApiError(
        `Registry API returned ${response.status}`,
        classifyHttpStatus(response.status),
        response.status,
        body,
      );
    }

    const data = await readJson(response, expect.maxBytes, signal);
    return expect.validate(data, response.status);
  }
}

interface ExpectedAnswer<T> {
  /** Largest body accepted, in bytes. */
  maxBytes: number;
  /** Checks the parsed body and returns it typed, or throws `invalid_response`. */
  validate: (data: unknown, status: number) => T;
  /** A 404 means this package is not in the registry. */
  packageNameForNotFound?: string;
}

function invalidResponse(message: string, status?: number): RegistryApiError {
  return new RegistryApiError(
    `Registry returned an invalid response: ${message}`,
    "invalid_response",
    status,
  );
}

function declaredLength(response: Response): number | undefined {
  const headers = (response as { headers?: { get?: (name: string) => string | null } })
    .headers;
  const raw = typeof headers?.get === "function" ? headers.get("content-length") : null;
  if (raw === null || raw === undefined || !/^\d+$/.test(raw.trim())) return undefined;
  return Number(raw.trim());
}

interface StreamReader {
  read(): Promise<{ done: boolean; value?: unknown }>;
  cancel(reason?: unknown): Promise<void>;
}

function streamReader(response: Response): StreamReader | undefined {
  const body = (response as { body?: unknown }).body;
  if (
    body !== null &&
    typeof body === "object" &&
    typeof (body as { getReader?: unknown }).getReader === "function"
  ) {
    return (body as { getReader(): StreamReader }).getReader();
  }
  return undefined;
}

/**
 * Read at most `maxBytes` from the body. `truncated` says whether more was
 * there; the rest of the stream is cancelled rather than read.
 */
async function readCapped(
  reader: StreamReader,
  maxBytes: number,
  signal: AbortSignal,
): Promise<{ bytes: Uint8Array; truncated: boolean }> {
  const onAbort = () => {
    reader.cancel().catch(() => undefined);
  };
  signal.addEventListener("abort", onAbort, { once: true });
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (signal.aborted) {
        throw new RegistryApiError("Registry request aborted", "timeout");
      }
      if (done) break;
      const chunk =
        value instanceof Uint8Array
          ? value
          : typeof value === "string"
            ? new TextEncoder().encode(value)
            : undefined;
      if (!chunk) throw invalidResponse("body stream yielded a non-byte chunk");
      if (total + chunk.byteLength > maxBytes) {
        chunks.push(chunk.subarray(0, maxBytes - total));
        total = maxBytes;
        truncated = true;
        reader.cancel().catch(() => undefined);
        break;
      }
      chunks.push(chunk);
      total += chunk.byteLength;
    }
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.byteLength;
  }
  return { bytes, truncated };
}

async function readJson(
  response: Response,
  maxBytes: number,
  signal: AbortSignal,
): Promise<unknown> {
  const tooLarge = () =>
    invalidResponse(`body exceeds ${maxBytes} bytes`, response.status);
  const declared = declaredLength(response);
  if (declared !== undefined && declared > maxBytes) throw tooLarge();

  const reader = streamReader(response);
  if (!reader) {
    // A fetch whose Response has no readable body stream (some test doubles
    // and fetch shims): fall back to its own json(); the deadline still applies.
    try {
      return await response.json();
    } catch (err) {
      if (err instanceof RegistryApiError) throw err;
      throw invalidJson(err, response.status);
    }
  }

  const { bytes, truncated } = await readCapped(reader, maxBytes, signal);
  if (truncated) throw tooLarge();
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (err) {
    throw invalidJson(err, response.status);
  }
}

function invalidJson(err: unknown, status: number): RegistryApiError {
  return new RegistryApiError(
    `Registry returned invalid JSON: ${err instanceof Error ? err.message : String(err)}`,
    "invalid_response",
    status,
  );
}

async function safeText(
  response: Response,
  signal: AbortSignal,
): Promise<string | undefined> {
  try {
    const reader = streamReader(response);
    if (reader) {
      // Stop reading at the cap: an error body is only kept for diagnostics.
      const { bytes, truncated } = await readCapped(reader, MAX_ERROR_BODY_BYTES, signal);
      const text = new TextDecoder().decode(bytes);
      return truncated ? text + TRUNCATED_MARKER : text;
    }
    const raw = await response.text();
    if (raw.length > MAX_ERROR_BODY_BYTES) {
      return raw.slice(0, MAX_ERROR_BODY_BYTES) + TRUNCATED_MARKER;
    }
    return raw;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** True when a field is absent: missing, or JSON null. */
function absent(value: unknown): boolean {
  return value === undefined || value === null;
}

function checkTrustAnswer(value: unknown, where: string, status: number): TrustAnswer {
  if (!isRecord(value)) {
    throw invalidResponse(`${where} is not a JSON object`, status);
  }
  for (const field of ["packageId", "name", "packageType", "type", "verdict"]) {
    if (!absent(value[field]) && typeof value[field] !== "string") {
      throw invalidResponse(`${where}.${field} is not a string`, status);
    }
  }
  const level = value.trustLevel;
  if (!absent(level)) {
    if (
      typeof level !== "number" ||
      !Number.isInteger(level) ||
      level < MIN_TRUST_LEVEL ||
      level > MAX_TRUST_LEVEL
    ) {
      throw invalidResponse(
        `${where}.trustLevel must be an integer from ${MIN_TRUST_LEVEL} to ${MAX_TRUST_LEVEL}`,
        status,
      );
    }
  }
  const score = value.trustScore;
  if (!absent(score)) {
    if (typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 1) {
      throw invalidResponse(`${where}.trustScore must be a number from 0 to 1`, status);
    }
  }
  if (!absent(value.dependencies) && !isRecord(value.dependencies)) {
    throw invalidResponse(`${where}.dependencies is not a JSON object`, status);
  }
  return value as unknown as TrustAnswer;
}

function checkBatchAnswer(value: unknown, status: number): RawBatchResponse {
  if (!isRecord(value)) {
    throw invalidResponse("batch answer is not a JSON object", status);
  }
  if (!Array.isArray(value.results)) {
    throw invalidResponse("batch answer has no results array", status);
  }
  value.results.forEach((r, i) => checkTrustAnswer(r, `results[${i}]`, status));
  const total = value.total;
  if (typeof total !== "number" || !Number.isSafeInteger(total) || total < 0) {
    throw invalidResponse("batch answer total is not a non-negative integer", status);
  }
  return value as unknown as RawBatchResponse;
}

function checkPublishAnswer(value: unknown, status: number): PublishResponse {
  if (!isRecord(value)) {
    throw invalidResponse("publish answer is not a JSON object", status);
  }
  if (!absent(value.accepted) && typeof value.accepted !== "boolean") {
    throw invalidResponse("publish answer accepted is not a boolean", status);
  }
  return value as unknown as PublishResponse;
}

function canonicalBatchKey(packages: PackageQuery[]): string {
  const sorted = packages
    .map((p) => ({
      name: p.name,
      type: p.type ?? "",
      ecosystem: p.ecosystem ?? "",
    }))
    .sort((a, b) => {
      if (a.name !== b.name) return a.name < b.name ? -1 : 1;
      if (a.type !== b.type) return a.type < b.type ? -1 : 1;
      return a.ecosystem < b.ecosystem ? -1 : a.ecosystem === b.ecosystem ? 0 : 1;
    });
  return JSON.stringify(sorted);
}
