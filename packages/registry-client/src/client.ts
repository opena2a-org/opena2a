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

const NULL_UUID = "00000000-0000-0000-0000-000000000000";
const MAX_PACKAGE_NAME_LENGTH = 512;
const MAX_ERROR_BODY_BYTES = 2048;
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
  /** Per-request timeout in ms. Default: 10000. */
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
    const data = await this.request<TrustAnswer>(url, { method: "GET" }, name);
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
    const raw = await this.request<RawBatchResponse>(url, {
      method: "POST",
      body: JSON.stringify({ packages }),
      headers: { "Content-Type": "application/json" },
    });

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
   * Publish scan results to the community registry. Never cached.
   */
  async publishScan(submission: ScanSubmission): Promise<PublishResponse> {
    const url = `${this.baseUrl}/api/v1/trust/publish`;
    return this.request<PublishResponse>(url, {
      method: "POST",
      body: JSON.stringify(submission),
      headers: { "Content-Type": "application/json" },
    });
  }

  private async request<T>(
    url: string,
    init: RequestInit,
    packageNameForNotFound?: string,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        ...init,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          "User-Agent": this.userAgent,
          ...(init.headers ?? {}),
        },
      });
    } catch (err) {
      const isAbort =
        err instanceof Error &&
        (err.name === "AbortError" || err.name === "TimeoutError");
      throw new RegistryApiError(
        isAbort
          ? `Registry request timed out after ${this.timeoutMs}ms`
          : `Registry network error: ${err instanceof Error ? err.message : String(err)}`,
        isAbort ? "timeout" : "network",
      );
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      if (response.status === 404 && packageNameForNotFound) {
        throw new PackageNotFoundError(packageNameForNotFound);
      }
      const body = await safeText(response);
      throw new RegistryApiError(
        `Registry API returned ${response.status}`,
        classifyHttpStatus(response.status),
        response.status,
        body,
      );
    }

    try {
      return (await response.json()) as T;
    } catch (err) {
      throw new RegistryApiError(
        `Registry returned invalid JSON: ${err instanceof Error ? err.message : String(err)}`,
        "invalid_response",
        response.status,
      );
    }
  }
}

async function safeText(response: Response): Promise<string | undefined> {
  try {
    const raw = await response.text();
    if (raw.length > MAX_ERROR_BODY_BYTES) {
      return raw.slice(0, MAX_ERROR_BODY_BYTES) + "... [truncated]";
    }
    return raw;
  } catch {
    return undefined;
  }
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
