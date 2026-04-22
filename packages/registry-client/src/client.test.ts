import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  PackageNotFoundError,
  RegistryApiError,
  RegistryClient,
} from "./index.js";

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
    text: async () => (typeof data === "string" ? data : JSON.stringify(data)),
  } as Response;
}

const UA = "test-cli/0.0.0";

describe("RegistryClient", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: RegistryClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    client = new RegistryClient({
      baseUrl: "https://api.example.com",
      userAgent: UA,
      fetch: fetchMock as unknown as typeof fetch,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("constructor", () => {
    it("requires baseUrl", () => {
      expect(
        () =>
          new RegistryClient({
            baseUrl: "",
            userAgent: UA,
            fetch: fetchMock as unknown as typeof fetch,
          }),
      ).toThrow(TypeError);
    });

    it("requires userAgent", () => {
      expect(
        () =>
          new RegistryClient({
            baseUrl: "https://api.example.com",
            userAgent: "",
            fetch: fetchMock as unknown as typeof fetch,
          }),
      ).toThrow(TypeError);
    });

    it("strips trailing slashes from baseUrl", async () => {
      const c = new RegistryClient({
        baseUrl: "https://api.example.com///",
        userAgent: UA,
        fetch: fetchMock as unknown as typeof fetch,
      });
      fetchMock.mockResolvedValue(
        jsonResponse({ packageId: "x", name: "t", trustLevel: 3, trustScore: 0.8, verdict: "safe" }),
      );
      await c.checkTrust("t");
      const calledUrl = fetchMock.mock.calls[0][0] as string;
      expect(calledUrl.startsWith("https://api.example.com/api/")).toBe(true);
    });
  });

  describe("checkTrust", () => {
    it("builds correct URL with name + profile + deps params", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ packageId: "abc", name: "my-pkg", trustLevel: 3, trustScore: 0.8, verdict: "safe" }),
      );
      await client.checkTrust("my-pkg");
      const url = fetchMock.mock.calls[0][0] as string;
      expect(url).toContain("/api/v1/trust/query?");
      expect(url).toContain("name=my-pkg");
      expect(url).toContain("includeProfile=true");
      expect(url).toContain("includeDeps=true");
      expect(url).not.toContain("type=");
    });

    it("includes type when provided", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ packageId: "abc", name: "p", trustLevel: 3, trustScore: 0.8, verdict: "safe" }),
      );
      await client.checkTrust("p", "mcp_server");
      const url = fetchMock.mock.calls[0][0] as string;
      expect(url).toContain("type=mcp_server");
    });

    it("sets found=true when packageId is a real id", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ packageId: "uuid-123", name: "p", trustLevel: 3, trustScore: 0.8, verdict: "safe" }),
      );
      const r = await client.checkTrust("p");
      expect(r.found).toBe(true);
    });

    it("sets found=false when packageId is missing", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ name: "p", trustLevel: 0, trustScore: 0, verdict: "unknown" }),
      );
      const r = await client.checkTrust("p");
      expect(r.found).toBe(false);
    });

    it("sets found=false when packageId is the NULL UUID", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({
          packageId: "00000000-0000-0000-0000-000000000000",
          name: "p",
          trustLevel: 0,
          trustScore: 0,
          verdict: "unknown",
        }),
      );
      const r = await client.checkTrust("p");
      expect(r.found).toBe(false);
    });

    it("passes server-computed trustLevel through unchanged (no client math)", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ packageId: "x", name: "p", trustLevel: 4, trustScore: 0.92, verdict: "trusted" }),
      );
      const r = await client.checkTrust("p");
      expect(r.trustLevel).toBe(4);
      expect(r.trustScore).toBe(0.92);
    });

    it("sends Accept + User-Agent headers", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ name: "p", trustLevel: 0, trustScore: 0, verdict: "unknown" }),
      );
      await client.checkTrust("p");
      const headers = fetchMock.mock.calls[0][1].headers as Record<string, string>;
      expect(headers["Accept"]).toBe("application/json");
      expect(headers["User-Agent"]).toBe(UA);
    });

    it("throws PackageNotFoundError on 404", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ error: "nope" }, 404));
      await expect(client.checkTrust("bad")).rejects.toBeInstanceOf(
        PackageNotFoundError,
      );
    });

    it("throws RegistryApiError with server_error code on 5xx", async () => {
      fetchMock.mockResolvedValue(jsonResponse("boom", 500));
      try {
        await client.checkTrust("p");
        throw new Error("should not reach");
      } catch (err) {
        expect(err).toBeInstanceOf(RegistryApiError);
        const apiErr = err as RegistryApiError;
        expect(apiErr.code).toBe("server_error");
        expect(apiErr.statusCode).toBe(500);
      }
    });

    it("maps 429 to rate_limited", async () => {
      fetchMock.mockResolvedValue(jsonResponse("slow down", 429));
      await expect(client.checkTrust("p")).rejects.toMatchObject({
        name: "RegistryApiError",
        code: "rate_limited",
        statusCode: 429,
      });
    });

    it("maps 401 to unauthorized", async () => {
      fetchMock.mockResolvedValue(jsonResponse("auth", 401));
      await expect(client.checkTrust("p")).rejects.toMatchObject({
        code: "unauthorized",
      });
    });

    it("wraps fetch network errors as RegistryApiError.network", async () => {
      fetchMock.mockRejectedValue(new TypeError("socket closed"));
      try {
        await client.checkTrust("p");
        throw new Error("should not reach");
      } catch (err) {
        expect(err).toBeInstanceOf(RegistryApiError);
        expect((err as RegistryApiError).code).toBe("network");
      }
    });

    it("wraps AbortError as RegistryApiError.timeout", async () => {
      const abort = new Error("aborted");
      abort.name = "AbortError";
      fetchMock.mockRejectedValue(abort);
      try {
        await client.checkTrust("p");
        throw new Error("should not reach");
      } catch (err) {
        expect(err).toBeInstanceOf(RegistryApiError);
        expect((err as RegistryApiError).code).toBe("timeout");
      }
    });

    it("caches repeat checkTrust calls by name+type", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ packageId: "x", name: "p", trustLevel: 3, trustScore: 0.8, verdict: "safe" }),
      );
      await client.checkTrust("p");
      await client.checkTrust("p");
      await client.checkTrust("p", "mcp_server"); // different key
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it("cache:false disables caching", async () => {
      const c = new RegistryClient({
        baseUrl: "https://api.example.com",
        userAgent: UA,
        cache: false,
        fetch: fetchMock as unknown as typeof fetch,
      });
      fetchMock.mockResolvedValue(
        jsonResponse({ packageId: "x", name: "p", trustLevel: 3, trustScore: 0.8, verdict: "safe" }),
      );
      await c.checkTrust("p");
      await c.checkTrust("p");
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it("clearCache forces refetch", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ packageId: "x", name: "p", trustLevel: 3, trustScore: 0.8, verdict: "safe" }),
      );
      await client.checkTrust("p");
      client.clearCache();
      await client.checkTrust("p");
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });

  describe("batchQuery", () => {
    it("POSTs to /batch with correct body", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({
          results: [
            { packageId: "a", name: "pkg-a", trustLevel: 3, trustScore: 0.8, verdict: "safe" },
          ],
          total: 1,
          queriedAt: "2026-01-01T00:00:00Z",
        }),
      );
      await client.batchQuery([{ name: "pkg-a" }]);
      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toContain("/api/v1/trust/batch");
      expect(init.method).toBe("POST");
      expect(JSON.parse(init.body as string)).toEqual({
        packages: [{ name: "pkg-a" }],
      });
    });

    it("computes meta.found and meta.notFound", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({
          results: [
            { packageId: "a", name: "pkg-a", trustLevel: 3, trustScore: 0.8, verdict: "safe" },
            { name: "pkg-b", trustLevel: 0, trustScore: 0, verdict: "unknown" },
          ],
          total: 2,
          queriedAt: "2026-01-01T00:00:00Z",
        }),
      );
      const r = await client.batchQuery([{ name: "pkg-a" }, { name: "pkg-b" }]);
      expect(r.meta).toEqual({ total: 2, found: 1, notFound: 1 });
    });

    it("treats null UUID as not found", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({
          results: [
            {
              packageId: "00000000-0000-0000-0000-000000000000",
              name: "ghost",
              trustLevel: 0,
              trustScore: 0,
              verdict: "unknown",
            },
          ],
          total: 1,
          queriedAt: "2026-01-01T00:00:00Z",
        }),
      );
      const r = await client.batchQuery([{ name: "ghost" }]);
      expect(r.results[0].found).toBe(false);
      expect(r.meta.notFound).toBe(1);
    });

    it("caches repeat batchQuery calls regardless of input order", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({
          results: [
            { packageId: "a", name: "a", trustLevel: 3, trustScore: 0.8, verdict: "safe" },
            { packageId: "b", name: "b", trustLevel: 3, trustScore: 0.8, verdict: "safe" },
          ],
          total: 2,
          queriedAt: "2026-01-01T00:00:00Z",
        }),
      );
      await client.batchQuery([{ name: "a" }, { name: "b" }]);
      await client.batchQuery([{ name: "b" }, { name: "a" }]);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("throws RegistryApiError on non-OK", async () => {
      fetchMock.mockResolvedValue(jsonResponse("oops", 500));
      await expect(client.batchQuery([{ name: "p" }])).rejects.toBeInstanceOf(
        RegistryApiError,
      );
    });
  });

  describe("publishScan", () => {
    it("POSTs to /publish and never caches", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ accepted: true, publishId: "pub-1" }),
      );
      const submission = {
        name: "pkg",
        score: 95,
        maxScore: 100,
        findings: [],
        tool: "hackmyagent",
        toolVersion: "0.18.0",
        scanTimestamp: "2026-01-01T00:00:00Z",
      };
      await client.publishScan(submission);
      await client.publishScan(submission);
      expect(fetchMock).toHaveBeenCalledTimes(2);
      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toContain("/api/v1/trust/publish");
      expect(init.method).toBe("POST");
    });

    it("surfaces server error codes", async () => {
      fetchMock.mockResolvedValue(jsonResponse("rate", 429));
      await expect(
        client.publishScan({
          name: "p",
          score: 0,
          maxScore: 100,
          findings: [],
          tool: "x",
          toolVersion: "0.0.0",
          scanTimestamp: "2026-01-01T00:00:00Z",
        }),
      ).rejects.toMatchObject({ code: "rate_limited", statusCode: 429 });
    });
  });
});
