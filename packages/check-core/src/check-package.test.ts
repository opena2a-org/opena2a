import { describe, it, expect, vi } from "vitest";
import { checkPackage } from "./check-package.js";
import type { ScanResult, TrustData } from "./types.js";

const foundRegistry: TrustData = {
  found: true,
  name: "@modelcontextprotocol/server-filesystem",
  trustScore: 0.82,
  trustLevel: 3,
  verdict: "warnings",
  scanStatus: "passed",
  packageType: "mcp_server",
};

const missingRegistry: TrustData = {
  found: false,
  name: "ghost",
  trustScore: 0,
  trustLevel: 0,
  verdict: "unknown",
};

const okScan: ScanResult = {
  projectType: "mcp-server",
  score: 100,
  maxScore: 100,
  findings: [],
};

describe("checkPackage — orchestrator", () => {
  it("returns found when registry has data", async () => {
    const res = await checkPackage({
      target: "@modelcontextprotocol/server-filesystem",
      mode: "scan-on-miss",
      registry: async () => foundRegistry,
    });
    expect(res.kind).toBe("found");
    if (res.kind === "found") {
      expect(res.output.source).toBe("registry");
      expect(res.output.trustLevel).toBe(3);
      expect(res.output.name).toBe(foundRegistry.name);
    }
  });

  it("registry-only mode → not-found when registry misses", async () => {
    const res = await checkPackage({
      target: "ghost",
      mode: "registry-only",
      registry: async () => missingRegistry,
    });
    expect(res.kind).toBe("not-found");
    if (res.kind === "not-found") {
      expect(res.output.name).toBe("ghost");
      expect(res.output.ecosystem).toBe("npm");
    }
  });

  it("scan-on-miss mode → runs scan on registry miss and returns source=local-scan", async () => {
    const scan = vi.fn(async () => okScan);
    const res = await checkPackage({
      target: "ghost",
      mode: "scan-on-miss",
      registry: async () => missingRegistry,
      scan,
    });
    expect(scan).toHaveBeenCalledWith("ghost");
    expect(res.kind).toBe("found");
    if (res.kind === "found") {
      expect(res.output.source).toBe("local-scan");
      expect(res.output.score).toBe(100);
    }
  });

  it("scan error with git-style name + code 128 → translated not-found", async () => {
    const scan = vi.fn(async () => {
      throw new Error("npm ERR! code 128 git clone failed");
    });
    const res = await checkPackage({
      target: "anthropic/code-review",
      mode: "scan-on-miss",
      registry: async () => missingRegistry,
      scan,
    });
    expect(res.kind).toBe("not-found");
    if (res.kind === "not-found") {
      expect(res.output.errorHint).toContain("@anthropic/code-review");
      expect(res.output.suggestions).toEqual(["@anthropic/code-review"]);
    }
  });

  it("registry error does not abort — scan adapter still runs in scan-on-miss mode", async () => {
    const scan = vi.fn(async () => okScan);
    const res = await checkPackage({
      target: "express",
      mode: "scan-on-miss",
      registry: async () => {
        throw new Error("HTTP 500 from registry");
      },
      scan,
    });
    expect(scan).toHaveBeenCalled();
    expect(res.kind).toBe("found");
  });

  it("skill fallback used when no scan adapter and registry misses", async () => {
    const skillFallback = vi.fn(async () => ({
      name: "@anthropic/code-review",
    }));
    const res = await checkPackage({
      target: "@anthropic/code-review",
      mode: "scan-on-miss",
      registry: async () => missingRegistry,
      skillFallback,
    });
    expect(skillFallback).toHaveBeenCalled();
    expect(res.kind).toBe("found");
    if (res.kind === "found") {
      expect(res.output.source).toBe("skill");
      expect(res.output.type).toBe("skill");
    }
  });

  it("skill fallback returning null yields not-found", async () => {
    const skillFallback = vi.fn(async () => null);
    const res = await checkPackage({
      target: "nothing",
      mode: "scan-on-miss",
      registry: async () => missingRegistry,
      skillFallback,
    });
    expect(res.kind).toBe("not-found");
  });

  it("registry-only mode never calls the scan adapter even if present", async () => {
    const scan = vi.fn(async () => okScan);
    await checkPackage({
      target: "ghost",
      mode: "registry-only",
      registry: async () => missingRegistry,
      scan,
    });
    expect(scan).not.toHaveBeenCalled();
  });

  it("passes the type filter through to the registry adapter", async () => {
    const registry = vi.fn(async () => foundRegistry);
    await checkPackage({
      target: "@modelcontextprotocol/server-filesystem",
      mode: "registry-only",
      type: "mcp_server",
      registry,
    });
    expect(registry).toHaveBeenCalledWith(
      "@modelcontextprotocol/server-filesystem",
      "mcp_server",
    );
  });

  it("parses pip: prefix and hands registry the stripped name", async () => {
    const registry = vi.fn(async () => foundRegistry);
    await checkPackage({
      target: "pip:requests",
      mode: "registry-only",
      registry,
    });
    expect(registry).toHaveBeenCalledWith("requests", undefined);
  });
});
