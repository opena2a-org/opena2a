import { describe, it, expect } from "vitest";
import {
  classify,
  isAiTrustScope,
  isHmaRoute,
  tierLabel,
  isNativeType,
  isKnownUnrelatedName,
} from "./index.js";

describe("classify — registry package_type drives the decision", () => {
  it("mcp_server -> native", () => {
    const r = classify({ name: "@modelcontextprotocol/server-filesystem", packageType: "mcp_server" });
    expect(r.tier).toBe("native");
    expect(r.reasons).toEqual([]);
  });

  it("a2a_agent -> native", () => {
    const r = classify({ name: "@opena2a/aim-core", packageType: "a2a_agent" });
    expect(r.tier).toBe("native");
  });

  it("skill -> native", () => {
    const r = classify({ name: "example-skill", packageType: "skill" });
    expect(r.tier).toBe("native");
  });

  it("ai_tool -> native", () => {
    const r = classify({ name: "some-tool", packageType: "ai_tool" });
    expect(r.tier).toBe("native");
  });

  it("llm -> native", () => {
    const r = classify({ name: "some-model", packageType: "llm" });
    expect(r.tier).toBe("native");
  });

  it("library -> unrelated", () => {
    const r = classify({ name: "express", packageType: "library" });
    expect(r.tier).toBe("unrelated");
  });
});

describe("classify — name-based fallback when no registry type", () => {
  it("known unrelated name -> unrelated", () => {
    expect(classify({ name: "chalk" }).tier).toBe("unrelated");
    expect(classify({ name: "typescript" }).tier).toBe("unrelated");
    expect(classify({ name: "vitest" }).tier).toBe("unrelated");
    expect(classify({ name: "commander" }).tier).toBe("unrelated");
  });

  it("@types/* -> unrelated", () => {
    expect(classify({ name: "@types/node" }).tier).toBe("unrelated");
    expect(classify({ name: "@types/js-yaml" }).tier).toBe("unrelated");
  });

  it("unknown name with no type -> unknown", () => {
    const r = classify({ name: "some-random-pkg-xyz-999" });
    expect(r.tier).toBe("unknown");
  });
});

describe("classify — never false-classify an AI package as unrelated", () => {
  // The critical invariant: if we're unsure, return "unknown", not "unrelated".
  // A user auditing an AI project doesn't want their MCP server silently dropped.
  it("ambiguous packages return unknown, not unrelated", () => {
    const r = classify({ name: "custom-agent-runtime" });
    expect(r.tier).toBe("unknown");
    expect(r.tier).not.toBe("unrelated");
  });

  it("packageType takes precedence over name allowlist", () => {
    // If somehow a package named like a library is registered as mcp_server,
    // we trust the registry classification.
    const r = classify({ name: "lodash", packageType: "mcp_server" });
    expect(r.tier).toBe("native");
  });
});

describe("helpers", () => {
  it("isNativeType", () => {
    expect(isNativeType("mcp_server")).toBe(true);
    expect(isNativeType("library")).toBe(false);
    expect(isNativeType(undefined)).toBe(false);
  });

  it("isKnownUnrelatedName", () => {
    expect(isKnownUnrelatedName("chalk")).toBe(true);
    expect(isKnownUnrelatedName("@types/node")).toBe(true);
    expect(isKnownUnrelatedName("@modelcontextprotocol/sdk")).toBe(false);
  });

  it("isAiTrustScope only true for native", () => {
    expect(isAiTrustScope(classify({ name: "x", packageType: "mcp_server" }))).toBe(true);
    expect(isAiTrustScope(classify({ name: "chalk" }))).toBe(false);
    expect(isAiTrustScope(classify({ name: "unknown-pkg" }))).toBe(false);
  });

  it("isHmaRoute only true for unrelated", () => {
    expect(isHmaRoute(classify({ name: "chalk" }))).toBe(true);
    expect(isHmaRoute(classify({ name: "x", packageType: "mcp_server" }))).toBe(false);
    expect(isHmaRoute(classify({ name: "unknown-pkg" }))).toBe(false);
  });

  it("tierLabel", () => {
    expect(tierLabel("native")).toBe("AI package");
    expect(tierLabel("unrelated")).toBe("library");
    expect(tierLabel("unknown")).toBe("unknown");
  });
});
