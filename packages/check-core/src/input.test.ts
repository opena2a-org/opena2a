import { describe, it, expect } from "vitest";
import { parseCheckInput, ecosystemToTargetType } from "./input.js";

describe("parseCheckInput", () => {
  it("classifies a scoped npm name", () => {
    const r = parseCheckInput("@modelcontextprotocol/server-filesystem");
    expect(r.ecosystem).toBe("npm");
    expect(r.normalizedName).toBe("@modelcontextprotocol/server-filesystem");
    expect(r.isScoped).toBe(true);
    expect(r.isGitShorthand).toBe(false);
  });

  it("classifies a bare npm name", () => {
    const r = parseCheckInput("express");
    expect(r.ecosystem).toBe("npm");
    expect(r.normalizedName).toBe("express");
    expect(r.isScoped).toBe(false);
    expect(r.isGitShorthand).toBe(false);
  });

  it("classifies a github shorthand as github", () => {
    const r = parseCheckInput("anthropic/code-review");
    expect(r.ecosystem).toBe("github");
    expect(r.normalizedName).toBe("anthropic/code-review");
    expect(r.isGitShorthand).toBe(true);
    expect(r.isScoped).toBe(false);
  });

  it("classifies a pip: prefixed name", () => {
    const r = parseCheckInput("pip:requests");
    expect(r.ecosystem).toBe("pypi");
    expect(r.normalizedName).toBe("requests");
    expect(r.isScoped).toBe(false);
  });

  it("classifies a local path (.)", () => {
    const r = parseCheckInput("./my-project");
    expect(r.ecosystem).toBe("local");
    expect(r.normalizedName).toBe("./my-project");
  });

  it("classifies an absolute local path (/)", () => {
    const r = parseCheckInput("/tmp/my-project");
    expect(r.ecosystem).toBe("local");
    expect(r.normalizedName).toBe("/tmp/my-project");
  });

  it("classifies a URL", () => {
    const r = parseCheckInput("https://github.com/a/b");
    expect(r.ecosystem).toBe("url");
    expect(r.normalizedName).toBe("https://github.com/a/b");
  });

  it("trims whitespace", () => {
    const r = parseCheckInput("  express  ");
    expect(r.ecosystem).toBe("npm");
    expect(r.normalizedName).toBe("express");
    // raw preserves the original
    expect(r.raw).toBe("  express  ");
  });

  it("is not scoped when name contains @ mid-string", () => {
    const r = parseCheckInput("foo@bar");
    expect(r.isScoped).toBe(false);
  });

  it("classifies totally malformed input as unknown", () => {
    const r = parseCheckInput("!!$$");
    expect(r.ecosystem).toBe("unknown");
  });
});

describe("ecosystemToTargetType", () => {
  it("maps npm → npm-package", () => {
    expect(ecosystemToTargetType("npm")).toBe("npm-package");
  });
  it("maps pypi → pypi-package", () => {
    expect(ecosystemToTargetType("pypi")).toBe("pypi-package");
  });
  it("maps github → github-repo", () => {
    expect(ecosystemToTargetType("github")).toBe("github-repo");
  });
  it("leaves local/url/unknown undefined", () => {
    expect(ecosystemToTargetType("local")).toBeUndefined();
    expect(ecosystemToTargetType("url")).toBeUndefined();
    expect(ecosystemToTargetType("unknown")).toBeUndefined();
  });
});
