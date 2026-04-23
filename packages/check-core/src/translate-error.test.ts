import { describe, it, expect } from "vitest";
import { translateDownloadError } from "./translate-error.js";

describe("translateDownloadError", () => {
  // Merged cases from hackmyagent/src/check-render.ts (translateNpmPackError)
  // + ai-trust/src/output/formatter.ts (translateDownloadError).

  describe("git-style name + code 128", () => {
    it("suggests the scoped form", () => {
      const out = translateDownloadError("anthropic/code-review", "npm ERR! code 128");
      expect(out).toEqual({
        errorHint: `Looks like a git-style name. npm packages use "@scope/name" — did you mean "@anthropic/code-review"?`,
        suggestions: ["@anthropic/code-review"],
      });
    });

    it("handles case-insensitive code 128 phrasing", () => {
      const out = translateDownloadError("foo/bar", "error: CODE 128 from git");
      expect(out?.suggestions).toEqual(["@foo/bar"]);
    });

    it("handles 'code  128' with extra whitespace", () => {
      const out = translateDownloadError("foo/bar", "died: code  128");
      expect(out?.suggestions).toEqual(["@foo/bar"]);
    });

    it("does not trigger on an already-scoped name even with code 128", () => {
      const out = translateDownloadError("@anthropic/code-review", "code 128");
      // @-scoped names are legit npm — don't suggest adding another @
      expect(out).toBeUndefined();
    });

    it("does not trigger on a bare name with code 128", () => {
      const out = translateDownloadError("express", "code 128");
      expect(out).toBeUndefined();
    });
  });

  describe("clean not-found messages", () => {
    it("returns empty hint object for 'not found on npm'", () => {
      const out = translateDownloadError("ghost-pkg", `Package "ghost-pkg" not found on npm`);
      expect(out).toEqual({});
    });

    it("returns empty hint object for 'not found on pypi'", () => {
      const out = translateDownloadError("ghost-pkg", `Package "ghost-pkg" not found on PyPI`);
      expect(out).toEqual({});
    });

    it("returns empty hint for case-insensitive pypi miss", () => {
      const out = translateDownloadError("ghost", "Found? no — NOT FOUND ON pypi anywhere");
      expect(out).toEqual({});
    });
  });

  describe("unrecognized messages", () => {
    it("returns undefined for a generic network error", () => {
      const out = translateDownloadError("express", "ETIMEDOUT reading registry");
      expect(out).toBeUndefined();
    });

    it("returns undefined when message is empty", () => {
      const out = translateDownloadError("express", "");
      expect(out).toBeUndefined();
    });
  });
});
