import { describe, expect, it } from "vitest";
import { sanitizeArray, sanitizeForTerminal } from "./terminal-safe.js";

describe("sanitizeForTerminal", () => {
  it("returns empty string for undefined / null", () => {
    expect(sanitizeForTerminal(undefined)).toBe("");
    expect(sanitizeForTerminal(null)).toBe("");
  });

  it("returns empty string unchanged", () => {
    expect(sanitizeForTerminal("")).toBe("");
  });

  it("passes plain text through unchanged", () => {
    expect(sanitizeForTerminal("opena2a/code-review-skill")).toBe(
      "opena2a/code-review-skill",
    );
    expect(sanitizeForTerminal("multi\nline\ttab")).toBe("multi\nline\ttab");
  });

  it("strips CSI clear-screen / cursor-home", () => {
    expect(sanitizeForTerminal("before\x1b[2J\x1b[Hafter")).toBe("beforeafter");
  });

  it("strips CSI color codes", () => {
    expect(sanitizeForTerminal("\x1b[31mred\x1b[0m text")).toBe("red text");
  });

  it("strips OSC-8 hyperlinks (BEL terminator)", () => {
    const malicious =
      "Rotate at \x1b]8;;https://evil.example/\x07evil-link\x1b]8;;\x07.";
    expect(sanitizeForTerminal(malicious)).toBe("Rotate at evil-link.");
  });

  it("strips OSC sequences with ST terminator", () => {
    const malicious = "before\x1b]0;title\x1b\\after";
    expect(sanitizeForTerminal(malicious)).toBe("beforeafter");
  });

  it("strips bell, NUL, and other C0 controls but preserves \\n and \\t", () => {
    expect(sanitizeForTerminal("a\x00b\x07c\rd\x1ee")).toBe("abcde");
    expect(sanitizeForTerminal("keep\nthis\tplease")).toBe("keep\nthis\tplease");
  });

  it("strips DEL (0x7f)", () => {
    expect(sanitizeForTerminal("a\x7fb")).toBe("ab");
  });

  it("strips lone ESC (no follow-up)", () => {
    expect(sanitizeForTerminal("a\x1b")).toBe("a");
  });
});

describe("sanitizeArray", () => {
  it("returns empty array for undefined", () => {
    expect(sanitizeArray(undefined)).toEqual([]);
  });

  it("sanitizes each entry", () => {
    expect(
      sanitizeArray(["plain", "with\x1b[31mansi\x1b[0m", "\x07bell"]),
    ).toEqual(["plain", "withansi", "bell"]);
  });
});
