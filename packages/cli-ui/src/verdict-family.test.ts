/**
 * The pass/fail/unverified verdict family: a check's own verdict renders
 * with the symbol and color of the registry family it mirrors (pass as
 * safe, fail as blocked) and unverified as a yellow `?`, and the printed
 * word carries the meaning when color is off.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import chalk from "chalk";
import { renderVerdict } from "./grammar.js";
import { normalizeVerdict, verdictColor, type CheckVerdict } from "./verdict.js";

const ANSI = /\x1b\[[0-9;?]*[\x40-\x7e]/g;
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";

describe("pass/fail/unverified verdict line, plain form", () => {
  it("prints each check verdict as its own word with its symbol", () => {
    const off = { color: false } as const;
    expect(renderVerdict({ verdict: "pass", summary: "3 checks passed" }, off)).toBe(
      "✔ PASS — 3 checks passed",
    );
    expect(renderVerdict({ verdict: "fail", summary: "event chain broken" }, off)).toBe(
      "✖ FAIL — event chain broken",
    );
    expect(renderVerdict({ verdict: "unverified", summary: "event log missing" }, off)).toBe(
      "? UNVERIFIED — event log missing",
    );
    expect(renderVerdict({ verdict: "unverified" }, off)).toBe("? UNVERIFIED");
  });

  it("keeps the check words apart from the registry words", () => {
    const words: CheckVerdict[] = ["pass", "fail", "unverified"];
    for (const word of words) {
      expect(normalizeVerdict(word)).toBe(word);
    }
    expect(normalizeVerdict("passed")).toBe("safe");
    expect(normalizeVerdict("failed")).toBe("blocked");
  });
});

describe("pass/fail/unverified verdict line, colored form", () => {
  beforeEach(() => {
    vi.stubEnv("NO_COLOR", "");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("paints pass as safe, fail as blocked and unverified yellow", () => {
    const on = { color: true } as const;
    expect(renderVerdict({ verdict: "pass" }, on).startsWith(`${GREEN}✔ PASS`)).toBe(true);
    expect(renderVerdict({ verdict: "fail" }, on).startsWith(`${RED}✖ FAIL`)).toBe(true);
    expect(renderVerdict({ verdict: "unverified" }, on).startsWith(`${YELLOW}? UNVERIFIED`)).toBe(
      true,
    );
    expect(renderVerdict({ verdict: "pass" }, on).replace("PASS", "SAFE")).toBe(
      renderVerdict({ verdict: "safe" }, on),
    );
    expect(renderVerdict({ verdict: "fail" }, on).replace("FAIL", "BLOCKED")).toBe(
      renderVerdict({ verdict: "blocked" }, on),
    );
  });

  it("drops every escape byte under NO_COLOR and leaves the word", () => {
    vi.stubEnv("NO_COLOR", "1");
    const on = { color: true } as const;
    for (const [word, line] of [
      ["pass", "✔ PASS — s"],
      ["fail", "✖ FAIL — s"],
      ["unverified", "? UNVERIFIED — s"],
    ] as const) {
      const out = renderVerdict({ verdict: word, summary: "s" }, on);
      expect(out).toBe(line);
      expect(out.match(ANSI)).toBeNull();
    }
  });
});

describe("verdictColor for the check family", () => {
  let savedLevel: typeof chalk.level;
  beforeEach(() => {
    savedLevel = chalk.level;
    chalk.level = 1;
  });
  afterEach(() => {
    chalk.level = savedLevel;
  });

  it("maps pass to green, fail to red and unverified to yellow", () => {
    expect(verdictColor("pass")("x")).toBe(`${GREEN}x\x1b[39m`);
    expect(verdictColor("fail")("x")).toBe(`${RED}x\x1b[39m`);
    expect(verdictColor("unverified")("x")).toBe(`${YELLOW}x\x1b[39m`);
    expect(verdictColor("pass")("x")).toBe(verdictColor("safe")("x"));
    expect(verdictColor("fail")("x")).toBe(verdictColor("blocked")("x"));
  });
});
