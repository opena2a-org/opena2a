/**
 * OPA-03.AC3 — self-test of the front-door conformance runner against the
 * two committed fixture binaries in test-fixtures/ (plain Node scripts,
 * no build): one conforming, one violating every property in turn. A
 * runner that reports pass on the violating fixture fails this criterion.
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { frontDoorConformance } from "./conformance.js";

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../test-fixtures");

const ALL_PROPERTIES = [
  "verdict-first-line",
  "json-envelope-parity",
  "exit-code-parity",
  "no-ansi-when-disabled",
  "commands-parse-against-help",
];

describe("frontDoorConformance self-test (OPA-03.AC3)", () => {
  it(
    "OPA-03.AC3 reports the conforming fixture all-pass across the five properties",
    async () => {
      const result = await frontDoorConformance({
        bin: path.join(FIXTURES, "conforming-cli.cjs"),
      });
      expect(result.properties.map((p) => p.property)).toEqual(ALL_PROPERTIES);
      const failed = result.properties.filter((p) => !p.pass);
      expect(failed, JSON.stringify(failed, null, 2)).toEqual([]);
      expect(result.pass).toBe(true);
    },
    30_000,
  );

  it(
    "OPA-03.AC3 names every violated property on the violating fixture",
    async () => {
      const result = await frontDoorConformance({
        bin: path.join(FIXTURES, "violating-cli.cjs"),
      });
      expect(result.pass).toBe(false);
      const failed = result.properties.filter((p) => !p.pass).map((p) => p.property);
      expect(failed).toEqual(ALL_PROPERTIES);
      for (const p of result.properties) {
        expect(p.observed.length).toBeGreaterThan(0);
      }
    },
    30_000,
  );

  it(
    "OPA-03.AC3 reports the observed value for each property, pass or fail",
    async () => {
      const result = await frontDoorConformance({
        bin: path.join(FIXTURES, "conforming-cli.cjs"),
      });
      const verdictLine = result.properties.find((p) => p.property === "verdict-first-line");
      expect(verdictLine?.observed).toContain("WARNING");
      const exitParity = result.properties.find((p) => p.property === "exit-code-parity");
      expect(exitParity?.observed).toContain("1");
    },
    30_000,
  );
});
