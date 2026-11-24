import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { CHECK_FIELD_GUIDE, checkJsonSchema } from "./check-json-schema.js";

/**
 * The check --json contract names every scanStatus value the Registry
 * serves, and null for a version with no Registry result, one line per
 * value. A status the Registry no longer serves is not presented as one.
 */

// The scan statuses the Registry serves for a version.
const SERVED = ["passed", "warnings", "failed", "not_applicable"] as const;
const NULL_MEANING = "no Registry result";
// The retired list, built at run time so a text search of this package for it finds nothing.
const RETIRED_LIST = ["pending", "completed", "warnings", "failed"].join(", ");
const RETIRED_AS_VALUE = /["`](pending|completed)["`]/;

const SOURCE = readFileSync(new URL("./check-json-schema.ts", import.meta.url), "utf8");

function axisNote(): string {
  const start = SOURCE.indexOf("REGISTRY-SCAN-STATE axis");
  const end = SOURCE.indexOf("## Which field do I gate CI on?", start);
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  return SOURCE.slice(start, end);
}

function expectOneLinePerValue(text: string): void {
  const lines = text.split("\n");
  for (const value of SERVED) {
    expect(lines.filter((line) => line.includes(`"${value}"`))).toHaveLength(1);
  }
  const nullLines = lines.filter((line) => line.includes(NULL_MEANING));
  expect(nullLines).toHaveLength(1);
  expect(nullLines[0]).toContain("null");
  for (const line of lines) {
    const named =
      SERVED.filter((value) => line.includes(`"${value}"`)).length +
      (line.includes(NULL_MEANING) ? 1 : 0);
    expect(named).toBeLessThanOrEqual(1);
  }
}

const TEXTS: ReadonlyArray<[string, () => string]> = [
  ["field guide description", () => CHECK_FIELD_GUIDE.scanStatus.description],
  ["JSON Schema description", () => checkJsonSchema.properties.scanStatus.description],
];

describe("check --json scanStatus description", () => {
  for (const [where, read] of TEXTS) {
    it(`${where}: names every served value and null, one line per value`, () => {
      expectOneLinePerValue(read());
    });

    it(`${where}: presents no retired status as a served value`, () => {
      expect(read()).not.toContain(RETIRED_LIST);
      expect(read()).not.toMatch(RETIRED_AS_VALUE);
    });
  }

  it("stays on the registry axis, orthogonal to the local score", () => {
    expect(CHECK_FIELD_GUIDE.scanStatus.source).toBe("registry");
    expect(CHECK_FIELD_GUIDE.scanStatus.description).toContain("Orthogonal to the local `score`");
  });
});

describe("check --json scanStatus axis note", () => {
  it("names every served value and null, one line per value", () => {
    expectOneLinePerValue(axisNote());
  });

  it("presents no retired status as a served value", () => {
    expect(axisNote()).not.toMatch(RETIRED_AS_VALUE);
  });
});
