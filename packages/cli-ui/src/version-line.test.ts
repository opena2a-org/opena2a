import { describe, it, expect, beforeEach } from "vitest";
import chalk from "chalk";
import { versionLine } from "./version-line.js";

beforeEach(() => {
  // Force chalk to emit ANSI codes deterministically for matching, then strip
  // them in assertions where we only care about the text content.
  chalk.level = 0;
});

describe("versionLine", () => {
  it("returns just the head line when telemetry omitted", () => {
    expect(versionLine({ tool: "dvaa", version: "0.8.1" })).toBe("dvaa 0.8.1");
  });

  it("appends 'on' line when telemetry enabled", () => {
    const out = versionLine({
      tool: "dvaa",
      version: "0.8.1",
      telemetry: { enabled: true, policyURL: "https://opena2a.org/telemetry" },
    });
    expect(out).toContain("dvaa 0.8.1");
    expect(out).toContain("Telemetry: on");
    expect(out).toContain("opena2a.org/telemetry");
    expect(out).toContain("OPENA2A_TELEMETRY=off");
  });

  it("appends 'off' line when telemetry disabled", () => {
    const out = versionLine({
      tool: "hma",
      version: "0.18.0",
      telemetry: { enabled: false, policyURL: "https://opena2a.org/telemetry" },
    });
    expect(out).toContain("Telemetry: off");
  });

  it("strips the URL scheme so the line stays compact", () => {
    const out = versionLine({
      tool: "ai-trust",
      version: "0.3.0",
      telemetry: { enabled: true, policyURL: "https://opena2a.org/telemetry" },
    });
    expect(out).not.toContain("https://");
    expect(out).toContain("opena2a.org/telemetry");
  });
});
