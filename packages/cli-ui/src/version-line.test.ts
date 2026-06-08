import { describe, it, expect, beforeEach } from "vitest";
import chalk from "chalk";
import { versionLine, versionLineParts } from "./version-line.js";

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

describe("versionLineParts", () => {
  it("puts the bare version on stdout and nothing on stderr without telemetry", () => {
    const v = versionLineParts({ tool: "dvaa", version: "0.8.1" });
    expect(v.stdout).toBe("dvaa 0.8.1");
    expect(v.stderr).toBeNull();
  });

  it("keeps stdout a clean single line and routes the disclosure to stderr", () => {
    const v = versionLineParts({
      tool: "ai-trust",
      version: "0.7.4",
      telemetry: { enabled: true, policyURL: "https://opena2a.org/telemetry" },
    });
    // stdout is script-clean: exactly the version, no telemetry, no newline.
    expect(v.stdout).toBe("ai-trust 0.7.4");
    expect(v.stdout).not.toContain("Telemetry");
    expect(v.stdout).not.toContain("\n");
    // The disclosure is preserved, just on stderr.
    expect(v.stderr).toContain("Telemetry: on");
    expect(v.stderr).toContain("opena2a.org/telemetry");
    expect(v.stderr).toContain("OPENA2A_TELEMETRY=off");
  });

  it("stdout matches the first line of the legacy versionLine (no drift)", () => {
    const input = {
      tool: "hma",
      version: "0.23.9",
      telemetry: { enabled: false, policyURL: "https://opena2a.org/telemetry" },
    };
    expect(versionLineParts(input).stdout).toBe(versionLine(input).split("\n")[0]);
  });
});
