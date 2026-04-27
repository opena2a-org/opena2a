import { describe, it, expect, beforeEach, vi } from "vitest";
import chalk from "chalk";
import { runTelemetryCommand } from "./telemetry-command.js";

beforeEach(() => {
  chalk.level = 0;
});

function makeInput(overrides: { enabled?: boolean } = {}) {
  let enabled = overrides.enabled ?? true;
  return {
    tool: "dvaa",
    setOptOut: vi.fn((v: boolean) => {
      enabled = v;
    }),
    getStatus: () => ({
      enabled,
      policyURL: "https://opena2a.org/telemetry",
      configPath: "/home/user/.config/opena2a/telemetry.json",
      installId: "abc-123",
    }),
  };
}

describe("runTelemetryCommand", () => {
  it("status (no action) prints current state and toggle hint", () => {
    const input = makeInput();
    const out = runTelemetryCommand(undefined, input);
    expect(out).toContain("dvaa telemetry");
    expect(out).toContain("state:");
    expect(out).toContain("on");
    expect(out).toContain("install_id:");
    expect(out).toContain("abc-123");
    expect(out).toContain("policy:");
    expect(out).toContain("opena2a.org/telemetry");
    expect(out).toContain("OPENA2A_TELEMETRY=off");
    expect(input.setOptOut).not.toHaveBeenCalled();
  });

  it("'status' action behaves the same as no action", () => {
    const a = runTelemetryCommand(undefined, makeInput());
    const b = runTelemetryCommand("status", makeInput());
    expect(a).toBe(b);
  });

  it("'on' action calls setOptOut(true) and prints enabled framing", () => {
    const input = makeInput({ enabled: false });
    const out = runTelemetryCommand("on", input);
    expect(input.setOptOut).toHaveBeenCalledWith(true);
    expect(out).toContain("Telemetry enabled for dvaa.");
  });

  it("'off' action calls setOptOut(false) and prints disabled framing", () => {
    const input = makeInput({ enabled: true });
    const out = runTelemetryCommand("off", input);
    expect(input.setOptOut).toHaveBeenCalledWith(false);
    expect(out).toContain("Telemetry disabled for dvaa.");
  });

  it("unknown action returns an error string and does not toggle", () => {
    const input = makeInput();
    // @ts-expect-error — testing the runtime guard
    const out = runTelemetryCommand("nuke", input);
    expect(out).toContain("Unknown action 'nuke'");
    expect(out).toContain("[on|off|status]");
    expect(input.setOptOut).not.toHaveBeenCalled();
  });
});
