import { describe, it, expect, beforeEach, vi } from "vitest";
import chalk from "chalk";
import { runTelemetryCommand } from "./telemetry-command.js";

beforeEach(() => {
  chalk.level = 0;
});

function makeInput(
  overrides: { enabled?: boolean; suppressedBy?: "ci" | "do-not-track"; installId?: string | null } = {},
) {
  let enabled = overrides.enabled ?? true;
  return {
    tool: "dvaa",
    setOptOut: vi.fn((v: boolean) => {
      // Mirrors the real SDK: under automatic suppression the preference is
      // persisted but the effective state stays off.
      enabled = overrides.suppressedBy ? false : v;
    }),
    getStatus: () => ({
      enabled,
      policyURL: "https://opena2a.org/telemetry",
      configPath: "/home/user/.config/opena2a/telemetry.json",
      installId: overrides.installId === undefined ? "abc-123" : overrides.installId,
      ...(overrides.suppressedBy ? { suppressedBy: overrides.suppressedBy } : {}),
    }),
  };
}

describe("automatic suppression rendering", () => {
  // The dead end this guards: under CI suppression the old renderer printed
  // `state: off` with a `dvaa telemetry on` hint. That hint writes
  // enabled=true, changes nothing, and the next status still says off.
  it("explains CI suppression instead of suggesting a toggle that cannot work", () => {
    const out = runTelemetryCommand("status", makeInput({ enabled: false, suppressedBy: "ci" }));
    expect(out).toContain("CI environment detected");
    expect(out).toContain("you did not turn it off");
    expect(out).toContain("OPENA2A_TELEMETRY=on dvaa <cmd>");
    // The broken hint must not appear.
    expect(out).not.toContain("dvaa telemetry on'");
  });

  it("explains DO_NOT_TRACK suppression and offers a remedy that works", () => {
    const out = runTelemetryCommand(
      "status",
      makeInput({ enabled: false, suppressedBy: "do-not-track" }),
    );
    expect(out).toContain("DO_NOT_TRACK is set");
    expect(out).toContain("unset DO_NOT_TRACK");
    expect(out).not.toContain("dvaa telemetry on'");
    // OPENA2A_TELEMETRY=on does not override DO_NOT_TRACK, so suggesting it
    // here would be a second dead end.
    expect(out).not.toContain("OPENA2A_TELEMETRY=on");
    // DO_NOT_TRACK is the user's own choice — don't tell them they didn't.
    expect(out).not.toContain("you did not turn it off");
  });

  it("does not contradict itself when 'on' is run under suppression", () => {
    const out = runTelemetryCommand("on", makeInput({ enabled: false, suppressedBy: "ci" }));
    expect(out).toContain("Preference saved");
    expect(out).toContain("stays off");
    expect(out).toContain("state:       off");
    // The old header claimed "Telemetry enabled" directly above `state: off`.
    expect(out).not.toContain("Telemetry enabled for dvaa.");
  });

  it("a plain off state (user's own choice) keeps the normal toggle hint", () => {
    const out = runTelemetryCommand("status", makeInput({ enabled: false }));
    expect(out).toContain("dvaa telemetry on");
    expect(out).not.toContain("CI environment detected");
    expect(out).not.toContain("did not turn it off");
  });

  it("a persisted off state does NOT offer OPENA2A_TELEMETRY=on", () => {
    // Precedence rule 2: a config-file opt-out is re-enabled by nothing,
    // including OPENA2A_TELEMETRY=on. This hint only ever prints for an
    // off-state that came from that file, so offering the env var sent the
    // user round a loop landing on an identical, unexplained "off".
    const out = runTelemetryCommand("status", makeInput({ enabled: false }));
    expect(out).not.toContain("OPENA2A_TELEMETRY=on");
  });

  it("an on state still offers OPENA2A_TELEMETRY=off (that direction works)", () => {
    const out = runTelemetryCommand("status", makeInput({ enabled: true }));
    expect(out).toContain("dvaa telemetry off");
    expect(out).toContain("OPENA2A_TELEMETRY=off");
  });

  it("explains OPENA2A_TELEMETRY=off instead of suggesting a toggle it overrides", () => {
    // `telemetry on` cannot survive an env opt-out — env-off always wins —
    // so the old hint sent the user round a loop that always landed on off.
    const out = runTelemetryCommand(
      "status",
      makeInput({ enabled: false, suppressedBy: "env-opt-out" }),
    );
    expect(out).toContain("OPENA2A_TELEMETRY=off is set");
    expect(out).toContain("overrides the saved preference");
    expect(out).toContain("unset OPENA2A_TELEMETRY");
    expect(out).not.toContain("dvaa telemetry on'");
    expect(out).not.toContain("you did not turn it off");
  });

  it("'on' under an env opt-out explains why it did not take effect", () => {
    // Regression guard: this path printed "Preference saved, but telemetry
    // stays off for dvaa here." with no reason and no remedy — the word
    // "here" promising an explanation that never came.
    const out = runTelemetryCommand("on", makeInput({ enabled: false, suppressedBy: "env-opt-out" }));
    expect(out).toContain("Preference saved");
    expect(out).toContain("OPENA2A_TELEMETRY=off is set");
    expect(out).toContain("unset OPENA2A_TELEMETRY");
  });

  it("every suppression reason renders a remedy", () => {
    // NOT a fail-by-construction guard, despite appearances: the reason list
    // below is a hardcoded literal, so a new union member does not extend it.
    // The actual guard is the compiler — `SUPPRESSION_LABEL` /
    // `SUPPRESSION_EXPLANATION` are Record<SuppressionReason, string> and
    // `suppressionRemedy` is a switch with no default, so a fourth reason
    // fails tsc at all three sites. This is a characterization test: it pins
    // the rendered shape of the three reasons that exist today.
    for (const reason of ["ci", "do-not-track", "env-opt-out"] as const) {
      const out = runTelemetryCommand("status", makeInput({ enabled: false, suppressedBy: reason }));
      expect(out, `reason=${reason}`).toMatch(/override:|to re-enable:/);
      expect(out, `reason=${reason}`).not.toContain("dvaa telemetry on'");
    }
  });
});

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

  it("status says there is no install_id while telemetry is off", () => {
    const out = runTelemetryCommand(
      "status",
      makeInput({ enabled: false, suppressedBy: "do-not-track", installId: null }),
    );
    expect(out).toContain("install_id:  none (not kept while telemetry is off)");
    expect(out).not.toContain("null");
  });

  it("status hint suggests 'off' when telemetry is on", () => {
    const out = runTelemetryCommand("status", makeInput({ enabled: true }));
    expect(out).toContain("dvaa telemetry off");
    expect(out).toContain("OPENA2A_TELEMETRY=off");
    expect(out).not.toContain("dvaa telemetry on'");
    expect(out).not.toContain("OPENA2A_TELEMETRY=on");
  });

  it("status hint suggests 'on' when telemetry is off (papercut from DVAA 0.9.0 release-test)", () => {
    // The original papercut (#170) was hint DIRECTION: status suggested
    // turning telemetry *off* when it was already off. That guard is intact —
    // `dvaa telemetry on` is still suggested, and no "off" affordance appears.
    //
    // The `OPENA2A_TELEMETRY=on` assertion that used to live here was
    // incidental to that fix (the env hint merely mirrored the flip) and was
    // wrong: this hint only prints for an off-state that came from the config
    // file, and precedence rule 2 says nothing re-enables that — including
    // OPENA2A_TELEMETRY=on. Following it landed on an identical, unexplained
    // "off". Asserting its absence now.
    const out = runTelemetryCommand("status", makeInput({ enabled: false }));
    expect(out).toContain("dvaa telemetry on");
    expect(out).not.toContain("OPENA2A_TELEMETRY=on");
    expect(out).not.toContain("dvaa telemetry off'");
    expect(out).not.toContain("OPENA2A_TELEMETRY=off");
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

  it("'--help' prints usage instead of error (papercut from DVAA 0.9.0 release-test)", () => {
    const input = makeInput();
    const out = runTelemetryCommand("--help", input);
    expect(out).not.toContain("Unknown action");
    expect(out).toContain("dvaa telemetry [on|off|status]");
    expect(out).toContain("Inspect or toggle");
    expect(out).toContain("Actions:");
    expect(out).toContain("on        Enable telemetry");
    expect(out).toContain("off       Disable telemetry");
    expect(out).toContain("status    Show current state");
    expect(out).toContain("OPENA2A_TELEMETRY=off dvaa");
    expect(input.setOptOut).not.toHaveBeenCalled();
  });

  describe("contributor_token", () => {
    // Contributed scans reach the Registry keyed by this token and carry no
    // install_id, so a CLI that contributes must show it next to install_id.
    const SENTINEL = "c0ffee".repeat(10) + "beef";

    it("status prints the contributor token between install_id and config", () => {
      const getContributorToken = vi.fn(() => SENTINEL);
      const out = runTelemetryCommand("status", { ...makeInput(), getContributorToken });
      expect(out).toContain(`  contributor_token: ${SENTINEL}`);
      const lines = out.split("\n");
      const at = (prefix: string) => lines.findIndex((l) => l.startsWith(prefix));
      expect(at("  install_id:")).toBeGreaterThan(0);
      expect(at("  contributor_token:")).toBe(at("  install_id:") + 1);
      expect(at("  config:")).toBe(at("  contributor_token:") + 1);
      expect(getContributorToken).toHaveBeenCalledTimes(1);
    });

    it("'on' and 'off' print it too, since both render the status block", () => {
      for (const action of ["on", "off"] as const) {
        const out = runTelemetryCommand(action, {
          ...makeInput(),
          getContributorToken: () => SENTINEL,
        });
        expect(out, `action=${action}`).toContain(`contributor_token: ${SENTINEL}`);
      }
    });

    it("is omitted for a CLI that does not pass a token getter", () => {
      const out = runTelemetryCommand("status", makeInput());
      expect(out).not.toContain("contributor_token");
    });

    it("prints 'unavailable' instead of failing when the token cannot be derived", () => {
      const out = runTelemetryCommand("status", {
        ...makeInput(),
        getContributorToken: () => {
          throw new Error("EACCES: permission denied");
        },
      });
      expect(out).toContain("  contributor_token: unavailable");
      expect(out).not.toContain("EACCES");
      expect(out).toContain("  config:");
    });

    it("help lists contributor_token under status only when it is shown", () => {
      const withToken = runTelemetryCommand("--help", {
        ...makeInput(),
        getContributorToken: () => SENTINEL,
      });
      expect(withToken).toContain("install_id, contributor_token, config file");
      expect(withToken).not.toContain(SENTINEL);
      expect(runTelemetryCommand("--help", makeInput())).not.toContain("contributor_token");
    });
  });

  it("'-h' is an alias for '--help'", () => {
    const inputA = makeInput();
    const inputB = makeInput();
    const a = runTelemetryCommand("--help", inputA);
    const b = runTelemetryCommand("-h", inputB);
    expect(a).toBe(b);
    expect(inputA.setOptOut).not.toHaveBeenCalled();
    expect(inputB.setOptOut).not.toHaveBeenCalled();
  });
});
