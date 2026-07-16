import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadConfig, setEnabled, configPaths, endpointURL, debugPrintEnabled, isCI, doNotTrack, DEFAULT_ENDPOINT } from "./config.js";
import { scrubSuppressionEnv, restoreSuppressionEnv, type SavedEnv } from "./test-support.js";

let tmpHome: string;
let savedEnv: SavedEnv;

beforeEach(() => {
  savedEnv = scrubSuppressionEnv();
  tmpHome = mkdtempSync(join(tmpdir(), "opena2a-telem-"));
  process.env.XDG_CONFIG_HOME = tmpHome;
  delete process.env.OPENA2A_TELEMETRY;
  delete process.env.OPENA2A_TELEMETRY_URL;
  delete process.env.OPENA2A_TELEMETRY_DEBUG;
});

afterEach(() => {
  restoreSuppressionEnv(savedEnv);
  rmSync(tmpHome, { recursive: true, force: true });
  delete process.env.XDG_CONFIG_HOME;
});

describe("configPaths", () => {
  it("uses XDG_CONFIG_HOME when set", () => {
    const { dir, file } = configPaths();
    expect(dir).toBe(join(tmpHome, "opena2a"));
    expect(file).toBe(join(tmpHome, "opena2a", "telemetry.json"));
  });
});

describe("loadConfig", () => {
  it("defaults to enabled on first run and persists install_id", () => {
    const { config, paths } = loadConfig();
    expect(config.enabled).toBe(true);
    expect(config.installId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(existsSync(paths.file)).toBe(true);
    const persisted = JSON.parse(readFileSync(paths.file, "utf8"));
    expect(persisted.installId).toBe(config.installId);
  });

  it("reuses install_id across calls", () => {
    const a = loadConfig().config.installId;
    const b = loadConfig().config.installId;
    expect(a).toBe(b);
  });

  it("env OPENA2A_TELEMETRY=off forces disabled even if file says enabled", () => {
    loadConfig(); // seed file with enabled=true
    process.env.OPENA2A_TELEMETRY = "off";
    expect(loadConfig().config.enabled).toBe(false);
  });

  it.each([["off"], ["false"], ["0"], ["no"], ["OFF"], ["False"]])(
    "env value %s disables",
    (val) => {
      process.env.OPENA2A_TELEMETRY = val;
      expect(loadConfig().config.enabled).toBe(false);
    },
  );

  it("file enabled=false is honored when env is unset", () => {
    setEnabled(false);
    expect(loadConfig().config.enabled).toBe(false);
  });

  it("file enabled=false with env=on still off (env can only force off, not on)", () => {
    setEnabled(false);
    process.env.OPENA2A_TELEMETRY = "on";
    // 'on' isn't in the disable list, so env doesn't force off; file says false → off
    expect(loadConfig().config.enabled).toBe(false);
  });

  it("recovers from a corrupt config file", () => {
    const { dir, file } = configPaths();
    mkdirSync(dir, { recursive: true });
    writeFileSync(file, "{not json");
    const result = loadConfig();
    expect(result.config.enabled).toBe(true);
    expect(result.config.installId).toBeTruthy();
  });
});

describe("isCI", () => {
  it("is false on a clean environment", () => {
    expect(isCI()).toBe(false);
  });

  it.each([["true"], ["1"], ["yes"], ["anything"]])("CI=%s is CI", (val) => {
    process.env.CI = val;
    expect(isCI()).toBe(true);
  });

  it.each([["false"], ["0"], ["no"], [""]])("CI=%s is not CI", (val) => {
    process.env.CI = val;
    expect(isCI()).toBe(false);
  });

  it.each([
    ["GITHUB_ACTIONS"],
    ["GITLAB_CI"],
    ["CIRCLECI"],
    ["BUILDKITE"],
    ["JENKINS_URL"],
    ["TF_BUILD"],
    ["VERCEL"],
  ])("%s presence marks CI even when CI is unset", (key) => {
    process.env[key] = "true";
    expect(isCI()).toBe(true);
  });

  it("reads the passed env rather than process.env", () => {
    expect(isCI({ CI: "true" } as NodeJS.ProcessEnv)).toBe(true);
    expect(isCI({} as NodeJS.ProcessEnv)).toBe(false);
  });
});

describe("doNotTrack", () => {
  it.each([["1"], ["true"], ["yes"]])("DO_NOT_TRACK=%s opts out", (val) => {
    process.env.DO_NOT_TRACK = val;
    expect(doNotTrack()).toBe(true);
  });

  it.each([["0"], ["false"], [""]])("DO_NOT_TRACK=%s does not opt out", (val) => {
    process.env.DO_NOT_TRACK = val;
    expect(doNotTrack()).toBe(false);
  });

  it("is false when unset", () => {
    expect(doNotTrack()).toBe(false);
  });
});

describe("loadConfig automatic suppression", () => {
  // Regression guard for the metric bug this suppression exists to fix:
  // CI runners are ephemeral (no machine-id, fresh hostname per job), so
  // every run minted a new install_id and inflated distinct-install and
  // active-user counts with our own pipelines.
  it("CI suppresses telemetry despite default-on", () => {
    process.env.CI = "true";
    expect(loadConfig().config.enabled).toBe(false);
  });

  it("DO_NOT_TRACK suppresses telemetry despite default-on", () => {
    process.env.DO_NOT_TRACK = "1";
    expect(loadConfig().config.enabled).toBe(false);
  });

  it.each([["on"], ["1"], ["true"], ["yes"]])(
    "OPENA2A_TELEMETRY=%s re-enables in CI (escape hatch for our own e2e)",
    (val) => {
      process.env.CI = "true";
      process.env.OPENA2A_TELEMETRY = val;
      expect(loadConfig().config.enabled).toBe(true);
    },
  );

  it("OPENA2A_TELEMETRY=on does NOT override DO_NOT_TRACK", () => {
    // DO_NOT_TRACK is a deliberate user intent, not an environmental fact.
    // A wrapper script, Makefile, Dockerfile ENV or org-wide CI config that
    // exports OPENA2A_TELEMETRY=on must never silently re-enable tracking
    // for a user who set DO_NOT_TRACK in their shell profile and never
    // touched OPENA2A_TELEMETRY at all.
    process.env.DO_NOT_TRACK = "1";
    process.env.OPENA2A_TELEMETRY = "on";
    expect(loadConfig().config.enabled).toBe(false);
  });

  it("DO_NOT_TRACK still wins when CI is also present and opt-in is set", () => {
    process.env.CI = "true";
    process.env.DO_NOT_TRACK = "1";
    process.env.OPENA2A_TELEMETRY = "on";
    const { config, suppressedBy } = loadConfig();
    expect(config.enabled).toBe(false);
    expect(suppressedBy).toBe("do-not-track");
  });

  it.each([["off "], [" off"], ["off\n"], ["\toff\t"]])(
    "OPENA2A_TELEMETRY=%j (untrimmed) still disables",
    (val) => {
      // Trailing whitespace/newlines are routine in .env files, compose
      // YAML and $(cmd) substitution. A privacy control must fail closed.
      process.env.OPENA2A_TELEMETRY = val;
      expect(loadConfig().config.enabled).toBe(false);
    },
  );

  it("DO_NOT_TRACK with surrounding whitespace still opts out", () => {
    process.env.DO_NOT_TRACK = " 1 ";
    expect(loadConfig().config.enabled).toBe(false);
  });

  it("a deliberate file opt-out still wins over env=on in CI", () => {
    setEnabled(false);
    process.env.CI = "true";
    process.env.OPENA2A_TELEMETRY = "on";
    expect(loadConfig().config.enabled).toBe(false);
  });

  it("env=off still wins over env-based re-enable paths", () => {
    process.env.CI = "true";
    process.env.OPENA2A_TELEMETRY = "off";
    expect(loadConfig().config.enabled).toBe(false);
  });

  it("does not persist CI suppression to the config file", () => {
    process.env.CI = "true";
    const { config, paths } = loadConfig();
    expect(config.enabled).toBe(false);
    // The file records the user's choice, not where the process ran —
    // otherwise one CI run would poison a developer's real config.
    const persisted = JSON.parse(readFileSync(paths.file, "utf8"));
    expect(persisted.enabled).toBe(true);

    delete process.env.CI;
    expect(loadConfig().config.enabled).toBe(true);
  });

  it("still persists a stable install_id while suppressed", () => {
    process.env.CI = "true";
    const a = loadConfig().config.installId;
    const b = loadConfig().config.installId;
    expect(a).toBe(b);
  });
});

describe("setEnabled", () => {
  it("flips the flag and preserves install_id", () => {
    const original = loadConfig().config.installId;
    const flipped = setEnabled(false);
    expect(flipped.enabled).toBe(false);
    expect(flipped.installId).toBe(original);
    expect(loadConfig().config.installId).toBe(original);
  });
});

describe("endpointURL", () => {
  it("defaults to api.oa2a.org canonical ingest route", () => {
    expect(endpointURL()).toBe(DEFAULT_ENDPOINT);
    expect(DEFAULT_ENDPOINT).toContain("/api/v1/telemetry/v1/event");
    // Regression guard: the default MUST NOT carry the `/registry/` prefix.
    // Registry #283 moved ingest off `/api/v1/registry/telemetry/v1/event`;
    // shipping that path again silently 404s all first-party telemetry until
    // the back-compat alias (#299) is retired.
    expect(DEFAULT_ENDPOINT).not.toContain("/registry/");
  });

  it("env OPENA2A_TELEMETRY_URL overrides", () => {
    process.env.OPENA2A_TELEMETRY_URL = "http://localhost:8088/api/v1/telemetry/v1/event";
    expect(endpointURL()).toBe("http://localhost:8088/api/v1/telemetry/v1/event");
  });
});

describe("debugPrintEnabled", () => {
  it("only true when env=print", () => {
    expect(debugPrintEnabled()).toBe(false);
    process.env.OPENA2A_TELEMETRY_DEBUG = "print";
    expect(debugPrintEnabled()).toBe(true);
    process.env.OPENA2A_TELEMETRY_DEBUG = "PRINT";
    expect(debugPrintEnabled()).toBe(true);
    process.env.OPENA2A_TELEMETRY_DEBUG = "verbose";
    expect(debugPrintEnabled()).toBe(false);
  });
});
