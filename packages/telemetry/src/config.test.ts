import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync, symlinkSync } from "node:fs";
import { join, parse } from "node:path";
import { tmpdir } from "node:os";
import { loadConfig, setEnabled, configPaths, endpointURL, debugPrintEnabled, isCI, isTestRunner, isEphemeralHome, doNotTrack, DEFAULT_ENDPOINT } from "./config.js";
import { scrubSuppressionEnv, restoreSuppressionEnv, markPersistent, markTemporary, type SavedEnv } from "./test-support.js";

let tmpHome: string;
let savedEnv: SavedEnv;

beforeEach(() => {
  savedEnv = scrubSuppressionEnv();
  tmpHome = mkdtempSync(join(tmpdir(), "opena2a-telem-"));
  markPersistent(tmpHome);
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

describe("isTestRunner", () => {
  it("is false on a clean environment", () => {
    expect(isTestRunner()).toBe(false);
  });

  it.each([
    ["VITEST", "true"],
    ["JEST_WORKER_ID", "1"],
    ["NODE_TEST_CONTEXT", "child"],
    ["NODE_TEST_CONTEXT", "child-v8"],
  ])("%s=%s marks a test runner", (key, val) => {
    process.env[key] = val;
    expect(isTestRunner()).toBe(true);
  });

  it.each([["false"], ["0"], [""]])("VITEST=%j is not a test runner", (val) => {
    process.env.VITEST = val;
    expect(isTestRunner()).toBe(false);
  });

  it("does not treat NODE_ENV=test as a test runner", () => {
    expect(isTestRunner({ NODE_ENV: "test" } as NodeJS.ProcessEnv)).toBe(false);
  });

  it("reads the passed env rather than process.env", () => {
    expect(isTestRunner({ VITEST: "true" } as NodeJS.ProcessEnv)).toBe(true);
    expect(isTestRunner({} as NodeJS.ProcessEnv)).toBe(false);
  });
});

describe("isEphemeralHome", () => {
  let root: string;
  let persistent: string;

  beforeEach(() => {
    root = join(tmpHome, "temp-root");
    persistent = join(tmpHome, "persistent");
    mkdirSync(root);
    mkdirSync(persistent);
  });

  it("is true when the config dir is inside the temporary directory", () => {
    expect(isEphemeralHome(join(root, "h", ".config", "opena2a"), persistent, root)).toBe(true);
  });

  it("is true when the home directory is inside the temporary directory", () => {
    expect(isEphemeralHome(join(persistent, "opena2a"), join(root, "home"), root)).toBe(true);
  });

  it("is true when the home directory is the temporary directory itself", () => {
    expect(isEphemeralHome(join(root, ".config", "opena2a"), root, root)).toBe(true);
  });

  it("is false when neither is inside the temporary directory", () => {
    expect(isEphemeralHome(join(persistent, ".config", "opena2a"), persistent, root)).toBe(false);
  });

  it("is false for a sibling that only shares the name prefix", () => {
    const sibling = `${root}-other`;
    expect(isEphemeralHome(join(sibling, "opena2a"), sibling, root)).toBe(false);
  });

  it("is false when the home is unknown and the config dir is persistent", () => {
    expect(isEphemeralHome(join(persistent, "opena2a"), null, root)).toBe(false);
  });

  it("resolves symlinks, so a linked temporary directory still matches", () => {
    if (process.platform === "win32") return;
    const link = join(tmpHome, "temp-link");
    symlinkSync(root, link);
    // Home reached through the link, temp root given by its real path.
    expect(isEphemeralHome(join(persistent, "opena2a"), join(link, "home"), root)).toBe(true);
    // And the other way round, as on macOS where TMPDIR is /var/... and
    // the real path is /private/var/...
    expect(isEphemeralHome(join(persistent, "opena2a"), join(root, "home"), link)).toBe(true);
  });

  it("ignores a temporary directory set to the filesystem root", () => {
    const fsRoot = parse(persistent).root;
    expect(isEphemeralHome(join(persistent, "opena2a"), persistent, fsRoot)).toBe(false);
  });

  it("defaults to this process's config dir, home and os.tmpdir()", () => {
    expect(isEphemeralHome()).toBe(false);
    markTemporary(tmpHome);
    expect(isEphemeralHome()).toBe(true);
  });
});

describe("loadConfig automatic suppression", () => {
  // Regression guard for the metric bug this suppression exists to fix:
  // CI runners are provisioned fresh per job, so the machine-id (or the
  // hostname fallback) differs every run — a CI run typically minted a new
  // install_id and inflated distinct-install and active-user counts with
  // our own pipelines.
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

  it("attributes an env opt-out so a CLI can explain it", () => {
    // Without a reason code a CLI can only print a bare "off" and suggest
    // `telemetry on` — which cannot work, since env-off wins outright.
    process.env.OPENA2A_TELEMETRY = "off";
    const { config, suppressedBy } = loadConfig();
    expect(config.enabled).toBe(false);
    expect(suppressedBy).toBe("env-opt-out");
  });

  it("env opt-out outranks CI in attribution", () => {
    process.env.OPENA2A_TELEMETRY = "off";
    process.env.CI = "true";
    expect(loadConfig().suppressedBy).toBe("env-opt-out");
  });

  it("a persisted opt-out gets NO reason code (the plain toggle works there)", () => {
    setEnabled(false);
    const { config, suppressedBy } = loadConfig();
    expect(config.enabled).toBe(false);
    expect(suppressedBy).toBeNull();
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
    // otherwise one CI run would poison a developer's real config. A
    // suppressed run writes nothing at all.
    expect(existsSync(paths.file)).toBe(false);

    delete process.env.CI;
    expect(loadConfig().config.enabled).toBe(true);
  });

  it("mints and persists no install_id while suppressed", () => {
    process.env.CI = "true";
    const { config, paths } = loadConfig();
    expect(config.installId).toBeNull();
    expect(existsSync(paths.file)).toBe(false);
  });

  it("deletes an install_id persisted before the suppression applied", () => {
    const { paths } = loadConfig();
    expect(JSON.parse(readFileSync(paths.file, "utf8")).installId).toBeTruthy();
    process.env.DO_NOT_TRACK = "1";
    expect(loadConfig().config.installId).toBeNull();
    expect(existsSync(paths.file)).toBe(false);
  });
});

describe("loadConfig suppression for test runners and temporary homes", () => {
  // Regression guard: a test suite that spawns a CLI, outside CI, sent an
  // event for every spawn, and a CLI started with HOME=$(mktemp -d) looked
  // like a first run on a new machine every time.
  it.each([
    ["VITEST", "true"],
    ["JEST_WORKER_ID", "1"],
    ["NODE_TEST_CONTEXT", "child"],
  ])("%s=%s suppresses telemetry and writes nothing", (key, val) => {
    process.env[key] = val;
    const { config, paths, suppressedBy } = loadConfig();
    expect(config.enabled).toBe(false);
    expect(config.installId).toBeNull();
    expect(suppressedBy).toBe("test-runner");
    expect(existsSync(paths.file)).toBe(false);
  });

  it("a config dir inside the temporary directory suppresses telemetry and writes nothing", () => {
    markTemporary(tmpHome);
    const { config, paths, suppressedBy } = loadConfig();
    expect(config.enabled).toBe(false);
    expect(config.installId).toBeNull();
    expect(suppressedBy).toBe("ephemeral-home");
    expect(existsSync(paths.file)).toBe(false);
  });

  it("a HOME inside the temporary directory suppresses telemetry", () => {
    for (const key of ["HOME", "USERPROFILE"]) {
      savedEnv[key] = process.env[key];
      process.env[key] = join(tmpHome, "home");
    }
    delete process.env.XDG_CONFIG_HOME;
    markTemporary(tmpHome);
    const { config, paths, suppressedBy } = loadConfig();
    expect(paths.dir).toBe(join(tmpHome, "home", ".config", "opena2a"));
    expect(config.enabled).toBe(false);
    expect(suppressedBy).toBe("ephemeral-home");
    expect(existsSync(paths.file)).toBe(false);
  });

  it("deletes an install_id persisted before the home read as temporary", () => {
    const { paths } = loadConfig();
    expect(JSON.parse(readFileSync(paths.file, "utf8")).installId).toBeTruthy();
    markTemporary(tmpHome);
    expect(loadConfig().config.installId).toBeNull();
    expect(existsSync(paths.file)).toBe(false);
  });

  it("CI outranks a test runner in attribution", () => {
    process.env.CI = "true";
    process.env.VITEST = "true";
    expect(loadConfig().suppressedBy).toBe("ci");
  });

  it("a test runner outranks a temporary home in attribution", () => {
    process.env.VITEST = "true";
    markTemporary(tmpHome);
    expect(loadConfig().suppressedBy).toBe("test-runner");
  });

  it("OPENA2A_TELEMETRY=on re-enables under a test runner and in a temporary home", () => {
    process.env.VITEST = "true";
    markTemporary(tmpHome);
    process.env.OPENA2A_TELEMETRY = "on";
    const { config, suppressedBy } = loadConfig();
    expect(config.enabled).toBe(true);
    expect(suppressedBy).toBeNull();
  });

  it("OPENA2A_TELEMETRY=on still does NOT override DO_NOT_TRACK under a test runner", () => {
    process.env.VITEST = "true";
    process.env.DO_NOT_TRACK = "1";
    process.env.OPENA2A_TELEMETRY = "on";
    const { config, suppressedBy } = loadConfig();
    expect(config.enabled).toBe(false);
    expect(suppressedBy).toBe("do-not-track");
  });

  it("an env opt-out outranks a test runner in attribution", () => {
    process.env.VITEST = "true";
    process.env.OPENA2A_TELEMETRY = "off";
    expect(loadConfig().suppressedBy).toBe("env-opt-out");
  });
});

describe("setEnabled", () => {
  it("off writes exactly {enabled:false} and drops install_id", () => {
    const { paths } = loadConfig();
    const flipped = setEnabled(false);
    expect(flipped).toEqual({ enabled: false, installId: null });
    expect(JSON.parse(readFileSync(paths.file, "utf8"))).toEqual({ enabled: false });
    expect(loadConfig().config.installId).toBeNull();
  });

  it("on keeps an existing install_id", () => {
    const original = loadConfig().config.installId;
    expect(setEnabled(true)).toEqual({ enabled: true, installId: original });
    expect(loadConfig().config.installId).toBe(original);
  });

  it("on under an env opt-out saves the preference without an install_id", () => {
    const { paths } = loadConfig();
    process.env.OPENA2A_TELEMETRY = "off";
    expect(setEnabled(true)).toEqual({ enabled: true, installId: null });
    expect(JSON.parse(readFileSync(paths.file, "utf8"))).toEqual({ enabled: true });
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
