import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadConfig, setEnabled, configPaths, endpointURL, debugPrintEnabled, DEFAULT_ENDPOINT } from "./config.js";

let tmpHome: string;

beforeEach(() => {
  tmpHome = mkdtempSync(join(tmpdir(), "opena2a-telem-"));
  process.env.XDG_CONFIG_HOME = tmpHome;
  delete process.env.OPENA2A_TELEMETRY;
  delete process.env.OPENA2A_TELEMETRY_URL;
  delete process.env.OPENA2A_TELEMETRY_DEBUG;
});

afterEach(() => {
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
  it("defaults to api.oa2a.org Registry route", () => {
    expect(endpointURL()).toBe(DEFAULT_ENDPOINT);
    expect(DEFAULT_ENDPOINT).toContain("/api/v1/registry/telemetry/v1/event");
  });

  it("env OPENA2A_TELEMETRY_URL overrides", () => {
    process.env.OPENA2A_TELEMETRY_URL = "http://localhost:8088/api/v1/registry/telemetry/v1/event";
    expect(endpointURL()).toBe("http://localhost:8088/api/v1/registry/telemetry/v1/event");
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
