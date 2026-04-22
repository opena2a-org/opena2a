import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TtlCache } from "./cache.js";

describe("TtlCache", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns undefined on miss", () => {
    const c = new TtlCache<string>(1000);
    expect(c.get("x")).toBeUndefined();
  });

  it("returns a set value before expiry", () => {
    const c = new TtlCache<string>(1000);
    c.set("x", "value");
    vi.advanceTimersByTime(500);
    expect(c.get("x")).toBe("value");
  });

  it("evicts expired entries", () => {
    const c = new TtlCache<string>(1000);
    c.set("x", "value");
    vi.advanceTimersByTime(1001);
    expect(c.get("x")).toBeUndefined();
    expect(c.size).toBe(0);
  });

  it("clear empties the cache", () => {
    const c = new TtlCache<string>(1000);
    c.set("a", "1");
    c.set("b", "2");
    c.clear();
    expect(c.size).toBe(0);
  });

  it("set updates expiry for existing key", () => {
    const c = new TtlCache<string>(1000);
    c.set("x", "old");
    vi.advanceTimersByTime(800);
    c.set("x", "new");
    vi.advanceTimersByTime(800);
    expect(c.get("x")).toBe("new");
  });
});
