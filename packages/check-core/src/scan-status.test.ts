import { describe, it, expect } from "vitest";
import { mapScanStatusForMeter } from "./scan-status.js";

describe("mapScanStatusForMeter", () => {
  it("maps 'complete' / 'completed' / 'passed' → completed", () => {
    expect(mapScanStatusForMeter("complete")).toBe("completed");
    expect(mapScanStatusForMeter("completed")).toBe("completed");
    expect(mapScanStatusForMeter("passed")).toBe("completed");
  });

  it("maps 'warnings' / 'warning' → warnings", () => {
    expect(mapScanStatusForMeter("warnings")).toBe("warnings");
    expect(mapScanStatusForMeter("warning")).toBe("warnings");
  });

  it("suppresses meter for pending / not_applicable / empty", () => {
    expect(mapScanStatusForMeter("pending")).toBeUndefined();
    expect(mapScanStatusForMeter("not_applicable")).toBeUndefined();
    expect(mapScanStatusForMeter("")).toBeUndefined();
  });

  it("suppresses meter for error / failed", () => {
    expect(mapScanStatusForMeter("error")).toBeUndefined();
    expect(mapScanStatusForMeter("failed")).toBeUndefined();
  });

  it("suppresses meter for undefined and unknown states", () => {
    expect(mapScanStatusForMeter(undefined)).toBeUndefined();
    expect(mapScanStatusForMeter("in_progress")).toBeUndefined();
    expect(mapScanStatusForMeter("weird-new-state")).toBeUndefined();
  });

  it("is case-insensitive and whitespace-tolerant", () => {
    expect(mapScanStatusForMeter("  PASSED  ")).toBe("completed");
    expect(mapScanStatusForMeter("Warning")).toBe("warnings");
  });
});
