import { describe, it, expect } from 'vitest';
import { ADAPTER_REGISTRY } from '../../src/adapters/registry.js';

/**
 * issue #191: the router injects `--format <fmt>` for non-text output, but
 * `ai-trust check` (the `registry` adapter) has no such flag and exits with
 * "unknown option '--format'". The adapter must opt out via
 * `acceptsFormatFlag: false` so the router skips injection (and surfaces a
 * one-line note instead of crashing).
 */
describe('AdapterConfig.acceptsFormatFlag — #191 registry --json crash', () => {
  it('registry (ai-trust check) opts out of --format injection', () => {
    expect(ADAPTER_REGISTRY['registry'].acceptsFormatFlag).toBe(false);
  });

  it('scan (hackmyagent) keeps default --format support (does not opt out)', () => {
    // undefined or true both mean "inject --format"; just assert it is not false,
    // so hackmyagent's working `--format json` path is not regressed.
    expect(ADAPTER_REGISTRY['scan'].acceptsFormatFlag).not.toBe(false);
  });
});
