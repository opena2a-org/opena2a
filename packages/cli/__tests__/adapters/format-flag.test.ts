import { describe, it, expect } from 'vitest';
import { ADAPTER_REGISTRY } from '../../src/adapters/registry.js';

/**
 * issue #191: the router injects `--format <fmt>` for non-text output, but
 * `ai-trust check` (the `registry` adapter) has no `--format` flag — it emits
 * JSON via a bare `--json`. The adapter declares `jsonOutputFlag: '--json'` so
 * the router injects `--json` for json output (instead of `--format json`,
 * which would crash with "unknown option '--format'") and notes any other
 * unsupported format.
 */
describe('AdapterConfig.jsonOutputFlag — #191 registry --json', () => {
  it('registry (ai-trust check) emits JSON via --json, not --format', () => {
    expect(ADAPTER_REGISTRY['registry'].jsonOutputFlag).toBe('--json');
    // No longer a blanket opt-out: json IS supported now (via --json).
    expect(ADAPTER_REGISTRY['registry'].acceptsFormatFlag).toBeUndefined();
  });

  it('scan (hackmyagent) keeps default --format support (no jsonOutputFlag)', () => {
    // undefined acceptsFormatFlag + no jsonOutputFlag means "inject --format",
    // so hackmyagent's working `--format json` path is not regressed.
    expect(ADAPTER_REGISTRY['scan'].jsonOutputFlag).toBeUndefined();
    expect(ADAPTER_REGISTRY['scan'].acceptsFormatFlag).not.toBe(false);
  });
});
