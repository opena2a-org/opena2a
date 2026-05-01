import { describe, it, expect } from 'vitest';
import { ADAPTER_REGISTRY } from '../../src/adapters/registry.js';

describe('AdapterConfig.aliases — closes #135 dead-end command citations', () => {
  it('scan registers `secure` as an alias so HMA-emitted Next Steps text resolves', () => {
    const scan = ADAPTER_REGISTRY['scan'];
    expect(scan).toBeDefined();
    expect(scan.aliases).toBeDefined();
    expect(scan.aliases).toContain('secure');
  });

  it('aliases array does not collide with another registered command name', () => {
    const allNames = new Set(Object.keys(ADAPTER_REGISTRY));
    for (const config of Object.values(ADAPTER_REGISTRY)) {
      for (const alias of config.aliases ?? []) {
        expect(allNames.has(alias)).toBe(false);
      }
    }
  });
});
