import { describe, it, expect } from 'vitest';
import { classifyInput } from '../../src/router.js';
import { createAdapter, ADAPTER_REGISTRY } from '../../src/adapters/index.js';

describe('input classifier', () => {
  it('classifies no args as guided', () => {
    expect(classifyInput([]).type).toBe('guided');
  });

  it('classifies ~ prefix as search', () => {
    const result = classifyInput(['~quantum']);
    expect(result.type).toBe('search');
    expect(result.value).toBe('quantum');
  });

  it('classifies ~multi word as search', () => {
    const result = classifyInput(['~api', 'key', 'scan']);
    expect(result.type).toBe('search');
    expect(result.value).toBe('api key scan');
  });

  it('classifies ? prefix as context', () => {
    const result = classifyInput(['?']);
    expect(result.type).toBe('context');
  });

  it('classifies known commands as subcommand', () => {
    for (const cmd of ['scan', 'secrets', 'runtime', 'benchmark', 'init', 'protect']) {
      const result = classifyInput([cmd, 'arg1']);
      expect(result.type).toBe('subcommand');
      expect(result.value).toBe(cmd);
      expect(result.args).toEqual(['arg1']);
    }
  });

  it('classifies quoted strings as natural language', () => {
    const result = classifyInput(['"is my agent safe?"']);
    expect(result.type).toBe('natural');
    expect(result.value).toBe('is my agent safe?');
  });

  it('classifies multi-word unknown input as natural language', () => {
    const result = classifyInput(['find', 'my', 'vulnerabilities']);
    expect(result.type).toBe('natural');
    expect(result.value).toBe('find my vulnerabilities');
  });

  it('classifies single unknown word as search', () => {
    const result = classifyInput(['quantum']);
    expect(result.type).toBe('search');
  });
});

describe('adapter registry', () => {
  it('has all expected adapters', () => {
    // guard, runtime, and identity are now handled directly (not adapter-based)
    const expected = ['scan', 'secrets', 'benchmark', 'registry',
      'train', 'crypto', 'broker'];
    for (const name of expected) {
      expect(ADAPTER_REGISTRY[name]).toBeDefined();
    }
  });

  it('creates correct adapter types', () => {
    expect(createAdapter('scan')).not.toBeNull();
    expect(createAdapter('train')).not.toBeNull();
    expect(createAdapter('crypto')).not.toBeNull();
    expect(createAdapter('nonexistent')).toBeNull();
  });
});
