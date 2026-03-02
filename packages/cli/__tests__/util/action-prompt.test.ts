import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { offerAction, type ActionPromptOptions } from '../../src/util/action-prompt.js';

describe('offerAction', () => {
  let origIsTTY: boolean | undefined;

  beforeEach(() => {
    origIsTTY = process.stdin.isTTY;
  });

  afterEach(() => {
    Object.defineProperty(process.stdin, 'isTTY', {
      value: origIsTTY,
      writable: true,
      configurable: true,
    });
  });

  it('returns false in CI mode', async () => {
    const result = await offerAction({
      actionId: 'test-ci',
      title: 'Test Action',
      steps: ['Step 1'],
      rollback: ['Undo step 1'],
      execute: async () => ({ success: true, message: 'Done' }),
      ci: true,
    });

    expect(result).toBe(false);
  });

  it('returns false when stdin is not a TTY', async () => {
    Object.defineProperty(process.stdin, 'isTTY', {
      value: false,
      writable: true,
      configurable: true,
    });

    const result = await offerAction({
      actionId: 'test-tty',
      title: 'Test Action',
      steps: ['Step 1'],
      rollback: ['Undo step 1'],
      execute: async () => ({ success: true, message: 'Done' }),
    });

    expect(result).toBe(false);
  });

  it('has correct interface shape', () => {
    const options: ActionPromptOptions = {
      actionId: 'test',
      title: 'Test',
      steps: ['a', 'b'],
      rollback: ['c'],
      execute: async () => ({ success: true, message: 'ok' }),
      ci: false,
    };

    expect(options.actionId).toBe('test');
    expect(options.steps).toHaveLength(2);
    expect(options.rollback).toHaveLength(1);
  });
});
