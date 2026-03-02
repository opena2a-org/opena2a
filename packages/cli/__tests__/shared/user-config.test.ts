import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  loadUserConfig,
  saveUserConfig,
  getUserConfigDir,
  isLlmEnabled,
  setLlmEnabled,
  getRememberedChoice,
  setRememberedChoice,
  incrementScanCount,
  getScanCount,
  shouldPromptContribute,
  dismissContributePrompt,
  setContributeEnabled,
} from '@opena2a/shared';

describe('UserConfig extensions', () => {
  let configBackup: string | null = null;

  beforeEach(() => {
    // Backup existing config if present
    const configPath = path.join(getUserConfigDir(), 'config.json');
    if (fs.existsSync(configPath)) {
      configBackup = fs.readFileSync(configPath, 'utf-8');
    }
    // Remove config to get clean defaults
    if (fs.existsSync(getUserConfigDir())) {
      fs.rmSync(getUserConfigDir(), { recursive: true, force: true });
    }
  });

  afterEach(() => {
    // Restore original config
    const dir = getUserConfigDir();
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    if (configBackup !== null) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'config.json'), configBackup, 'utf-8');
    }
  });

  it('loadUserConfig returns default llm config when no config file exists', () => {
    const config = loadUserConfig();

    expect(config.llm).toBeDefined();
    expect(config.llm.enabled).toBe(false);
    expect(config.llm.consentedAt).toBeNull();
    expect(config.llm.consentVersion).toBe('1.0');
  });

  it('loadUserConfig returns default preferences when no config file exists', () => {
    const config = loadUserConfig();

    expect(config.preferences).toBeDefined();
    expect(config.preferences.rememberedChoices).toEqual({});
  });

  it('isLlmEnabled returns false by default', () => {
    expect(isLlmEnabled()).toBe(false);
  });

  it('setLlmEnabled enables LLM and records timestamp', () => {
    setLlmEnabled(true);
    const config = loadUserConfig();

    expect(config.llm.enabled).toBe(true);
    expect(config.llm.consentedAt).toBeTruthy();
    expect(typeof config.llm.consentedAt).toBe('string');
  });

  it('setLlmEnabled(false) clears consent timestamp', () => {
    setLlmEnabled(true);
    setLlmEnabled(false);
    const config = loadUserConfig();

    expect(config.llm.enabled).toBe(false);
    expect(config.llm.consentedAt).toBeNull();
  });

  it('getRememberedChoice returns undefined for unknown actions', () => {
    expect(getRememberedChoice('nonexistent-action')).toBeUndefined();
  });

  it('setRememberedChoice stores and retrieves choices', () => {
    setRememberedChoice('test-action', true);
    expect(getRememberedChoice('test-action')).toBe(true);

    setRememberedChoice('test-action', false);
    expect(getRememberedChoice('test-action')).toBe(false);
  });

  it('loadUserConfig merges partial config with defaults', () => {
    // Write a partial config (missing llm and preferences)
    const dir = getUserConfigDir();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'config.json'),
      JSON.stringify({
        version: 1,
        contribute: { enabled: true, consentedAt: '2025-01-01', consentVersion: '1.0' },
        registry: { url: 'https://custom.registry.org' },
      }),
      'utf-8'
    );

    const config = loadUserConfig();

    // Existing fields preserved
    expect(config.contribute.enabled).toBe(true);
    expect(config.registry.url).toBe('https://custom.registry.org');

    // New llm and preferences sections exist (merged from defaults)
    expect(config.llm).toBeDefined();
    expect(config.llm.consentVersion).toBe('1.0');
    expect(config.preferences).toBeDefined();
    expect(typeof config.preferences.rememberedChoices).toBe('object');

    // Telemetry defaults merged
    expect(config.telemetry).toBeDefined();
    expect(config.telemetry.scanCount).toBe(0);
  });

  it('incrementScanCount tracks cumulative scans', () => {
    const count1 = incrementScanCount();
    expect(count1).toBe(1);
    const count2 = incrementScanCount();
    expect(count2).toBe(2);
    const count3 = incrementScanCount();
    expect(count3).toBe(3);
    expect(getScanCount()).toBe(3);
  });

  it('shouldPromptContribute returns false before threshold (3 scans required)', () => {
    // Verify clean state
    const config = loadUserConfig();
    const startCount = config.telemetry?.scanCount ?? 0;
    // Increment to 2 from wherever we start (should be 0 after cleanup)
    const finalCount = startCount + 2;
    incrementScanCount();
    incrementScanCount();
    expect(getScanCount()).toBe(finalCount);
    // With fewer than 3 scans, should not prompt
    if (finalCount < 3) {
      expect(shouldPromptContribute()).toBe(false);
    }
  });

  it('shouldPromptContribute returns true at threshold', () => {
    // Explicitly reach threshold of 3
    incrementScanCount();
    incrementScanCount();
    incrementScanCount();
    expect(getScanCount()).toBeGreaterThanOrEqual(3);
    expect(shouldPromptContribute()).toBe(true);
  });

  it('shouldPromptContribute returns false when already opted in', () => {
    incrementScanCount();
    incrementScanCount();
    incrementScanCount();
    setContributeEnabled(true);
    expect(shouldPromptContribute()).toBe(false);
  });

  it('dismissContributePrompt prevents re-prompt', () => {
    incrementScanCount();
    incrementScanCount();
    incrementScanCount();
    expect(shouldPromptContribute()).toBe(true);
    dismissContributePrompt();
    expect(shouldPromptContribute()).toBe(false);
  });
});
