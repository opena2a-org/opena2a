import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

export interface ContributeConfig {
  enabled: boolean;
  consentedAt: string | null;
  consentVersion: string;
}

export interface LlmConfig {
  enabled: boolean;
  consentedAt: string | null;
  consentVersion: string;
}

export interface PreferencesConfig {
  rememberedChoices: Record<string, boolean>;
}

export interface UserConfig {
  version: 1;
  contribute: ContributeConfig;
  registry: {
    url: string;
  };
  llm: LlmConfig;
  preferences: PreferencesConfig;
}

const DEFAULT_CONFIG: UserConfig = {
  version: 1,
  contribute: {
    enabled: false,
    consentedAt: null,
    consentVersion: '1.0',
  },
  registry: {
    url: 'https://registry.opena2a.org',
  },
  llm: {
    enabled: false,
    consentedAt: null,
    consentVersion: '1.0',
  },
  preferences: {
    rememberedChoices: {},
  },
};

export function getUserConfigDir(): string {
  return join(homedir(), '.opena2a');
}

export function getUserConfigPath(): string {
  return join(getUserConfigDir(), 'config.json');
}

export function loadUserConfig(): UserConfig {
  const configPath = getUserConfigPath();
  try {
    const raw = readFileSync(configPath, 'utf-8');
    const parsed = JSON.parse(raw);

    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      contribute: { ...DEFAULT_CONFIG.contribute, ...parsed.contribute },
      registry: { ...DEFAULT_CONFIG.registry, ...parsed.registry },
      llm: { ...DEFAULT_CONFIG.llm, ...parsed.llm },
      preferences: {
        ...DEFAULT_CONFIG.preferences,
        ...parsed.preferences,
        rememberedChoices: {
          ...DEFAULT_CONFIG.preferences.rememberedChoices,
          ...(parsed.preferences?.rememberedChoices ?? {}),
        },
      },
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

export function saveUserConfig(config: UserConfig): void {
  const configPath = getUserConfigPath();
  const configDir = dirname(configPath);

  if (!existsSync(configDir)) {
    mkdirSync(configDir, { recursive: true, mode: 0o700 });
  }

  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', {
    mode: 0o600,
  });
}

export function isContributeEnabled(): boolean {
  return loadUserConfig().contribute.enabled;
}

export function setContributeEnabled(enabled: boolean): void {
  const config = loadUserConfig();
  config.contribute.enabled = enabled;
  config.contribute.consentedAt = enabled ? new Date().toISOString() : null;
  saveUserConfig(config);
}

export function isLlmEnabled(): boolean {
  return loadUserConfig().llm.enabled;
}

export function setLlmEnabled(enabled: boolean): void {
  const config = loadUserConfig();
  config.llm.enabled = enabled;
  config.llm.consentedAt = enabled ? new Date().toISOString() : null;
  saveUserConfig(config);
}

export function getRememberedChoice(actionId: string): boolean | undefined {
  const config = loadUserConfig();
  const value = config.preferences.rememberedChoices[actionId];
  return value === undefined ? undefined : value;
}

export function setRememberedChoice(actionId: string, value: boolean): void {
  const config = loadUserConfig();
  config.preferences.rememberedChoices[actionId] = value;
  saveUserConfig(config);
}
