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

export interface TelemetryConfig {
  scanCount: number;
  contributePromptDismissedAt: string | null;
}

export interface UserConfig {
  version: 1;
  contribute: ContributeConfig;
  registry: {
    url: string;
  };
  llm: LlmConfig;
  preferences: PreferencesConfig;
  telemetry: TelemetryConfig;
}

const DEFAULT_CONFIG: UserConfig = {
  version: 1,
  contribute: {
    enabled: false,
    consentedAt: null,
    consentVersion: '1.0',
  },
  registry: {
    url: '',
  },
  llm: {
    enabled: false,
    consentedAt: null,
    consentVersion: '1.0',
  },
  preferences: {
    rememberedChoices: {},
  },
  telemetry: {
    scanCount: 0,
    contributePromptDismissedAt: null,
  },
};

export function getUserConfigDir(): string {
  return join(homedir(), '.opena2a');
}

export function getUserConfigPath(): string {
  return join(getUserConfigDir(), 'config.json');
}

/**
 * Registry host names that were in use before the migration to oa2a.org.
 * Any config pointing at one of these is silently rewritten on load to the
 * current canonical URL so existing users do not have to edit their config
 * manually after an upstream URL change.
 */
export const STALE_REGISTRY_HOSTS: readonly string[] = [
  'https://registry.opena2a.org',
  'http://registry.opena2a.org',
  'https://api.opena2a.org',
  'http://api.opena2a.org',
];

export const CANONICAL_REGISTRY_URL = 'https://api.oa2a.org';

/**
 * Pure helper: returns true if the given URL matches a known-stale registry host.
 * Exported for testing.
 */
export function isStaleRegistryUrl(url: string | undefined | null): boolean {
  if (!url) return false;
  const normalized = url.trim().replace(/\/+$/, '').toLowerCase();
  if (!normalized) return false;
  return STALE_REGISTRY_HOSTS.some(
    host => normalized === host.toLowerCase() || normalized.startsWith(host.toLowerCase() + '/'),
  );
}

/**
 * If the user's config points at a registry host that no longer exists,
 * rewrite it to the canonical URL and persist the change. Returns true if
 * a migration was performed. Callers may use the return value to emit a
 * one-time notice; failures to persist are swallowed so a broken home
 * directory never blocks CLI startup.
 */
function migrateStaleRegistryUrl(config: UserConfig): boolean {
  if (!isStaleRegistryUrl(config.registry?.url)) return false;
  config.registry.url = CANONICAL_REGISTRY_URL;
  try {
    saveUserConfig(config);
  } catch {
    // Non-fatal: in-memory value is correct even if we cannot persist.
  }
  return true;
}

export function loadUserConfig(): UserConfig {
  const configPath = getUserConfigPath();
  try {
    const raw = readFileSync(configPath, 'utf-8');
    const parsed = JSON.parse(raw);

    const merged: UserConfig = {
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
      telemetry: { ...DEFAULT_CONFIG.telemetry, ...parsed.telemetry },
    };

    if (migrateStaleRegistryUrl(merged)) {
      // Print to stderr so JSON-formatted stdout stays clean. One-time per
      // invocation; subsequent loads see the already-migrated config.
      try {
        process.stderr.write(
          `opena2a: migrated stale registry URL to ${CANONICAL_REGISTRY_URL}\n`,
        );
      } catch {
        // stderr unavailable in some sandboxed runtimes — ignore.
      }
    }

    return merged;
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

// --- Scan telemetry ---

const CONTRIBUTE_PROMPT_THRESHOLD = 3;
const CONTRIBUTE_PROMPT_COOLDOWN_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export function incrementScanCount(): number {
  const config = loadUserConfig();
  config.telemetry.scanCount = (config.telemetry.scanCount ?? 0) + 1;
  saveUserConfig(config);
  return config.telemetry.scanCount;
}

export function getScanCount(): number {
  return loadUserConfig().telemetry.scanCount ?? 0;
}

/**
 * Returns true if the user should be shown a one-time prompt to opt into
 * sharing anonymized scan reports. Only shown after the user has completed
 * enough scans to have seen value, and not if they already opted in or
 * recently dismissed the prompt.
 */
export function shouldPromptContribute(): boolean {
  const config = loadUserConfig();

  // Already opted in
  if (config.contribute.enabled) return false;

  // Not enough scans yet
  if ((config.telemetry.scanCount ?? 0) < CONTRIBUTE_PROMPT_THRESHOLD) return false;

  // Dismissed recently
  if (config.telemetry.contributePromptDismissedAt) {
    const dismissedAt = new Date(config.telemetry.contributePromptDismissedAt).getTime();
    if (Date.now() - dismissedAt < CONTRIBUTE_PROMPT_COOLDOWN_MS) return false;
  }

  return true;
}

export function dismissContributePrompt(): void {
  const config = loadUserConfig();
  config.telemetry.contributePromptDismissedAt = new Date().toISOString();
  saveUserConfig(config);
}
