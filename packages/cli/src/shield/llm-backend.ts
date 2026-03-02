// Shield LLM Backend Abstraction
//
// Two backends:
//   1. Claude Code CLI (primary, zero-config): detects `claude` binary and
//      uses `claude --print` for completions. No API key required.
//   2. Anthropic API (secondary): uses ANTHROPIC_API_KEY for direct API calls.
//
// Nesting prevention: if $CLAUDECODE is set, we're already inside a Claude
// Code session and spawning `claude --print` would nest. Fall back to API.

import { execSync, execFileSync } from 'node:child_process';
import type { LlmBackend, LlmResponse } from './types.js';

const CLAUDE_CODE_TIMEOUT_MS = 30_000;

// Approximate tokens from text length (used when Claude Code doesn't report exact counts)
function estimateTokens(text: string): number {
  // ~4 chars per token is a reasonable approximation
  return Math.ceil(text.length / 4);
}

/**
 * Check if the Claude Code CLI binary is available and safe to call.
 *
 * Returns false if:
 *   - `which claude` fails (not installed)
 *   - $CLAUDECODE is set (nesting prevention)
 */
export function isClaudeCodeAvailable(): boolean {
  // Nesting prevention: if CLAUDECODE env var is set, we're already
  // inside a Claude Code session. Don't spawn another.
  if (process.env.CLAUDECODE) {
    return false;
  }

  try {
    const result = execSync('which claude', {
      encoding: 'utf-8',
      timeout: 5_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return result.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Detect which LLM backend is available.
 *
 * Priority:
 *   1. Claude Code CLI (zero-config, no API key needed)
 *   2. Anthropic API (requires ANTHROPIC_API_KEY + consent)
 *   3. None
 */
export async function detectBackend(): Promise<{ backend: LlmBackend; apiKey?: string }> {
  // 1. Try Claude Code CLI
  if (isClaudeCodeAvailable()) {
    return { backend: 'claude-code' };
  }

  // 2. Try Anthropic API
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (apiKey) {
    // Check consent via @opena2a/shared
    try {
      const shared = await import('@opena2a/shared');
      const mod = 'default' in shared ? (shared as Record<string, unknown>).default : shared;
      if (!(mod as { isLlmEnabled: () => boolean }).isLlmEnabled()) {
        return { backend: 'none' };
      }
    } catch {
      // shared not available -- allow (backward compat)
    }
    return { backend: 'api', apiKey };
  }

  return { backend: 'none' };
}

/**
 * Call the Claude Code CLI as an LLM backend.
 *
 * Uses `claude --print` with JSON output format and Haiku model
 * for cost-efficient, fast completions.
 */
export function callClaudeCode(
  systemPrompt: string,
  userPrompt: string,
  _maxTokens: number,
): LlmResponse | null {
  try {
    const result = execFileSync('claude', [
      '--print',
      '--output-format', 'json',
      '--model', 'haiku',
      '--max-turns', '1',
      '--no-session-persistence',
      '--system-prompt', systemPrompt,
      userPrompt,
    ], {
      encoding: 'utf-8',
      timeout: CLAUDE_CODE_TIMEOUT_MS,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env },
    });

    // Parse JSON output from claude --print --output-format json
    const parsed = JSON.parse(result) as {
      result?: string;
      cost_usd?: number;
      duration_ms?: number;
      num_turns?: number;
    };

    const text = parsed.result ?? '';
    if (!text) return null;

    return {
      text,
      inputTokens: estimateTokens(systemPrompt + userPrompt),
      outputTokens: estimateTokens(text),
      backend: 'claude-code',
    };
  } catch {
    return null;
  }
}

/**
 * Unified LLM call interface.
 *
 * Routes to Claude Code CLI or Anthropic API based on detected backend.
 * Returns null if no backend is available or the call fails.
 */
export async function callLlm(
  systemPrompt: string,
  userPrompt: string,
  maxTokens: number,
): Promise<LlmResponse | null> {
  const { backend, apiKey } = await detectBackend();

  if (backend === 'none') return null;

  if (backend === 'claude-code') {
    return callClaudeCode(systemPrompt, userPrompt, maxTokens);
  }

  // API backend -- use callHaiku (imported lazily to avoid circular deps)
  if (backend === 'api' && apiKey) {
    const { callHaiku } = await import('./llm.js');
    const result = await callHaiku(systemPrompt, userPrompt, maxTokens, apiKey);
    if (!result) return null;
    return {
      text: result.text,
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
      backend: 'api',
    };
  }

  return null;
}
