// Shield LLM Backend Abstraction
//
// Two backends:
//   1. Claude Code CLI (primary, zero-config): detects `claude` binary and
//      uses `claude --print` for completions. No API key required.
//   2. Anthropic API (secondary): uses ANTHROPIC_API_KEY for direct API calls.
//
// Nesting prevention: if $CLAUDECODE is set, we're already inside a Claude
// Code session and spawning `claude --print` would nest. Fall back to API.
//
// The `claude` binary is looked up only in PATH's absolute directories and
// started by that absolute path, in an empty working directory made for the
// call: a program reachable only through an empty or relative PATH entry,
// resolved against the directory the command was started in, is never chosen
// as the backend and never started.

import { execFileSync } from 'node:child_process';
import type { LlmBackend, LlmResponse } from './types.js';
import { childEnv } from '../adapters/registry.js';
import { absolutePathDirs, programOnPath, withEmptyWorkDir } from '../util/program-on-path.js';

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
 *   - no absolute PATH directory holds an executable `claude` (an empty or
 *     relative PATH entry is not searched)
 *   - $CLAUDECODE is set (nesting prevention)
 *
 * A lookup only: no program is started to find `claude`, so no discovery
 * step sees ANTHROPIC_API_KEY (#246).
 */
export function isClaudeCodeAvailable(): boolean {
  // Nesting prevention: if CLAUDECODE env var is set, we're already
  // inside a Claude Code session. Don't spawn another.
  if (process.env.CLAUDECODE) {
    return false;
  }

  return programOnPath('claude') !== null;
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
 * for cost-efficient, fast completions. `claude` is started by the absolute
 * path found in PATH's absolute directories, with PATH narrowed to those
 * directories, in an empty working directory made for the call (the prompt is
 * an argument; the call reads no project directory). Returns null, starting
 * nothing, when no absolute PATH directory holds `claude` or no working
 * directory can be made.
 */
export function callClaudeCode(
  systemPrompt: string,
  userPrompt: string,
  _maxTokens: number,
): LlmResponse | null {
  const claudePath = programOnPath('claude');
  if (claudePath === null) return null;

  return withEmptyWorkDir('opena2a-shield-llm-', (workDir) => {
    if (workDir.path === null) return null;
    try {
      const result = execFileSync(claudePath, [
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
        cwd: workDir.path,
        // The `claude` contract (CHILD_ENV_CONTRACTS.claude): model credentials
        // and endpoint selection, not the operator's whole environment (#246).
        // PATH alone is replaced, by its absolute directories.
        env: childEnv('claude', { set: { PATH: absolutePathDirs() } }),
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
  });
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
