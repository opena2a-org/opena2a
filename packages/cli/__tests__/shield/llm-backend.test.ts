import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// Mock node:os so that homedir() returns our temp directory.
// ---------------------------------------------------------------------------

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

// Mock @opena2a/shared for LLM consent checks
let _llmEnabled = true;

vi.mock('@opena2a/shared', () => ({
  isLlmEnabled: () => _llmEnabled,
  setLlmEnabled: (v: boolean) => { _llmEnabled = v; },
}));

// Mock node:child_process for Claude Code CLI detection
let _whichResult: string | null = '/usr/local/bin/claude';
let _execFileResult: string | null = null;

vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  return {
    ...actual,
    execSync: (cmd: string, _opts?: unknown) => {
      if (cmd === 'which claude') {
        if (_whichResult === null) throw new Error('not found');
        return _whichResult;
      }
      return actual.execSync(cmd, _opts as Parameters<typeof actual.execSync>[1]);
    },
    execFileSync: (_cmd: string, _args?: string[], _opts?: unknown) => {
      if (_execFileResult === null) throw new Error('command failed');
      return _execFileResult;
    },
  };
});

// Import after mocks
const {
  isClaudeCodeAvailable,
  detectBackend,
  callClaudeCode,
  callLlm,
} = await import('../../src/shield/llm-backend.js');

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempDir: string;
let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-backend-test-'));
  _mockHomeDir = tempDir;
  _llmEnabled = true;
  _whichResult = '/usr/local/bin/claude';
  _execFileResult = null;
  savedEnv = {
    ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
    CLAUDECODE: process.env.CLAUDECODE,
  };
  delete process.env.CLAUDECODE;
  process.env.ANTHROPIC_API_KEY = 'test-key-for-unit-tests';
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

// ===========================================================================
// 1. isClaudeCodeAvailable
// ===========================================================================

describe('isClaudeCodeAvailable', () => {
  it('returns true when claude is available and not nested', () => {
    _whichResult = '/usr/local/bin/claude';
    delete process.env.CLAUDECODE;
    expect(isClaudeCodeAvailable()).toBe(true);
  });

  it('returns false when claude binary is not found', () => {
    _whichResult = null;
    expect(isClaudeCodeAvailable()).toBe(false);
  });

  it('returns false when CLAUDECODE is set (nesting prevention)', () => {
    _whichResult = '/usr/local/bin/claude';
    process.env.CLAUDECODE = '1';
    expect(isClaudeCodeAvailable()).toBe(false);
  });
});

// ===========================================================================
// 2. detectBackend
// ===========================================================================

describe('detectBackend', () => {
  it('prefers claude-code when available', async () => {
    _whichResult = '/usr/local/bin/claude';
    delete process.env.CLAUDECODE;

    const result = await detectBackend();
    expect(result.backend).toBe('claude-code');
    expect(result.apiKey).toBeUndefined();
  });

  it('falls back to api when claude-code unavailable', async () => {
    _whichResult = null;
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    _llmEnabled = true;

    const result = await detectBackend();
    expect(result.backend).toBe('api');
    expect(result.apiKey).toBe('sk-test');
  });

  it('falls back to api when nested in Claude Code', async () => {
    _whichResult = '/usr/local/bin/claude';
    process.env.CLAUDECODE = '1';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    _llmEnabled = true;

    const result = await detectBackend();
    expect(result.backend).toBe('api');
    expect(result.apiKey).toBe('sk-test');
  });

  it('returns none when no backend available', async () => {
    _whichResult = null;
    delete process.env.ANTHROPIC_API_KEY;

    const result = await detectBackend();
    expect(result.backend).toBe('none');
  });

  it('returns none when API key exists but LLM disabled', async () => {
    _whichResult = null;
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    _llmEnabled = false;

    const result = await detectBackend();
    expect(result.backend).toBe('none');
  });
});

// ===========================================================================
// 3. callClaudeCode
// ===========================================================================

describe('callClaudeCode', () => {
  it('returns parsed response on success', () => {
    _execFileResult = JSON.stringify({
      result: '{"severity": "low", "explanation": "benign"}',
      cost_usd: 0.001,
      duration_ms: 500,
      num_turns: 1,
    });

    const result = callClaudeCode('system prompt', 'user prompt', 200);
    expect(result).not.toBeNull();
    expect(result!.text).toBe('{"severity": "low", "explanation": "benign"}');
    expect(result!.backend).toBe('claude-code');
    expect(result!.inputTokens).toBeGreaterThan(0);
    expect(result!.outputTokens).toBeGreaterThan(0);
  });

  it('returns null when command fails', () => {
    _execFileResult = null; // will throw

    const result = callClaudeCode('system', 'user', 200);
    expect(result).toBeNull();
  });

  it('returns null when result is empty', () => {
    _execFileResult = JSON.stringify({ result: '' });

    const result = callClaudeCode('system', 'user', 200);
    expect(result).toBeNull();
  });

  it('estimates tokens from text length', () => {
    const longSystem = 'a'.repeat(400);
    const longUser = 'b'.repeat(400);
    _execFileResult = JSON.stringify({ result: 'c'.repeat(200) });

    const result = callClaudeCode(longSystem, longUser, 200);
    expect(result).not.toBeNull();
    // ~200 chars / 4 = ~50 tokens for input, ~50 for output
    expect(result!.inputTokens).toBe(200); // (400+400)/4 = 200
    expect(result!.outputTokens).toBe(50); // 200/4 = 50
  });
});

// ===========================================================================
// 4. callLlm routing
// ===========================================================================

describe('callLlm', () => {
  it('returns null when no backend available', async () => {
    _whichResult = null;
    delete process.env.ANTHROPIC_API_KEY;

    const result = await callLlm('system', 'user', 200);
    expect(result).toBeNull();
  });

  it('routes to claude-code when available', async () => {
    _whichResult = '/usr/local/bin/claude';
    delete process.env.CLAUDECODE;
    _execFileResult = JSON.stringify({ result: '{"answer": "test"}' });

    const result = await callLlm('system', 'user', 200);
    expect(result).not.toBeNull();
    expect(result!.backend).toBe('claude-code');
    expect(result!.text).toBe('{"answer": "test"}');
  });

  it('routes to api when claude-code unavailable', async () => {
    _whichResult = null;
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    _llmEnabled = true;

    // Mock fetch for API calls
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        content: [{ type: 'text', text: '{"result": "api"}' }],
        usage: { input_tokens: 50, output_tokens: 30 },
      }),
    });

    const result = await callLlm('system', 'user', 200);
    expect(result).not.toBeNull();
    expect(result!.backend).toBe('api');
    expect(result!.text).toBe('{"result": "api"}');

    globalThis.fetch = originalFetch;
  });
});
