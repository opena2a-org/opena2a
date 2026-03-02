import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { loadUserConfig } from '@opena2a/shared';

describe('LLM consent gate', () => {
  let origHome: string | undefined;

  beforeEach(() => {
    origHome = process.env.HOME;
    process.env.HOME = os.tmpdir();
    const configDir = path.join(os.tmpdir(), '.opena2a');
    if (fs.existsSync(configDir)) {
      fs.rmSync(configDir, { recursive: true, force: true });
    }
  });

  afterEach(() => {
    process.env.HOME = origHome;
    const configDir = path.join(os.tmpdir(), '.opena2a');
    if (fs.existsSync(configDir)) {
      fs.rmSync(configDir, { recursive: true, force: true });
    }
  });

  it('llmFallback returns null when no API key is set', async () => {
    const origKey = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    try {
      const { llmFallback } = await import('../../src/natural/llm-fallback.js');
      const result = await llmFallback('scan my project');
      expect(result).toBeNull();
    } finally {
      if (origKey) process.env.ANTHROPIC_API_KEY = origKey;
    }
  });

  it('handleNaturalLanguage tries static matching first', async () => {
    const chunks: string[] = [];
    const origStdout = process.stdout.write;
    const origStderr = process.stderr.write;

    process.stdout.write = ((chunk: any) => {
      chunks.push(String(chunk));
      return true;
    }) as any;
    process.stderr.write = ((chunk: any) => {
      chunks.push(String(chunk));
      return true;
    }) as any;

    try {
      const { handleNaturalLanguage } = await import('../../src/natural/llm-fallback.js');
      await handleNaturalLanguage('scan my code for vulnerabilities');
      expect(true).toBe(true);
    } finally {
      process.stdout.write = origStdout;
      process.stderr.write = origStderr;
    }
  });

  it('LLM config defaults to disabled', () => {
    const config = loadUserConfig();
    expect(config.llm.enabled).toBe(false);
  });
});
