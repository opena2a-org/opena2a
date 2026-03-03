import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

import {
  configureClaudeCodeForShield,
  configureCursorForShield,
  configureWindsurfForShield,
  configureCopilotForShield,
  configureClineForShield,
  configureAiTools,
  hasShieldMarker,
} from '../../src/shield/ai-tool-config.js';

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-aitool-test-'));
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

describe('ai-tool-config', () => {
  describe('configureClaudeCodeForShield', () => {
    it('creates CLAUDE.md with shield section when none exists', () => {
      const result = configureClaudeCodeForShield(tempDir);
      expect(result).toBe(true);

      const content = fs.readFileSync(path.join(tempDir, 'CLAUDE.md'), 'utf-8');
      expect(content).toContain('<!-- opena2a-shield:managed -->');
      expect(content).toContain('Shield Security Context');
      expect(content).toContain('opena2a shield status');
    });

    it('appends to existing CLAUDE.md preserving content', () => {
      const existingContent = '# My Project\n\nExisting instructions here.\n';
      fs.writeFileSync(path.join(tempDir, 'CLAUDE.md'), existingContent);

      const result = configureClaudeCodeForShield(tempDir);
      expect(result).toBe(true);

      const content = fs.readFileSync(path.join(tempDir, 'CLAUDE.md'), 'utf-8');
      expect(content).toContain('# My Project');
      expect(content).toContain('Existing instructions here.');
      expect(content).toContain('<!-- opena2a-shield:managed -->');
    });

    it('is idempotent -- skips if marker already present', () => {
      configureClaudeCodeForShield(tempDir);
      const firstContent = fs.readFileSync(path.join(tempDir, 'CLAUDE.md'), 'utf-8');

      const result = configureClaudeCodeForShield(tempDir);
      expect(result).toBe(false);

      const secondContent = fs.readFileSync(path.join(tempDir, 'CLAUDE.md'), 'utf-8');
      expect(secondContent).toBe(firstContent);
    });

    it('preserves secretless section when adding shield section', () => {
      const existingContent = '# Project\n\n<!-- secretless:managed -->\n## Secretless Mode\nSecretless content here.\n';
      fs.writeFileSync(path.join(tempDir, 'CLAUDE.md'), existingContent);

      configureClaudeCodeForShield(tempDir);
      const content = fs.readFileSync(path.join(tempDir, 'CLAUDE.md'), 'utf-8');

      expect(content).toContain('<!-- secretless:managed -->');
      expect(content).toContain('Secretless Mode');
      expect(content).toContain('<!-- opena2a-shield:managed -->');
      expect(content).toContain('Shield Security Context');
    });
  });

  describe('configureCursorForShield', () => {
    it('creates .cursorrules with shield section', () => {
      const result = configureCursorForShield(tempDir);
      expect(result).toBe(true);
      expect(fs.existsSync(path.join(tempDir, '.cursorrules'))).toBe(true);
      expect(hasShieldMarker(path.join(tempDir, '.cursorrules'))).toBe(true);
    });
  });

  describe('configureWindsurfForShield', () => {
    it('creates .windsurfrules with shield section', () => {
      const result = configureWindsurfForShield(tempDir);
      expect(result).toBe(true);
      expect(fs.existsSync(path.join(tempDir, '.windsurfrules'))).toBe(true);
    });
  });

  describe('configureCopilotForShield', () => {
    it('creates .github/copilot-instructions.md with subdirectory', () => {
      const result = configureCopilotForShield(tempDir);
      expect(result).toBe(true);
      expect(fs.existsSync(path.join(tempDir, '.github', 'copilot-instructions.md'))).toBe(true);
    });
  });

  describe('configureClineForShield', () => {
    it('creates .clinerules with shield section', () => {
      const result = configureClineForShield(tempDir);
      expect(result).toBe(true);
      expect(fs.existsSync(path.join(tempDir, '.clinerules'))).toBe(true);
    });
  });

  describe('configureAiTools', () => {
    it('always configures Claude Code', () => {
      const result = configureAiTools(tempDir, []);
      expect(result.toolsConfigured).toContain('Claude Code (CLAUDE.md)');
    });

    it('configures Cursor when detected', () => {
      const result = configureAiTools(tempDir, ['Cursor']);
      expect(result.toolsConfigured).toContain('Claude Code (CLAUDE.md)');
      expect(result.toolsConfigured).toContain('Cursor (.cursorrules)');
    });

    it('configures Windsurf when .windsurfrules exists', () => {
      fs.writeFileSync(path.join(tempDir, '.windsurfrules'), 'existing rules\n');
      const result = configureAiTools(tempDir, []);
      expect(result.toolsConfigured).toContain('Windsurf (.windsurfrules)');
    });

    it('reports already-configured tools as skipped', () => {
      configureAiTools(tempDir, ['Cursor']);
      const result = configureAiTools(tempDir, ['Cursor']);
      expect(result.toolsSkipped).toContain('Claude Code (already configured)');
      expect(result.toolsSkipped).toContain('Cursor (already configured)');
      expect(result.toolsConfigured).toHaveLength(0);
    });
  });

  describe('hasShieldMarker', () => {
    it('returns false for non-existent file', () => {
      expect(hasShieldMarker(path.join(tempDir, 'nonexistent.md'))).toBe(false);
    });

    it('returns true after configuration', () => {
      configureClaudeCodeForShield(tempDir);
      expect(hasShieldMarker(path.join(tempDir, 'CLAUDE.md'))).toBe(true);
    });
  });
});
