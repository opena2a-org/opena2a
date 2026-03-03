import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  buildConfigItem,
  configureSecretlessForAiTools,
  generateSecretlessSection,
  upsertSecretlessSection,
  parseExistingCredentials,
  type SecretlessConfigItem,
} from '../../src/util/secretless-config.js';

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-config-'));
}

function cleanupDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('secretless-config', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir();
  });

  afterEach(() => {
    cleanupDir(tempDir);
  });

  // --- buildConfigItem ---

  describe('buildConfigItem', () => {
    it('returns correct metadata for known services', () => {
      const item = buildConfigItem('ANTHROPIC_API_KEY');
      expect(item.envVar).toBe('ANTHROPIC_API_KEY');
      expect(item.service).toBe('Anthropic Messages API');
      expect(item.authHeader).toBe('x-api-key: $ANTHROPIC_API_KEY');
    });

    it('returns correct metadata for OpenAI', () => {
      const item = buildConfigItem('OPENAI_API_KEY');
      expect(item.service).toBe('OpenAI API');
      expect(item.authHeader).toContain('Bearer');
    });

    it('returns fallback for unknown services', () => {
      const item = buildConfigItem('SOME_RANDOM_KEY');
      expect(item.service).toBe('API Service');
      expect(item.authHeader).toBe('(check service docs)');
    });

    it('strips numeric suffix for lookup', () => {
      const item = buildConfigItem('ANTHROPIC_API_KEY_2');
      expect(item.envVar).toBe('ANTHROPIC_API_KEY_2');
      expect(item.service).toBe('Anthropic Messages API');
      expect(item.authHeader).toBe('x-api-key: $ANTHROPIC_API_KEY_2');
    });

    it('handles GitHub token', () => {
      const item = buildConfigItem('GITHUB_TOKEN');
      expect(item.service).toBe('GitHub API');
      expect(item.authHeader).toContain('Bearer');
    });
  });

  // --- generateSecretlessSection ---

  describe('generateSecretlessSection', () => {
    it('generates section with correct markers and table', () => {
      const items: SecretlessConfigItem[] = [
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic Messages API', authHeader: 'x-api-key: $ANTHROPIC_API_KEY' },
      ];

      const section = generateSecretlessSection(items);

      expect(section).toContain('<!-- secretless:managed -->');
      expect(section).toContain('<!-- /secretless:managed -->');
      expect(section).toContain('## Secretless Mode');
      expect(section).toContain('`$ANTHROPIC_API_KEY`');
      expect(section).toContain('Anthropic Messages API');
      expect(section).toContain('Blocked file patterns');
      expect(section).toContain('Transcript Protection');
    });

    it('includes multiple credentials in the table', () => {
      const items: SecretlessConfigItem[] = [
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic Messages API', authHeader: 'x-api-key: $ANTHROPIC_API_KEY' },
        { envVar: 'OPENAI_API_KEY', service: 'OpenAI API', authHeader: 'Authorization: Bearer $OPENAI_API_KEY' },
      ];

      const section = generateSecretlessSection(items);
      expect(section).toContain('`$ANTHROPIC_API_KEY`');
      expect(section).toContain('`$OPENAI_API_KEY`');
    });
  });

  // --- upsertSecretlessSection ---

  describe('upsertSecretlessSection', () => {
    it('creates CLAUDE.md when none exists', () => {
      const filePath = path.join(tempDir, 'CLAUDE.md');
      const section = generateSecretlessSection([
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic', authHeader: 'x-api-key: $ANTHROPIC_API_KEY' },
      ]);

      const updated = upsertSecretlessSection(filePath, section, true);

      expect(updated).toBe(true);
      expect(fs.existsSync(filePath)).toBe(true);

      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toContain('<!-- secretless:managed -->');
      expect(content).toContain('<!-- /secretless:managed -->');
      expect(content).toContain('`$ANTHROPIC_API_KEY`');
    });

    it('does not create non-CLAUDE.md files if they do not exist', () => {
      const filePath = path.join(tempDir, '.cursorrules');
      const section = generateSecretlessSection([
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic', authHeader: 'test' },
      ]);

      const updated = upsertSecretlessSection(filePath, section, false);

      expect(updated).toBe(false);
      expect(fs.existsSync(filePath)).toBe(false);
    });

    it('appends to existing CLAUDE.md preserving content', () => {
      const filePath = path.join(tempDir, 'CLAUDE.md');
      fs.writeFileSync(filePath, '# My Project\n\nSome instructions here.\n');

      const section = generateSecretlessSection([
        { envVar: 'OPENAI_API_KEY', service: 'OpenAI', authHeader: 'Bearer $OPENAI_API_KEY' },
      ]);

      const updated = upsertSecretlessSection(filePath, section, true);

      expect(updated).toBe(true);
      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toContain('# My Project');
      expect(content).toContain('Some instructions here.');
      expect(content).toContain('<!-- secretless:managed -->');
      expect(content).toContain('`$OPENAI_API_KEY`');
    });

    it('replaces existing secretless section with new credentials', () => {
      const filePath = path.join(tempDir, 'CLAUDE.md');
      const oldSection = generateSecretlessSection([
        { envVar: 'OLD_KEY', service: 'Old Service', authHeader: 'old' },
      ]);
      fs.writeFileSync(filePath, `# Project\n\n${oldSection}\n`);

      const newSection = generateSecretlessSection([
        { envVar: 'NEW_KEY', service: 'New Service', authHeader: 'new' },
      ]);

      const updated = upsertSecretlessSection(filePath, newSection, true);

      expect(updated).toBe(true);
      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toContain('`$NEW_KEY`');
      expect(content).not.toContain('`$OLD_KEY`');
      // Only one start marker
      expect(content.split('<!-- secretless:managed -->').length).toBe(2);
    });

    it('preserves opena2a-shield section when updating', () => {
      const filePath = path.join(tempDir, 'CLAUDE.md');
      const shieldSection = '<!-- opena2a-shield:managed -->\n## Shield\nShield content here.\n<!-- /opena2a-shield:managed -->';
      const secretlessSection = generateSecretlessSection([
        { envVar: 'OLD_KEY', service: 'Old', authHeader: 'old' },
      ]);
      fs.writeFileSync(filePath, `${secretlessSection}\n\n${shieldSection}\n`);

      const newSection = generateSecretlessSection([
        { envVar: 'NEW_KEY', service: 'New', authHeader: 'new' },
      ]);

      upsertSecretlessSection(filePath, newSection, true);

      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toContain('`$NEW_KEY`');
      expect(content).toContain('opena2a-shield:managed');
      expect(content).toContain('Shield content here.');
    });

    it('handles missing end marker (backward compat)', () => {
      const filePath = path.join(tempDir, 'CLAUDE.md');
      // Old secretless-ai format without end marker, followed by another section
      const oldContent = `<!-- secretless:managed -->
## Secretless Mode
Old content here.

<!-- opena2a-shield:managed -->
## Shield
Shield stuff.
<!-- /opena2a-shield:managed -->
`;
      fs.writeFileSync(filePath, oldContent);

      const newSection = generateSecretlessSection([
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic', authHeader: 'test' },
      ]);

      upsertSecretlessSection(filePath, newSection, true);

      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toContain('`$ANTHROPIC_API_KEY`');
      expect(content).toContain('<!-- /secretless:managed -->');
      // Shield section preserved
      expect(content).toContain('opena2a-shield:managed');
      expect(content).toContain('Shield stuff.');
    });

    it('is idempotent -- re-running with same content returns false', () => {
      const filePath = path.join(tempDir, 'CLAUDE.md');
      const section = generateSecretlessSection([
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic', authHeader: 'test' },
      ]);

      // First upsert
      upsertSecretlessSection(filePath, section, true);

      // Second upsert with identical section
      const updated = upsertSecretlessSection(filePath, section, true);
      expect(updated).toBe(false);
    });
  });

  // --- parseExistingCredentials ---

  describe('parseExistingCredentials', () => {
    it('extracts credentials from existing section', () => {
      const filePath = path.join(tempDir, 'CLAUDE.md');
      const section = generateSecretlessSection([
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic Messages API', authHeader: 'x-api-key: $ANTHROPIC_API_KEY' },
        { envVar: 'OPENAI_API_KEY', service: 'OpenAI API', authHeader: 'Authorization: Bearer $OPENAI_API_KEY' },
      ]);
      fs.writeFileSync(filePath, section);

      const items = parseExistingCredentials(filePath);

      expect(items).toHaveLength(2);
      expect(items[0].envVar).toBe('ANTHROPIC_API_KEY');
      expect(items[0].service).toBe('Anthropic Messages API');
      expect(items[1].envVar).toBe('OPENAI_API_KEY');
    });

    it('returns empty array for file without section', () => {
      const filePath = path.join(tempDir, 'CLAUDE.md');
      fs.writeFileSync(filePath, '# Project\nNo secretless here.\n');

      const items = parseExistingCredentials(filePath);
      expect(items).toHaveLength(0);
    });

    it('returns empty array for nonexistent file', () => {
      const items = parseExistingCredentials(path.join(tempDir, 'nope.md'));
      expect(items).toHaveLength(0);
    });
  });

  // --- configureSecretlessForAiTools ---

  describe('configureSecretlessForAiTools', () => {
    it('creates CLAUDE.md with secretless section', () => {
      const items: SecretlessConfigItem[] = [
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic', authHeader: 'x-api-key: $ANTHROPIC_API_KEY' },
      ];

      const result = configureSecretlessForAiTools(tempDir, items);

      expect(result.toolsUpdated).toContain('CLAUDE.md');
      const content = fs.readFileSync(path.join(tempDir, 'CLAUDE.md'), 'utf-8');
      expect(content).toContain('<!-- secretless:managed -->');
      expect(content).toContain('`$ANTHROPIC_API_KEY`');
    });

    it('updates .cursorrules when it exists', () => {
      fs.writeFileSync(path.join(tempDir, '.cursorrules'), 'Existing cursor rules.\n');

      const items: SecretlessConfigItem[] = [
        { envVar: 'OPENAI_API_KEY', service: 'OpenAI', authHeader: 'Bearer $OPENAI_API_KEY' },
      ];

      const result = configureSecretlessForAiTools(tempDir, items);

      expect(result.toolsUpdated).toContain('CLAUDE.md');
      expect(result.toolsUpdated).toContain('.cursorrules');

      const content = fs.readFileSync(path.join(tempDir, '.cursorrules'), 'utf-8');
      expect(content).toContain('Existing cursor rules.');
      expect(content).toContain('`$OPENAI_API_KEY`');
    });

    it('skips .cursorrules when it does not exist', () => {
      const items: SecretlessConfigItem[] = [
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic', authHeader: 'test' },
      ];

      const result = configureSecretlessForAiTools(tempDir, items);

      expect(result.toolsUpdated).toContain('CLAUDE.md');
      expect(result.toolsSkipped).toContain('.cursorrules');
      expect(fs.existsSync(path.join(tempDir, '.cursorrules'))).toBe(false);
    });

    it('merges new credentials with existing ones', () => {
      // Create CLAUDE.md with an existing credential
      const existing = generateSecretlessSection([
        { envVar: 'OPENAI_API_KEY', service: 'OpenAI API', authHeader: 'Bearer $OPENAI_API_KEY' },
      ]);
      fs.writeFileSync(path.join(tempDir, 'CLAUDE.md'), existing);

      // Add a new credential
      const items: SecretlessConfigItem[] = [
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic', authHeader: 'x-api-key: $ANTHROPIC_API_KEY' },
      ];

      configureSecretlessForAiTools(tempDir, items);

      const content = fs.readFileSync(path.join(tempDir, 'CLAUDE.md'), 'utf-8');
      expect(content).toContain('`$OPENAI_API_KEY`');
      expect(content).toContain('`$ANTHROPIC_API_KEY`');
    });

    it('deduplicates by envVar (new overwrites old)', () => {
      const existing = generateSecretlessSection([
        { envVar: 'ANTHROPIC_API_KEY', service: 'Old Service', authHeader: 'old-header' },
      ]);
      fs.writeFileSync(path.join(tempDir, 'CLAUDE.md'), existing);

      const items: SecretlessConfigItem[] = [
        { envVar: 'ANTHROPIC_API_KEY', service: 'Anthropic Messages API', authHeader: 'x-api-key: $ANTHROPIC_API_KEY' },
      ];

      configureSecretlessForAiTools(tempDir, items);

      const content = fs.readFileSync(path.join(tempDir, 'CLAUDE.md'), 'utf-8');
      expect(content).toContain('Anthropic Messages API');
      expect(content).not.toContain('Old Service');
    });

    it('no-op when items list is empty', () => {
      const result = configureSecretlessForAiTools(tempDir, []);

      expect(result.toolsUpdated).toHaveLength(0);
      expect(result.toolsSkipped).toHaveLength(0);
      expect(fs.existsSync(path.join(tempDir, 'CLAUDE.md'))).toBe(false);
    });

    it('updates .github/copilot-instructions.md when it exists', () => {
      const ghDir = path.join(tempDir, '.github');
      fs.mkdirSync(ghDir, { recursive: true });
      fs.writeFileSync(path.join(ghDir, 'copilot-instructions.md'), 'Copilot instructions.\n');

      const items: SecretlessConfigItem[] = [
        { envVar: 'GITHUB_TOKEN', service: 'GitHub API', authHeader: 'Bearer $GITHUB_TOKEN' },
      ];

      const result = configureSecretlessForAiTools(tempDir, items);

      expect(result.toolsUpdated).toContain('.github/copilot-instructions.md');
      const content = fs.readFileSync(path.join(ghDir, 'copilot-instructions.md'), 'utf-8');
      expect(content).toContain('`$GITHUB_TOKEN`');
    });
  });
});
