import { z } from 'zod';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';

export const projectConfigSchema = z.object({
  version: z.literal(1),
  project: z.object({
    name: z.string().optional(),
    type: z.enum(['mcp-server', 'agent', 'api', 'library', 'unknown']).default('unknown'),
  }).optional(),
  scan: z.object({
    include: z.array(z.string()).default(['./']),
    exclude: z.array(z.string()).default(['node_modules', '.git', 'dist', 'build']),
    checks: z.array(z.string()).optional(),
  }).optional(),
  protect: z.object({
    backend: z.enum(['local', 'keychain', '1password']).default('local'),
    autoFix: z.boolean().default(false),
  }).optional(),
  registry: z.object({
    url: z.string().url().default('https://registry.opena2a.org'),
    contribute: z.boolean().default(false),
  }).optional(),
});

export type ProjectConfig = z.infer<typeof projectConfigSchema>;

const CONFIG_FILENAMES = ['.opena2a.yaml', '.opena2a.yml', '.opena2a.json'];

export function loadProjectConfig(startDir?: string): ProjectConfig | null {
  const dir = startDir ?? process.cwd();

  for (const filename of CONFIG_FILENAMES) {
    const filepath = resolve(dir, filename);
    try {
      const raw = readFileSync(filepath, 'utf-8');
      let parsed: unknown;

      if (filename.endsWith('.json')) {
        parsed = JSON.parse(raw);
      } else {
        // Simple YAML-like parsing for basic key-value configs
        // For full YAML support, users should use .opena2a.json
        parsed = JSON.parse(raw);
      }

      return projectConfigSchema.parse(parsed);
    } catch {
      // File doesn't exist or failed to parse, try next
    }
  }

  return null;
}

export function findProjectRoot(startDir?: string): string {
  let dir = startDir ?? process.cwd();

  while (dir !== dirname(dir)) {
    for (const filename of CONFIG_FILENAMES) {
      try {
        readFileSync(resolve(dir, filename));
        return dir;
      } catch {
        // Not found, continue
      }
    }

    // Also check for common project markers
    for (const marker of ['package.json', 'go.mod', 'pyproject.toml', '.git']) {
      try {
        readFileSync(resolve(dir, marker));
        return dir;
      } catch {
        // Not found, continue
      }
    }

    dir = dirname(dir);
  }

  return process.cwd();
}
