import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

export type ProjectType = 'node' | 'go' | 'python' | 'unknown';

export interface ProjectInfo {
  type: ProjectType;
  name: string | null;
  version: string | null;
  hasMcp: boolean;
  hasEnv: boolean;
  hasGit: boolean;
}

export function detectProject(dir: string): ProjectInfo {
  const info: ProjectInfo = {
    type: 'unknown',
    name: null,
    version: null,
    hasMcp: false,
    hasEnv: false,
    hasGit: existsSync(resolve(dir, '.git')),
  };

  // Check for Node.js project
  const pkgPath = resolve(dir, 'package.json');
  if (existsSync(pkgPath)) {
    info.type = 'node';
    try {
      const { readFileSync } = require('node:fs');
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      info.name = pkg.name ?? null;
      info.version = pkg.version ?? null;
    } catch {
      // Ignore parse errors
    }
  }

  // Check for Go project
  if (existsSync(resolve(dir, 'go.mod'))) {
    info.type = 'go';
  }

  // Check for Python project
  if (
    existsSync(resolve(dir, 'pyproject.toml')) ||
    existsSync(resolve(dir, 'setup.py')) ||
    existsSync(resolve(dir, 'requirements.txt'))
  ) {
    info.type = 'python';
  }

  // Check for MCP configuration
  info.hasMcp =
    existsSync(resolve(dir, 'mcp.json')) ||
    existsSync(resolve(dir, '.mcp.json'));

  // Check for environment files
  info.hasEnv =
    existsSync(resolve(dir, '.env')) ||
    existsSync(resolve(dir, '.env.local'));

  return info;
}
