import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export type ProjectType = 'node' | 'go' | 'python' | 'rust' | 'java' | 'ruby' | 'docker' | 'generic';

export interface ProjectInfo {
  type: ProjectType;
  name: string | null;
  version: string | null;
  hasMcp: boolean;
  hasEnv: boolean;
  hasGit: boolean;
  frameworkHints: string[];
}

export function detectProject(dir: string): ProjectInfo {
  const info: ProjectInfo = {
    type: 'generic',
    name: null,
    version: null,
    hasMcp: false,
    hasEnv: false,
    hasGit: existsSync(resolve(dir, '.git')),
    frameworkHints: [],
  };

  // Check for Node.js project
  const pkgPath = resolve(dir, 'package.json');
  if (existsSync(pkgPath)) {
    info.type = 'node';
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      info.name = pkg.name ?? null;
      info.version = pkg.version ?? null;
    } catch {
      // Ignore parse errors
    }
  }

  // Check for Go project
  const goModPath = resolve(dir, 'go.mod');
  if (existsSync(goModPath)) {
    info.type = 'go';
    try {
      const goModContent = readFileSync(goModPath, 'utf-8');
      const goMatch = goModContent.match(/^module\s+(\S+)/m);
      if (goMatch) {
        // Extract last path segment: github.com/org/name -> name
        const segments = goMatch[1].split('/');
        info.name = segments[segments.length - 1];
      }
    } catch {
      // Ignore read errors
    }
  }

  // Check for Python project
  const pyprojectPath = resolve(dir, 'pyproject.toml');
  if (existsSync(pyprojectPath)) {
    info.type = 'python';
    try {
      const pyContent = readFileSync(pyprojectPath, 'utf-8');
      const pyMatch = pyContent.match(/^\s*name\s*=\s*"([^"]+)"/m);
      if (pyMatch) {
        info.name = pyMatch[1];
      }
    } catch {
      // Ignore read errors
    }
  } else if (
    existsSync(resolve(dir, 'setup.py')) ||
    existsSync(resolve(dir, 'requirements.txt'))
  ) {
    info.type = 'python';
  }

  // Check for Rust project
  if (existsSync(resolve(dir, 'Cargo.toml'))) {
    info.type = 'rust';
  }

  // Check for Java project
  if (
    existsSync(resolve(dir, 'pom.xml')) ||
    existsSync(resolve(dir, 'build.gradle')) ||
    existsSync(resolve(dir, 'build.gradle.kts'))
  ) {
    info.type = 'java';
  }

  // Check for Ruby project
  if (existsSync(resolve(dir, 'Gemfile'))) {
    info.type = 'ruby';
  }

  // Docker: only if no primary language type was detected
  const hasDocker =
    existsSync(resolve(dir, 'Dockerfile')) ||
    existsSync(resolve(dir, 'docker-compose.yml')) ||
    existsSync(resolve(dir, 'docker-compose.yaml')) ||
    existsSync(resolve(dir, 'compose.yml'));

  if (hasDocker && info.type === 'generic') {
    info.type = 'docker';
  }

  // Framework hints: secondary signals shown alongside the primary type
  if (hasDocker && info.type !== 'docker') {
    info.frameworkHints.push('Docker');
  }

  // Check for MCP configuration
  info.hasMcp =
    existsSync(resolve(dir, 'mcp.json')) ||
    existsSync(resolve(dir, '.mcp.json')) ||
    existsSync(resolve(dir, '.mcp', 'config.json'));

  if (info.hasMcp) {
    info.frameworkHints.push('MCP server');
  }

  // Check for environment files
  info.hasEnv =
    existsSync(resolve(dir, '.env')) ||
    existsSync(resolve(dir, '.env.local'));

  return info;
}
