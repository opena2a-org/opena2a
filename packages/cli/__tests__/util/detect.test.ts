import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { detectProject } from '../../src/util/detect.js';

describe('detectProject', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('detects Node.js project', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test', version: '1.0.0' }));
    const info = detectProject(tempDir);
    expect(info.type).toBe('node');
    expect(info.name).toBe('test');
    expect(info.version).toBe('1.0.0');
  });

  it('detects Go project', () => {
    fs.writeFileSync(path.join(tempDir, 'go.mod'), 'module example.com/test');
    const info = detectProject(tempDir);
    expect(info.type).toBe('go');
  });

  it('detects Python project via pyproject.toml', () => {
    fs.writeFileSync(path.join(tempDir, 'pyproject.toml'), '[project]\nname = "test"');
    const info = detectProject(tempDir);
    expect(info.type).toBe('python');
  });

  it('detects Python project via requirements.txt', () => {
    fs.writeFileSync(path.join(tempDir, 'requirements.txt'), 'flask\n');
    const info = detectProject(tempDir);
    expect(info.type).toBe('python');
  });

  it('detects Rust project', () => {
    fs.writeFileSync(path.join(tempDir, 'Cargo.toml'), '[package]\nname = "test"');
    const info = detectProject(tempDir);
    expect(info.type).toBe('rust');
  });

  it('detects Java project via pom.xml', () => {
    fs.writeFileSync(path.join(tempDir, 'pom.xml'), '<project></project>');
    const info = detectProject(tempDir);
    expect(info.type).toBe('java');
  });

  it('detects Java project via build.gradle', () => {
    fs.writeFileSync(path.join(tempDir, 'build.gradle'), 'apply plugin: "java"');
    const info = detectProject(tempDir);
    expect(info.type).toBe('java');
  });

  it('detects Java project via build.gradle.kts', () => {
    fs.writeFileSync(path.join(tempDir, 'build.gradle.kts'), 'plugins { java }');
    const info = detectProject(tempDir);
    expect(info.type).toBe('java');
  });

  it('detects Ruby project', () => {
    fs.writeFileSync(path.join(tempDir, 'Gemfile'), 'source "https://rubygems.org"');
    const info = detectProject(tempDir);
    expect(info.type).toBe('ruby');
  });

  it('detects Docker project when no language detected', () => {
    fs.writeFileSync(path.join(tempDir, 'Dockerfile'), 'FROM node:18');
    const info = detectProject(tempDir);
    expect(info.type).toBe('docker');
  });

  it('detects Docker via docker-compose.yml', () => {
    fs.writeFileSync(path.join(tempDir, 'docker-compose.yml'), 'version: "3"');
    const info = detectProject(tempDir);
    expect(info.type).toBe('docker');
  });

  it('detects Docker via compose.yml', () => {
    fs.writeFileSync(path.join(tempDir, 'compose.yml'), 'services: {}');
    const info = detectProject(tempDir);
    expect(info.type).toBe('docker');
  });

  it('falls back to generic when nothing detected', () => {
    fs.writeFileSync(path.join(tempDir, 'README.md'), '# Test');
    const info = detectProject(tempDir);
    expect(info.type).toBe('generic');
  });

  it('adds Docker as frameworkHint when language also detected', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'app' }));
    fs.writeFileSync(path.join(tempDir, 'Dockerfile'), 'FROM node:18');
    const info = detectProject(tempDir);
    expect(info.type).toBe('node');
    expect(info.frameworkHints).toContain('Docker');
  });

  it('adds MCP server as frameworkHint', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'mcp-app' }));
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), '{}');
    const info = detectProject(tempDir);
    expect(info.type).toBe('node');
    expect(info.hasMcp).toBe(true);
    expect(info.frameworkHints).toContain('MCP server');
  });

  it('includes multiple frameworkHints', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'full-app' }));
    fs.writeFileSync(path.join(tempDir, 'Dockerfile'), 'FROM node:18');
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), '{}');
    const info = detectProject(tempDir);
    expect(info.type).toBe('node');
    expect(info.frameworkHints).toContain('Docker');
    expect(info.frameworkHints).toContain('MCP server');
  });

  it('detects git repository', () => {
    fs.mkdirSync(path.join(tempDir, '.git'));
    const info = detectProject(tempDir);
    expect(info.hasGit).toBe(true);
  });

  it('detects environment files', () => {
    fs.writeFileSync(path.join(tempDir, '.env'), 'KEY=value');
    const info = detectProject(tempDir);
    expect(info.hasEnv).toBe(true);
  });

  it('frameworkHints is empty array when no secondary signals', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'bare' }));
    const info = detectProject(tempDir);
    expect(info.frameworkHints).toEqual([]);
  });
});
