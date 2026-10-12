import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadProjectConfig, findProjectRoot } from './config.js';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'opena2a-config-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('loadProjectConfig', () => {
  it('parses .opena2a.yaml as YAML', () => {
    writeFileSync(
      join(dir, '.opena2a.yaml'),
      [
        'version: 1',
        'project:',
        '  name: demo',
        '  type: agent',
        'scan:',
        '  exclude:',
        '    - vendor',
        '    - fixtures',
        'protect:',
        '  autoFix: true',
        '',
      ].join('\n'),
    );

    const config = loadProjectConfig(dir);

    expect(config).not.toBeNull();
    expect(config?.project).toEqual({ name: 'demo', type: 'agent' });
    expect(config?.scan?.exclude).toEqual(['vendor', 'fixtures']);
    expect(config?.scan?.include).toEqual(['./']);
    expect(config?.protect).toEqual({ backend: 'local', autoFix: true });
  });

  it('parses .opena2a.yml as YAML', () => {
    writeFileSync(join(dir, '.opena2a.yml'), 'version: 1\nscan:\n  exclude: [vendor]\n');

    expect(loadProjectConfig(dir)?.scan?.exclude).toEqual(['vendor']);
  });

  it('reads .opena2a.json', () => {
    writeFileSync(join(dir, '.opena2a.json'), JSON.stringify({ version: 1, project: { name: 'dot-json' } }));

    expect(loadProjectConfig(dir)?.project?.name).toBe('dot-json');
  });

  it('reads opena2a.config.json', () => {
    writeFileSync(join(dir, 'opena2a.config.json'), JSON.stringify({ version: 1, project: { name: 'config-json' } }));

    expect(loadProjectConfig(dir)?.project?.name).toBe('config-json');
  });

  it('prefers .opena2a.yaml over the other names', () => {
    writeFileSync(join(dir, '.opena2a.yaml'), 'version: 1\nproject:\n  name: from-yaml\n');
    writeFileSync(join(dir, '.opena2a.yml'), 'version: 1\nproject:\n  name: from-yml\n');
    writeFileSync(join(dir, '.opena2a.json'), JSON.stringify({ version: 1, project: { name: 'from-json' } }));
    writeFileSync(join(dir, 'opena2a.config.json'), JSON.stringify({ version: 1, project: { name: 'from-config-json' } }));

    expect(loadProjectConfig(dir)?.project?.name).toBe('from-yaml');
  });

  it('keeps a date-like YAML scalar a string', () => {
    writeFileSync(join(dir, '.opena2a.yaml'), 'version: 1\nproject:\n  name: 2026-10-11\n');

    expect(loadProjectConfig(dir)?.project?.name).toBe('2026-10-11');
  });

  it('falls through to the next name when a YAML file does not parse', () => {
    writeFileSync(join(dir, '.opena2a.yaml'), 'version: 1\nproject: [unclosed\n');
    writeFileSync(join(dir, 'opena2a.config.json'), JSON.stringify({ version: 1, project: { name: 'fallback' } }));

    expect(loadProjectConfig(dir)?.project?.name).toBe('fallback');
  });

  it('falls through to the next name when a YAML file carries a tag that would build code', () => {
    writeFileSync(
      join(dir, '.opena2a.yaml'),
      'version: 1\nproject:\n  name: from-yaml\nhook: !!js/function "function () { return 1; }"\n',
    );
    writeFileSync(join(dir, 'opena2a.config.json'), JSON.stringify({ version: 1, project: { name: 'fallback' } }));

    expect(loadProjectConfig(dir)?.project?.name).toBe('fallback');
  });

  it('returns null, without throwing, for YAML nested too deep to parse', () => {
    writeFileSync(join(dir, '.opena2a.yaml'), `version: 1\nextra: ${'['.repeat(100_000)}${']'.repeat(100_000)}\n`);

    expect(loadProjectConfig(dir)).toBeNull();
  });

  it('loads a small YAML file whose aliases name a billion values without copying them', () => {
    const lines = ['version: 1', 'l0: &l0 [x, x, x, x, x, x, x, x, x, x]'];
    for (let i = 1; i <= 9; i++) lines.push(`l${i}: &l${i} [${Array(10).fill(`*l${i - 1}`).join(', ')}]`);
    writeFileSync(join(dir, '.opena2a.yaml'), `${lines.join('\n')}\n`);

    expect(loadProjectConfig(dir)).toEqual({ version: 1 });
  });

  it('returns null when the only file fails schema validation', () => {
    writeFileSync(join(dir, '.opena2a.yaml'), 'version: 2\n');

    expect(loadProjectConfig(dir)).toBeNull();
  });

  it('returns null when no config file exists', () => {
    expect(loadProjectConfig(dir)).toBeNull();
  });
});

describe('findProjectRoot', () => {
  it('treats a directory holding opena2a.config.json as the root', () => {
    writeFileSync(join(dir, 'opena2a.config.json'), JSON.stringify({ version: 1 }));

    expect(findProjectRoot(dir)).toBe(dir);
  });
});
