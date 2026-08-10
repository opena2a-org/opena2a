import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { knownCommandNames } from '../../src/natural/known-commands.js';
import type { ShieldEvent, PolicyViolation } from '../../src/shield/types.js';
import {
  FINDING_CATALOG,
  classifyEvent,
  classifyEvents,
  classifyViolation,
  getRemediation,
} from '../../src/shield/findings.js';

// ---------------------------------------------------------------------------
// Helper: build a minimal ShieldEvent
// ---------------------------------------------------------------------------

function makeEvent(overrides: Partial<ShieldEvent> = {}): ShieldEvent {
  return {
    id: 'test-id',
    timestamp: '2026-03-01T00:00:00.000Z',
    version: 1,
    source: 'shield',
    category: 'test',
    severity: 'info',
    agent: null,
    sessionId: null,
    action: 'test-action',
    target: 'test-target',
    outcome: 'allowed',
    detail: {},
    prevHash: 'abc',
    eventHash: 'def',
    orgId: null,
    managed: false,
    agentId: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// FINDING_CATALOG
// ---------------------------------------------------------------------------

describe('FINDING_CATALOG', () => {
  it('contains 15 finding definitions', () => {
    expect(Object.keys(FINDING_CATALOG).length).toBe(15);
  });

  it('all findings have required fields', () => {
    for (const [id, def] of Object.entries(FINDING_CATALOG)) {
      expect(def.id).toBe(id);
      expect(def.title).toBeTruthy();
      expect(def.severity).toBeTruthy();
      expect(def.category).toBeTruthy();
      expect(def.owaspAgentic).toMatch(/^ASI\d+$/);
      expect(def.mitreAtlas).toMatch(/^AML\.T\d+$/);
      // `remediation` is checked structurally, not for truthiness -- see
      // "remediation commands resolve against the CLI surface" below.
      expect(def.description).toBeTruthy();
    }
  });

  it('finding IDs follow SHIELD-{CAT}-{NUM} pattern', () => {
    for (const id of Object.keys(FINDING_CATALOG)) {
      expect(id).toMatch(/^SHIELD-[A-Z]+-\d{3}$/);
    }
  });
});

// ---------------------------------------------------------------------------
// Remediation structural guard (#231)
//
// A remediation is the only exit a finding offers. `SHIELD-INT-002` shipped
// `opena2a shield recover --forensic`, where `--forensic` was registered and
// documented but never read: `handleRecover` branched only on `options.verify`.
// Following the remediation verbatim therefore changed nothing, and the
// finding could not be cleared. Truthiness testing cannot see that.
//
// This guard resolves every remediation against the CLI surface itself:
// command names from `knownCommandNames()` (the same list Commander routing
// uses), options parsed out of the registrations in `src/index.ts`, and
// subcommands parsed out of the dispatchers that consume them. A registered
// flag with no read site anywhere in `src/` is the `--forensic` defect and
// fails here.
// ---------------------------------------------------------------------------

const SRC_ROOT = path.resolve(__dirname, '..', '..', 'src');
const INDEX_TS = path.join(SRC_ROOT, 'index.ts');

/** Executables a remediation may invoke. Anything else is a typo or a gap. */
const ALLOWED_EXECUTABLES = new Set(['opena2a', 'git', 'gh', 'npm', 'go']);

function listTsFiles(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue;
      listTsFiles(full, out);
    } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
      out.push(full);
    }
  }
  return out;
}

/** Long flags (`--x`) declared in a Commander flag spec such as `--dir <path>`. */
function longFlags(spec: string): string[] {
  return spec.match(/--[a-z][a-z0-9-]*/g) ?? [];
}

/** `--archive-log` -> `archiveLog`, the property Commander exposes it as. */
function optionProperty(flag: string): string {
  return flag.replace(/^--/, '').replace(/-([a-z])/g, (_m, c: string) => c.toUpperCase());
}

interface ProgramSurface {
  /** Options registered on `program` itself; available to every command. */
  globals: Set<string>;
  /** Long options registered per command name (and per alias). */
  byCommand: Map<string, Set<string>>;
}

/**
 * Parse the Commander registrations out of `src/index.ts`.
 *
 * The program is built inside `main()`, which parses `process.argv` and runs
 * the CLI on import, so it cannot be constructed from a test. The
 * registration chain is read from source instead: everything before the first
 * `.command('...')` is registered on `program` (global), and each
 * `.command('<name> ...')` owns the `.option()` calls up to the next one.
 */
function parseProgramSurface(): ProgramSurface {
  const src = fs.readFileSync(INDEX_TS, 'utf-8');

  const starts: { name: string; index: number }[] = [];
  const commandRe = /\.command\(\s*'([^']+)'/g;
  let m: RegExpExecArray | null;
  while ((m = commandRe.exec(src)) !== null) {
    starts.push({ name: m[1].trim().split(/\s+/)[0], index: m.index });
  }

  const optionsIn = (block: string): string[] => {
    const found: string[] = [];
    const optionRe = /\.option\(\s*'([^']+)'/g;
    let om: RegExpExecArray | null;
    while ((om = optionRe.exec(block)) !== null) found.push(...longFlags(om[1]));
    return found;
  };

  const globals = new Set(optionsIn(src.slice(0, starts[0]?.index ?? src.length)));
  const byCommand = new Map<string, Set<string>>();

  for (let i = 0; i < starts.length; i++) {
    const block = src.slice(starts[i].index, starts[i + 1]?.index ?? src.length);
    const flags = new Set(optionsIn(block));
    const names = [starts[i].name];
    const aliasRe = /\.alias(?:es)?\(\s*\[?\s*'([^']+)'/g;
    let am: RegExpExecArray | null;
    while ((am = aliasRe.exec(block)) !== null) names.push(am[1]);
    for (const name of names) {
      const existing = byCommand.get(name) ?? new Set<string>();
      for (const f of flags) existing.add(f);
      byCommand.set(name, existing);
    }
  }

  return { globals, byCommand };
}

/**
 * Subcommands a `<command> [subcommand]` dispatcher actually handles, read
 * from the dispatcher rather than from its help text.
 */
function parseSubcommands(): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();

  // shield: `switch (options.subcommand) { case 'init': ... }`
  const shieldSrc = fs.readFileSync(path.join(SRC_ROOT, 'commands', 'shield.ts'), 'utf-8');
  const switchStart = shieldSrc.indexOf('switch (options.subcommand)');
  if (switchStart >= 0) {
    const body = shieldSrc.slice(switchStart, shieldSrc.indexOf('\n}', switchStart));
    const cases = body.match(/case '([a-z-]+)':/g) ?? [];
    out.set('shield', new Set(cases.map(c => c.replace(/case '|':/g, ''))));
  }

  // guard: `const validSubs = ['sign', 'verify', ...]` inside its registration.
  const indexSrc = fs.readFileSync(INDEX_TS, 'utf-8');
  const guardAt = indexSrc.indexOf(".command('guard");
  if (guardAt >= 0) {
    const validSubs = /const validSubs = \[([^\]]+)\]/.exec(indexSrc.slice(guardAt));
    if (validSubs) {
      out.set('guard', new Set((validSubs[1].match(/'([^']+)'/g) ?? []).map(s => s.replace(/'/g, ''))));
    }
  }

  return out;
}

const SURFACE = parseProgramSurface();
const SUBCOMMANDS = parseSubcommands();
const SRC_TEXTS = listTsFiles(SRC_ROOT).map(f => ({
  file: path.relative(SRC_ROOT, f),
  text: fs.readFileSync(f, 'utf-8'),
}));

/**
 * Files where a flag reaching `src/` at all counts as a read site.
 *
 * Property access (`options.forensic`), not a method call (`.action(` is the
 * Commander handler, not a read of `--action`), and not a declaration -- an
 * interface field or a help-table entry names the flag without consuming it.
 */
function readSites(flag: string): string[] {
  const prop = optionProperty(flag);
  const re = new RegExp(`\\.${prop}\\b(?!\\s*\\()`);
  return SRC_TEXTS.filter(({ text }) => re.test(text)).map(({ file }) => file);
}

/** Split a remediation into the shell commands it actually runs. */
function commandSegments(remediation: string): string[] {
  return remediation.split(/\s*(?:&&|\|\|)\s*/).map(s => s.trim()).filter(Boolean);
}

describe('remediation commands resolve against the CLI surface (#231)', () => {
  it('parses a plausible program surface (guards the parser itself)', () => {
    // A parser that silently returned nothing would make every assertion
    // below vacuous, so pin known-good and known-bad facts about it.
    expect(SURFACE.byCommand.size).toBeGreaterThan(20);
    expect(SURFACE.byCommand.get('shield')).toBeDefined();
    expect(SURFACE.byCommand.get('shield')!.has('--verify')).toBe(true);
    expect(SURFACE.byCommand.get('shield')!.has('--not-a-real-flag')).toBe(false);
    expect(SURFACE.byCommand.get('protect')!.has('--dir')).toBe(true);
    expect(SUBCOMMANDS.get('shield')!.has('recover')).toBe(true);
    expect(SUBCOMMANDS.get('shield')!.has('not-a-subcommand')).toBe(false);
    expect(SUBCOMMANDS.get('guard')!.has('resign')).toBe(true);
  });

  it('detects the absence of a read site (guards the read-site scan)', () => {
    // The read-site scan must be able to say "no", or an unread flag passes.
    expect(readSites('--dir').length).toBeGreaterThan(0);
    expect(readSites('--never-registered-placeholder')).toEqual([]);
  });

  for (const [id, def] of Object.entries(FINDING_CATALOG)) {
    describe(id, () => {
      const segments = commandSegments(def.remediation);

      it('is a non-empty sequence of known executables', () => {
        expect(def.remediation.trim().length).toBeGreaterThan(0);
        expect(segments.length).toBeGreaterThan(0);
        for (const segment of segments) {
          const exe = segment.split(/\s+/)[0];
          expect(
            ALLOWED_EXECUTABLES.has(exe),
            `${id}: remediation segment "${segment}" invokes unknown executable "${exe}"`,
          ).toBe(true);
        }
      });

      it('names commands and subcommands the CLI registers', () => {
        for (const segment of segments) {
          const tokens = segment.split(/\s+/);
          if (tokens[0] !== 'opena2a') continue;

          const command = tokens[1];
          expect(
            knownCommandNames().includes(command),
            `${id}: remediation "${segment}" runs unregistered command "${command}"`,
          ).toBe(true);

          const subcommands = SUBCOMMANDS.get(command);
          const sub = tokens[2];
          if (subcommands && sub && !sub.startsWith('-')) {
            expect(
              subcommands.has(sub),
              `${id}: remediation "${segment}" runs unhandled subcommand "${command} ${sub}"`,
            ).toBe(true);
          }
        }
      });

      it('cites only flags that are registered and read', () => {
        for (const segment of segments) {
          const tokens = segment.split(/\s+/);
          if (tokens[0] !== 'opena2a') continue;
          const command = tokens[1];
          const registered = SURFACE.byCommand.get(command) ?? new Set<string>();

          for (const flag of tokens.filter(t => t.startsWith('--'))) {
            expect(
              registered.has(flag) || SURFACE.globals.has(flag),
              `${id}: remediation "${segment}" cites "${flag}", which is not a registered ` +
                `option on "${command}". allowUnknownOption() swallows it, so the flag is a no-op.`,
            ).toBe(true);

            expect(
              readSites(flag),
              `${id}: remediation "${segment}" cites "${flag}", which is registered but never ` +
                `read in src/. The command ignores it, so following the remediation changes nothing.`,
            ).not.toEqual([]);
          }
        }
      });
    });
  }
});

// ---------------------------------------------------------------------------
// classifyEvent
// ---------------------------------------------------------------------------

describe('classifyEvent', () => {
  it('classifies secretless Anthropic credential as SHIELD-CRED-001', () => {
    const event = makeEvent({
      source: 'secretless',
      target: 'anthropic-key-file',
      action: 'credential-scan',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-CRED-001');
    expect(finding?.severity).toBe('critical');
  });

  it('classifies secretless OpenAI credential as SHIELD-CRED-002', () => {
    const event = makeEvent({
      source: 'secretless',
      target: 'openai-api-key',
      action: 'credential-scan',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-CRED-002');
  });

  it('classifies secretless GitHub credential as SHIELD-CRED-003', () => {
    const event = makeEvent({
      source: 'secretless',
      target: 'github-token',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-CRED-003');
  });

  it('classifies generic secretless event as SHIELD-CRED-004', () => {
    const event = makeEvent({
      source: 'secretless',
      target: 'some-api-key',
      action: 'found',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-CRED-004');
  });

  it('classifies credential-finding category as CRED', () => {
    // Real credential findings come from secretless, not shield
    const event = makeEvent({
      source: 'secretless',
      category: 'credential-finding',
      target: 'openai-key',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-CRED-002');
  });

  it('classifies configguard tamper as SHIELD-INT-001', () => {
    const event = makeEvent({
      source: 'configguard',
      action: 'tamper-detected',
      severity: 'critical',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-INT-001');
  });

  it('classifies configguard unsigned as SHIELD-INT-003', () => {
    const event = makeEvent({
      source: 'configguard',
      action: 'unsigned',
      category: 'config-unsigned',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-INT-003');
  });

  it('classifies ARP process.spawn as SHIELD-PROC-001', () => {
    const event = makeEvent({
      source: 'arp',
      category: 'process.spawn',
      severity: 'high',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-PROC-001');
  });

  it('classifies ARP network event as SHIELD-PROC-002', () => {
    const event = makeEvent({
      source: 'arp',
      category: 'network.connect',
      severity: 'medium',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-PROC-002');
  });

  it('classifies ARP behavioral anomaly as SHIELD-BAS-001', () => {
    const event = makeEvent({
      source: 'arp',
      category: 'behavioral-anomaly',
      severity: 'medium',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-BAS-001');
  });

  it('classifies registry high-severity as SHIELD-SUP-001', () => {
    const event = makeEvent({
      source: 'registry',
      severity: 'high',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-SUP-001');
  });

  it('classifies registry medium-severity as SHIELD-SUP-002', () => {
    const event = makeEvent({
      source: 'registry',
      severity: 'medium',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-SUP-002');
  });

  it('classifies blocked outcome as SHIELD-POL-002', () => {
    const event = makeEvent({
      source: 'arp',
      category: 'policy',
      outcome: 'blocked',
      severity: 'high',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-POL-002');
  });

  it('classifies monitored high-severity as SHIELD-POL-003', () => {
    const event = makeEvent({
      source: 'arp',
      category: 'policy',
      outcome: 'monitored',
      severity: 'high',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-POL-003');
  });

  it('returns null for shield diagnostic events', () => {
    const event = makeEvent({
      source: 'shield',
      category: 'posture-assessment',
      severity: 'info',
    });
    expect(classifyEvent(event)).toBeNull();
  });

  it('returns null for benign allowed events', () => {
    const event = makeEvent({
      outcome: 'allowed',
      severity: 'info',
    });
    expect(classifyEvent(event)).toBeNull();
  });

  it('returns null for shield.posture diagnostic events', () => {
    const event = makeEvent({
      source: 'shield',
      category: 'shield.posture',
      severity: 'info',
      outcome: 'monitored',
    });
    expect(classifyEvent(event)).toBeNull();
  });

  it('returns null for shield.credential diagnostic events', () => {
    const event = makeEvent({
      source: 'shield',
      category: 'shield.credential',
      severity: 'medium',
      outcome: 'monitored',
    });
    expect(classifyEvent(event)).toBeNull();
  });

  it('returns null for shield enforcement events', () => {
    const event = makeEvent({
      source: 'shield',
      category: 'policy-evaluation',
      severity: 'high',
      outcome: 'blocked',
    });
    expect(classifyEvent(event)).toBeNull();
  });

  it('still classifies shield integrity failures as SHIELD-INT-002', () => {
    const event = makeEvent({
      source: 'shield',
      category: 'integrity',
      severity: 'critical',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-INT-002');
  });
});

// ---------------------------------------------------------------------------
// classifyEvents
// ---------------------------------------------------------------------------

describe('classifyEvents', () => {
  it('deduplicates findings by ID', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key', timestamp: '2026-03-01T01:00:00Z' }),
      makeEvent({ source: 'secretless', target: 'anthropic-key2', timestamp: '2026-03-01T02:00:00Z' }),
    ];
    const classified = classifyEvents(events);
    const cred001 = classified.find(c => c.finding.id === 'SHIELD-CRED-001');
    expect(cred001).toBeDefined();
    expect(cred001!.count).toBe(2);
    expect(cred001!.firstSeen).toBe('2026-03-01T01:00:00Z');
    expect(cred001!.lastSeen).toBe('2026-03-01T02:00:00Z');
  });

  it('sorts by severity (critical first), then by count', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key' }),       // CRED-001 critical
      makeEvent({ source: 'arp', category: 'process.spawn' }),            // PROC-001 high
      makeEvent({ source: 'arp', category: 'network.connect' }),          // PROC-002 medium
      makeEvent({ source: 'arp', category: 'network.connect' }),          // PROC-002 medium (dup)
    ];
    const classified = classifyEvents(events);
    expect(classified[0].finding.id).toBe('SHIELD-CRED-001');   // critical
    expect(classified[1].finding.id).toBe('SHIELD-PROC-001');   // high
    expect(classified[2].finding.id).toBe('SHIELD-PROC-002');   // medium, count 2
  });

  it('limits examples to 3', () => {
    const events = Array.from({ length: 5 }, (_, i) =>
      makeEvent({ source: 'secretless', target: `anthropic-key-${i}`, timestamp: `2026-03-0${i + 1}T00:00:00Z` }),
    );
    const classified = classifyEvents(events);
    expect(classified[0].examples.length).toBe(3);
    expect(classified[0].count).toBe(5);
  });

  it('returns empty array for empty events', () => {
    expect(classifyEvents([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// classifyViolation
// ---------------------------------------------------------------------------

describe('classifyViolation', () => {
  function makeViolation(overrides: Partial<PolicyViolation> = {}): PolicyViolation {
    return {
      action: 'test-action',
      target: 'test-target',
      agent: 'claude-code',
      count: 1,
      severity: 'high',
      recommendation: 'Review and consider blocking',
      ...overrides,
    };
  }

  it('classifies credential-related violations', () => {
    const v = makeViolation({ action: 'credential.access', target: 'anthropic-api' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-CRED-001');
  });

  it('classifies process violations', () => {
    const v = makeViolation({ action: 'process.spawn', target: '/usr/bin/curl' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-PROC-001');
  });

  it('classifies network violations', () => {
    const v = makeViolation({ action: 'network.connect', target: 'evil.com' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-PROC-002');
  });

  it('classifies config violations', () => {
    const v = makeViolation({ action: 'config.tamper', target: '.env' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-INT-001');
  });

  it('defaults to POL-002 for high-severity unknowns', () => {
    const v = makeViolation({ action: 'unknown', severity: 'high' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-POL-002');
  });

  it('defaults to POL-003 for medium-severity unknowns', () => {
    const v = makeViolation({ action: 'unknown', severity: 'medium' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-POL-003');
  });
});

// ---------------------------------------------------------------------------
// getRemediation
// ---------------------------------------------------------------------------

describe('getRemediation', () => {
  it('returns remediation for known finding', () => {
    const cmd = getRemediation('SHIELD-CRED-001');
    expect(cmd).toContain('opena2a protect');
  });

  it('returns default for unknown finding', () => {
    const cmd = getRemediation('SHIELD-UNKNOWN-999');
    expect(cmd).toBe('opena2a shield selfcheck');
  });
});
