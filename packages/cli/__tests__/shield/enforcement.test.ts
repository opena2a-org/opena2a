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

// Import after mocks so the modules pick up the mocked homedir.
const { writeEvent, readEvents, getShieldDir } =
  await import('../../src/shield/events.js');

const { loadPolicy, evaluatePolicy, savePolicy, createDefaultPolicy } =
  await import('../../src/shield/policy.js');

const { getExpectedHookContent } =
  await import('../../src/shield/integrity.js');

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-enforcement-test-'));
  _mockHomeDir = tempDir;
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Helper: create and save a policy with a given mode
// ---------------------------------------------------------------------------

function setupPolicy(mode: 'enforce' | 'monitor' | 'adaptive') {
  const policy = createDefaultPolicy(mode);
  // Default policy already denies: ['aws', 'gcloud', 'az', 'kubectl', 'terraform', 'rm -rf']
  // and allows: ['git', 'npm', 'node', 'npx', 'tsc', 'eslint', 'prettier', ...]
  const shieldDir = getShieldDir();
  const policyPath = path.join(shieldDir, 'policy.yaml');
  savePolicy(policy, policyPath);
  return policy;
}

// ===========================================================================
// 1. Enforce mode: denied binary returns blocked decision
// ===========================================================================

describe('enforce mode evaluation', () => {
  it('blocks a denied binary with exit-code-equivalent outcome', () => {
    const policy = setupPolicy('enforce');

    const decision = evaluatePolicy(policy, null, 'processes', 'aws');

    expect(decision.outcome).toBe('blocked');
    expect(decision.allowed).toBe(false);
    expect(decision.rule).toContain('processes.deny');
  });

  it('allows an explicitly allowed binary', () => {
    const policy = setupPolicy('enforce');

    const decision = evaluatePolicy(policy, null, 'processes', 'git');

    expect(decision.outcome).toBe('allowed');
    expect(decision.allowed).toBe(true);
    expect(decision.rule).toContain('processes.allow');
  });

  it('allows an unknown binary (no matching rule)', () => {
    const policy = setupPolicy('enforce');

    const decision = evaluatePolicy(policy, null, 'processes', 'myapp');

    expect(decision.outcome).toBe('allowed');
    expect(decision.allowed).toBe(true);
    expect(decision.rule).toContain('no-match');
  });
});

// ===========================================================================
// 2. Monitor mode: denied binary returns monitored (not blocked)
// ===========================================================================

describe('monitor mode evaluation', () => {
  it('monitors a denied binary instead of blocking', () => {
    const policy = setupPolicy('monitor');

    const decision = evaluatePolicy(policy, null, 'processes', 'kubectl');

    expect(decision.outcome).toBe('monitored');
    expect(decision.allowed).toBe(true);
    expect(decision.rule).toContain('processes.deny');
  });

  it('allows an explicitly allowed binary', () => {
    const policy = setupPolicy('monitor');

    const decision = evaluatePolicy(policy, null, 'processes', 'npm');

    expect(decision.outcome).toBe('allowed');
    expect(decision.allowed).toBe(true);
  });
});

// ===========================================================================
// 3. Enforcement events are written for blocked commands
// ===========================================================================

describe('enforcement event logging', () => {
  it('writes a high-severity event when a command is blocked', () => {
    getShieldDir();

    writeEvent({
      source: 'shield',
      category: 'enforcement',
      severity: 'high',
      agent: null,
      sessionId: null,
      action: 'command.blocked',
      target: 'aws s3 ls',
      outcome: 'blocked',
      detail: { rule: 'processes.deny:aws', mode: 'enforce' },
      orgId: null,
      managed: false,
      agentId: null,
    });

    const events = readEvents({ category: 'enforcement' });
    expect(events.length).toBe(1);
    expect(events[0].action).toBe('command.blocked');
    expect(events[0].severity).toBe('high');
    expect(events[0].outcome).toBe('blocked');
    expect(events[0].target).toBe('aws s3 ls');
    expect(events[0].source).toBe('shield');
  });

  it('writes a medium-severity event when a command is monitored', () => {
    getShieldDir();

    writeEvent({
      source: 'shield',
      category: 'enforcement',
      severity: 'medium',
      agent: null,
      sessionId: null,
      action: 'command.monitored',
      target: 'kubectl get pods',
      outcome: 'monitored',
      detail: { rule: 'processes.deny:kubectl', mode: 'monitor' },
      orgId: null,
      managed: false,
      agentId: null,
    });

    const events = readEvents({ category: 'enforcement' });
    expect(events.length).toBe(1);
    expect(events[0].action).toBe('command.monitored');
    expect(events[0].severity).toBe('medium');
    expect(events[0].outcome).toBe('monitored');
    expect(events[0].target).toBe('kubectl get pods');
  });

  it('does not write an event for allowed commands', () => {
    getShieldDir();

    const policy = setupPolicy('enforce');
    const decision = evaluatePolicy(policy, null, 'processes', 'git');

    // Allowed decisions should not trigger event writes
    expect(decision.outcome).toBe('allowed');

    const events = readEvents({ category: 'enforcement' });
    expect(events.length).toBe(0);
  });
});

// ===========================================================================
// 4. Command string parsing extracts the first word as the binary
// ===========================================================================

describe('command string parsing for binary extraction', () => {
  it('extracts binary from a simple command', () => {
    const policy = setupPolicy('enforce');

    // Simulate what handleEvaluate does: extract first word from command
    const commandString = 'aws s3 ls';
    const firstWord = commandString.trim().split(/[\s|;&]/)[0] ?? commandString;

    const decision = evaluatePolicy(policy, null, 'processes', firstWord);
    expect(decision.outcome).toBe('blocked');
  });

  it('extracts binary from a piped command', () => {
    const policy = setupPolicy('enforce');

    const commandString = 'kubectl get pods | grep running';
    const firstWord = commandString.trim().split(/[\s|;&]/)[0] ?? commandString;

    const decision = evaluatePolicy(policy, null, 'processes', firstWord);
    expect(decision.outcome).toBe('blocked');
  });

  it('handles an allowed command with arguments', () => {
    const policy = setupPolicy('enforce');

    const commandString = 'git push origin main';
    const firstWord = commandString.trim().split(/[\s|;&]/)[0] ?? commandString;

    const decision = evaluatePolicy(policy, null, 'processes', firstWord);
    expect(decision.outcome).toBe('allowed');
  });
});

// ===========================================================================
// 5. Shell hook content checks exit codes
// ===========================================================================

describe('shell hook enforcement integration', () => {
  it('zsh hook checks exit code and returns 1 on failure', () => {
    const hook = getExpectedHookContent('zsh');

    // The hook should use "if ! opena2a shield evaluate" pattern
    expect(hook).toContain('if ! opena2a shield evaluate "$1" 2>/dev/null; then');
    expect(hook).toContain('return 1');
    // Should NOT contain the old non-exit-code-checking form
    expect(hook).not.toMatch(/^\s*opena2a shield evaluate "\$1"\s*$/m);
  });

  it('bash hook checks exit code and returns 1 on failure', () => {
    const hook = getExpectedHookContent('bash');

    expect(hook).toContain('if ! opena2a shield evaluate "$BASH_COMMAND" 2>/dev/null; then');
    expect(hook).toContain('return 1');
    expect(hook).not.toMatch(/^\s*opena2a shield evaluate "\$BASH_COMMAND"\s*$/m);
  });
});

// ===========================================================================
// 6. Integration: enforce mode full flow
// ===========================================================================

describe('enforcement full flow integration', () => {
  it('enforce mode with denied binary produces blocked outcome and event', () => {
    const policy = setupPolicy('enforce');

    // Simulate the evaluate flow: parse command -> evaluate -> write event
    const commandString = 'terraform apply';
    const firstWord = commandString.trim().split(/[\s|;&]/)[0] ?? commandString;
    const decision = evaluatePolicy(policy, null, 'processes', firstWord);

    expect(decision.outcome).toBe('blocked');

    // Write the event as handleEvaluate would
    writeEvent({
      source: 'shield',
      category: 'enforcement',
      severity: 'high',
      agent: null,
      sessionId: null,
      action: 'command.blocked',
      target: commandString,
      outcome: 'blocked',
      detail: { rule: decision.rule, mode: policy.mode },
      orgId: null,
      managed: false,
      agentId: null,
    });

    const events = readEvents({ category: 'enforcement' });
    expect(events.length).toBe(1);
    expect(events[0].target).toBe('terraform apply');
    expect(events[0].severity).toBe('high');
  });

  it('monitor mode with denied binary produces monitored outcome and medium event', () => {
    const policy = setupPolicy('monitor');

    const commandString = 'gcloud compute list';
    const firstWord = commandString.trim().split(/[\s|;&]/)[0] ?? commandString;
    const decision = evaluatePolicy(policy, null, 'processes', firstWord);

    expect(decision.outcome).toBe('monitored');

    writeEvent({
      source: 'shield',
      category: 'enforcement',
      severity: 'medium',
      agent: null,
      sessionId: null,
      action: 'command.monitored',
      target: commandString,
      outcome: 'monitored',
      detail: { rule: decision.rule, mode: policy.mode },
      orgId: null,
      managed: false,
      agentId: null,
    });

    const events = readEvents({ category: 'enforcement' });
    expect(events.length).toBe(1);
    expect(events[0].severity).toBe('medium');
    expect(events[0].action).toBe('command.monitored');
  });

  it('allowed commands produce no enforcement events', () => {
    const policy = setupPolicy('enforce');

    const commandString = 'npm install lodash';
    const firstWord = commandString.trim().split(/[\s|;&]/)[0] ?? commandString;
    const decision = evaluatePolicy(policy, null, 'processes', firstWord);

    expect(decision.outcome).toBe('allowed');

    // No event should be written for allowed commands
    const events = readEvents({ category: 'enforcement' });
    expect(events.length).toBe(0);
  });
});
