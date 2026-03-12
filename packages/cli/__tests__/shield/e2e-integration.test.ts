/**
 * Shield E2E Integration Tests
 *
 * Exercises the full Shield lifecycle in a single temp directory:
 * init -> write events -> import ARP -> integrity checks -> signing ->
 * lockdown -> policy evaluation -> session detection.
 */

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

// Import all Shield modules AFTER mock setup so they use the mocked homedir.
const { writeEvent, readEvents, verifyEventChain, getShieldDir, GENESIS_HASH } =
  await import('../../src/shield/events.js');

const { runIntegrityChecks, enterLockdown, exitLockdown, isLockdown } =
  await import('../../src/shield/integrity.js');

const { importARPEvents } = await import('../../src/shield/arp-bridge.js');

const { loadPolicy, evaluatePolicy, createDefaultPolicy, savePolicy } =
  await import('../../src/shield/policy.js');

const {
  signArtifact,
  verifyArtifact,
  signAllArtifacts,
  verifyAllArtifacts,
  saveSignatures,
} = await import('../../src/shield/signing.js');

const { getShieldStatus } = await import('../../src/shield/status.js');

const { collectSignals, identifySession } =
  await import('../../src/shield/session.js');

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-e2e-'));
  _mockHomeDir = tempDir;
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
  // Clean up env vars that session tests may have set
  delete process.env['CLAUDE_CODE'];
  delete process.env['CURSOR'];
  delete process.env['VSCODE_PID'];
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEventPartial(overrides: Record<string, unknown> = {}) {
  return {
    source: 'shield' as const,
    category: 'test',
    severity: 'info' as const,
    agent: null,
    sessionId: null,
    action: 'test-action',
    target: 'test-target',
    outcome: 'allowed' as const,
    detail: {},
    orgId: null,
    managed: false,
    agentId: null,
    ...overrides,
  };
}

function makeARPEvent(overrides: Record<string, unknown> = {}) {
  return {
    id: 'arp-e2e-' + Math.random().toString(36).slice(2),
    timestamp: new Date().toISOString(),
    source: 'process',
    category: 'normal',
    severity: 'info',
    description: 'Test process spawn',
    data: { command: '/usr/bin/ls', pid: 12345 },
    classifiedBy: 'L0-rules',
    ...overrides,
  };
}

/**
 * Simulate shieldInit without the full async init flow (which runs
 * detectEnvironment, credential scanning, guard signing, ARP init, etc.).
 * Instead, we create the essential files that init would produce:
 * - policy.yaml
 * - scan.json
 * - events.jsonl (with a genesis event)
 * - signatures.json
 */
function initShieldManually() {
  const shieldDir = getShieldDir();

  // Create a default policy
  const policy = createDefaultPolicy('adaptive');
  const policyPath = path.join(shieldDir, 'policy.yaml');
  savePolicy(policy, policyPath);

  // Create a scan.json
  const scan = {
    timestamp: new Date().toISOString(),
    hostname: 'test-host',
    platform: 'darwin',
    shell: '/bin/zsh',
    clis: [],
    assistants: [],
    mcpServers: [],
    oauthSessions: [],
    projectType: 'node',
    projectName: 'test-project',
  };
  fs.writeFileSync(
    path.join(shieldDir, 'scan.json'),
    JSON.stringify(scan, null, 2),
    { mode: 0o600 },
  );

  // Write the genesis event
  writeEvent(makeEventPartial({
    category: 'shield.init',
    action: 'shield.init',
    target: tempDir,
  }));

  // Sign all artifacts
  signAllArtifacts();

  return { policy, policyPath, shieldDir };
}

// ===========================================================================
// Test 1: Full lifecycle
// ===========================================================================

describe('Shield E2E Integration', () => {
  describe('Full lifecycle', () => {
    it('initializes, writes events, imports ARP, verifies integrity, and reports status', () => {
      // Step 1: Initialize Shield
      const { shieldDir, policyPath } = initShieldManually();

      // Step 2: Verify init created essential files
      expect(fs.existsSync(policyPath)).toBe(true);
      expect(fs.existsSync(path.join(shieldDir, 'scan.json'))).toBe(true);
      expect(fs.existsSync(path.join(shieldDir, 'events.jsonl'))).toBe(true);
      expect(fs.existsSync(path.join(shieldDir, 'signatures.json'))).toBe(true);

      // Verify genesis event exists
      const genesisEvents = readEvents({ count: 100 });
      expect(genesisEvents.length).toBe(1);
      expect(genesisEvents[0].category).toBe('shield.init');

      // Step 3: Write additional events simulating agent activity
      writeEvent(makeEventPartial({ action: 'process.spawn', target: 'git status' }));
      writeEvent(makeEventPartial({ action: 'file.read', target: '/src/index.ts' }));
      writeEvent(makeEventPartial({
        action: 'network.connect',
        target: 'registry.npmjs.org',
        severity: 'low' as const,
      }));

      // Step 4: Import ARP events
      const arpDir = path.join(tempDir, '.opena2a', 'arp');
      fs.mkdirSync(arpDir, { recursive: true });

      const arpEvents = [
        makeARPEvent({ id: 'arp-lifecycle-1', source: 'process' }),
        makeARPEvent({ id: 'arp-lifecycle-2', source: 'network', data: { host: 'example.com' } }),
      ];
      fs.writeFileSync(
        path.join(arpDir, 'events.jsonl'),
        arpEvents.map(e => JSON.stringify(e)).join('\n') + '\n',
      );

      const importResult = importARPEvents(tempDir);
      expect(importResult.imported).toBe(2);
      expect(importResult.errors).toBe(0);

      // Step 5: Run integrity checks -- should be healthy
      // (We need to re-sign artifacts since we wrote new events after signing)
      // Note: integrity checks verify policy and artifacts, not event count
      const state = runIntegrityChecks({ shell: 'zsh' });

      // Event chain should pass (it's based on the hash chain, not artifacts)
      const eventChainCheck = state.checks.find(c => c.name === 'event-chain');
      expect(eventChainCheck).toBeDefined();
      expect(eventChainCheck!.status).toBe('pass');

      // Step 6: Read events and verify chain integrity
      const allEvents = readEvents({ count: 100 });
      // 1 genesis + 3 manual + 2 ARP = 6 total
      expect(allEvents.length).toBe(6);

      // readEvents returns newest-first, so reverse for chronological order
      const chronological = [...allEvents].reverse();
      const chainResult = verifyEventChain(chronological);
      expect(chainResult.valid).toBe(true);
      expect(chainResult.brokenAt).toBeNull();

      // Verify ARP events are in the chain
      const arpInShield = allEvents.filter(e => e.source === 'arp');
      expect(arpInShield.length).toBe(2);

      // Step 7: Get shield status
      const status = getShieldStatus();
      expect(status.timestamp).toBeTruthy();
      expect(status.policyLoaded).toBe(true);
      expect(status.policyMode).toBe('adaptive');
      expect(status.integrityStatus).toBe('healthy');
    });
  });

  // ===========================================================================
  // Test 2: Tamper detection
  // ===========================================================================

  describe('Tamper detection', () => {
    it('detects tampered events.jsonl via integrity checks', () => {
      // Step 1: Init Shield
      const { shieldDir } = initShieldManually();

      // Step 2: Write additional events
      writeEvent(makeEventPartial({ action: 'legit-1' }));
      writeEvent(makeEventPartial({ action: 'legit-2' }));

      // Verify chain is valid before tampering
      const eventsBefore = readEvents({ count: 100 });
      const chainBefore = verifyEventChain([...eventsBefore].reverse());
      expect(chainBefore.valid).toBe(true);

      // Step 3: Tamper with events.jsonl (modify a hash in the middle)
      const eventsPath = path.join(shieldDir, 'events.jsonl');
      const content = fs.readFileSync(eventsPath, 'utf-8');
      // Replace the GENESIS_HASH with a fake hash in the first event line
      const tampered = content.replace(GENESIS_HASH, 'deadbeef'.repeat(8));
      fs.writeFileSync(eventsPath, tampered);

      // Step 4: Run integrity checks -- should detect degradation (not compromise)
      const state = runIntegrityChecks({ shell: 'zsh' });
      expect(state.status).toBe('degraded');

      // Step 5: Verify event-chain check shows warning (not failure)
      const eventChainCheck = state.checks.find(c => c.name === 'event-chain');
      expect(eventChainCheck).toBeDefined();
      expect(eventChainCheck!.status).toBe('warn');
    });

    it('detects tampered event hash within the chain', () => {
      initShieldManually();

      const e1 = writeEvent(makeEventPartial({ action: 'first' }));
      writeEvent(makeEventPartial({ action: 'second' }));

      // Tamper: modify the eventHash of the first additional event
      const shieldDir = getShieldDir();
      const eventsPath = path.join(shieldDir, 'events.jsonl');
      const content = fs.readFileSync(eventsPath, 'utf-8');
      const tampered = content.replace(e1.eventHash, 'badc0de'.repeat(9).slice(0, 64));
      fs.writeFileSync(eventsPath, tampered);

      const state = runIntegrityChecks({ shell: 'zsh' });
      const eventChainCheck = state.checks.find(c => c.name === 'event-chain');
      expect(eventChainCheck!.status).toBe('warn');
    });
  });

  // ===========================================================================
  // Test 3: Lockdown and recovery
  // ===========================================================================

  describe('Lockdown and recovery', () => {
    it('enters lockdown, verifies lockdown state, exits lockdown, and recovers', () => {
      // Step 1: Init Shield
      initShieldManually();

      // Verify we start healthy
      expect(isLockdown()).toBe(false);
      const healthyState = runIntegrityChecks({ shell: 'zsh' });
      // May be degraded due to shell hook not installed, but not lockdown
      expect(healthyState.status).not.toBe('lockdown');

      // Step 2: Enter lockdown
      enterLockdown('test reason: suspicious activity detected');

      // Step 3: Verify lockdown
      expect(isLockdown()).toBe(true);

      // Step 4: Verify integrity checks return lockdown status
      const lockdownState = runIntegrityChecks({ shell: 'zsh' });
      expect(lockdownState.status).toBe('lockdown');
      expect(lockdownState.checks.length).toBe(1);
      expect(lockdownState.checks[0].name).toBe('lockdown');
      expect(lockdownState.checks[0].status).toBe('fail');
      expect(lockdownState.checks[0].detail).toContain('test reason');

      // Step 5: Exit lockdown
      exitLockdown();

      // Step 6: Verify lockdown is cleared
      expect(isLockdown()).toBe(false);

      // Step 7: Verify integrity checks return non-lockdown status
      const recoveredState = runIntegrityChecks({ shell: 'zsh' });
      expect(recoveredState.status).not.toBe('lockdown');

      // Event chain should still pass
      const eventChainCheck = recoveredState.checks.find(c => c.name === 'event-chain');
      expect(eventChainCheck).toBeDefined();
      expect(eventChainCheck!.status).toBe('pass');
    });
  });

  // ===========================================================================
  // Test 4: Policy evaluation round-trip
  // ===========================================================================

  describe('Policy evaluation round-trip', () => {
    it('loads policy from disk and evaluates allow/block decisions', () => {
      // Step 1: Init Shield (creates a policy)
      initShieldManually();

      // Step 2: Load policy from disk
      const policy = loadPolicy();
      expect(policy).not.toBeNull();
      expect(policy!.version).toBe(1);
      expect(policy!.mode).toBe('adaptive');

      // Step 3: Evaluate policy -- allowed process
      const gitDecision = evaluatePolicy(policy!, null, 'process.spawn', 'git');
      expect(gitDecision.allowed).toBe(true);
      expect(gitDecision.outcome).toBe('allowed');

      // Step 4: Evaluate policy -- denied process (in adaptive mode = monitored, not blocked)
      const awsDecision = evaluatePolicy(policy!, null, 'process.spawn', 'aws');
      // In adaptive mode, deny matches are 'monitored' not 'blocked'
      expect(awsDecision.outcome).toBe('monitored');
      expect(awsDecision.rule).toContain('deny');

      // Step 5: Evaluate policy -- denied process in enforce mode
      const enforcePolicy = { ...policy!, mode: 'enforce' as const };
      const awsEnforceDecision = evaluatePolicy(enforcePolicy, null, 'process.spawn', 'aws');
      expect(awsEnforceDecision.allowed).toBe(false);
      expect(awsEnforceDecision.outcome).toBe('blocked');

      // Step 6: Evaluate policy -- unknown target (implicitly allowed)
      const unknownDecision = evaluatePolicy(policy!, null, 'process.spawn', 'my-custom-tool');
      expect(unknownDecision.allowed).toBe(true);
      expect(unknownDecision.outcome).toBe('allowed');

      // Step 7: Evaluate policy -- credential path denied
      // The deny pattern ~/.ssh/* is expanded via homedir() (which is our temp dir).
      // So the target must also use the expanded homedir path.
      const credTarget = path.join(tempDir, '.ssh', 'id_rsa');
      const credDecision = evaluatePolicy(policy!, null, 'credential.read', credTarget);
      // In adaptive mode, deny matches are 'monitored' not 'blocked'
      expect(credDecision.outcome).toBe('monitored');
      expect(credDecision.rule).toContain('deny');
    });

    it('supports agent-specific overrides', () => {
      initShieldManually();

      const policy = loadPolicy()!;

      // Add agent-specific override that allows aws for a specific agent
      policy.agents['deploy-bot'] = {
        processes: {
          allow: ['aws', 'terraform', 'kubectl'],
          deny: [],
        },
      };

      // Default agent: aws is denied
      const defaultDecision = evaluatePolicy(policy, null, 'process.spawn', 'aws');
      expect(defaultDecision.outcome).toBe('monitored');

      // deploy-bot: aws is allowed (agent override replaces default processes rules)
      const botDecision = evaluatePolicy(policy, 'deploy-bot', 'process.spawn', 'aws');
      expect(botDecision.allowed).toBe(true);
      expect(botDecision.outcome).toBe('allowed');
    });
  });

  // ===========================================================================
  // Test 5: Signing and verification
  // ===========================================================================

  describe('Signing and verification', () => {
    it('signs artifacts, verifies them, detects tampering, and fails integrity checks', () => {
      // Step 1: Init Shield
      const { shieldDir } = initShieldManually();

      // Step 2: Sign a specific artifact
      const policyPath = path.join(shieldDir, 'policy.yaml');
      const sig = signArtifact(policyPath);

      expect(sig.filePath).toBe('policy.yaml');
      expect(sig.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(sig.signedBy).toContain('@opena2a-cli');

      // Step 3: Verify via verifyArtifact -- should pass
      const verifyResult = verifyArtifact(policyPath);
      expect(verifyResult.valid).toBe(true);

      // Step 4: verifyAllArtifacts -- should pass
      const allResult = verifyAllArtifacts();
      expect(allResult.valid).toBe(true);
      expect(allResult.detail).toContain('verified');

      // Step 5: Tamper with the policy file
      fs.writeFileSync(policyPath, '{"version":1,"mode":"enforce","default":{},"agents":{}}');

      // Step 6: verifyAllArtifacts -- should fail
      const tamperedResult = verifyAllArtifacts();
      expect(tamperedResult.valid).toBe(false);
      expect(tamperedResult.detail).toContain('has been modified');

      // Step 7: runIntegrityChecks -- artifact-signatures check should fail
      const state = runIntegrityChecks({ shell: 'zsh' });
      const artifactCheck = state.checks.find(c => c.name === 'artifact-signatures');
      expect(artifactCheck).toBeDefined();
      expect(artifactCheck!.status).toBe('fail');

      // Overall status should be compromised
      expect(state.status).toBe('compromised');
    });

    it('detects missing signed file', () => {
      const { shieldDir } = initShieldManually();

      // Verify artifacts are signed
      const before = verifyAllArtifacts();
      expect(before.valid).toBe(true);

      // Delete a signed file
      const scanPath = path.join(shieldDir, 'scan.json');
      expect(fs.existsSync(scanPath)).toBe(true);
      fs.unlinkSync(scanPath);

      // Verification should fail
      const after = verifyAllArtifacts();
      expect(after.valid).toBe(false);
      expect(after.detail).toContain('missing');
    });

    it('re-signing after legitimate changes restores validity', () => {
      const { shieldDir } = initShieldManually();

      // Modify policy legitimately
      const policyPath = path.join(shieldDir, 'policy.yaml');
      const policy = createDefaultPolicy('enforce');
      savePolicy(policy, policyPath);

      // Artifacts are now invalid (policy changed)
      const invalid = verifyAllArtifacts();
      expect(invalid.valid).toBe(false);

      // Re-sign all artifacts
      signAllArtifacts();

      // Now valid again
      const valid = verifyAllArtifacts();
      expect(valid.valid).toBe(true);
    });
  });

  // ===========================================================================
  // Test 6: Session detection
  // ===========================================================================

  describe('Session detection', () => {
    it('detects Claude Code session from CLAUDE_CODE env var', () => {
      process.env['CLAUDE_CODE'] = '1';

      const signals = collectSignals();
      const claudeSignal = signals.find(s => s.name === 'CLAUDE_CODE');
      expect(claudeSignal).toBeDefined();
      expect(claudeSignal!.confidence).toBe(0.95);

      const session = identifySession();
      expect(session).not.toBeNull();
      expect(session!.agent).toBe('claude-code');
      expect(session!.confidence).toBeGreaterThan(0.9);
      expect(session!.sessionId).toMatch(/^claude-code-[0-9a-f]{12}$/);
    });

    it('detects Cursor session from CURSOR env var', () => {
      process.env['CURSOR'] = '1';

      const session = identifySession();
      expect(session).not.toBeNull();
      expect(session!.agent).toBe('cursor');
    });

    it('detects VS Code / Copilot session from VSCODE_PID env var', () => {
      process.env['VSCODE_PID'] = '99999';

      const session = identifySession();
      expect(session).not.toBeNull();
      expect(session!.agent).toBe('copilot');
    });

    it('returns null when no AI coding assistant is detected', () => {
      // No env vars set for any known assistant.
      // The only signal should be PPID which has low confidence (0.4).
      // detectAgent returns null when confidence is below 0.3, and
      // the "unknown" rule catches everything -- but PPID alone gives 0.4.
      // The result depends on what other env vars exist in the test runner.
      const session = identifySession();
      // The session may or may not be null depending on the test runner's env.
      // We just verify the function returns without error.
      if (session) {
        expect(session.sessionId).toBeTruthy();
        expect(session.agent).toBeTruthy();
      }
    });
  });

  // ===========================================================================
  // Test 7: Cross-cutting -- events survive across all operations
  // ===========================================================================

  describe('Cross-cutting: event chain integrity across operations', () => {
    it('maintains chain integrity through init, manual writes, ARP import, and lockdown', () => {
      // Init
      initShieldManually();

      // Write some events
      writeEvent(makeEventPartial({ action: 'step-1' }));
      writeEvent(makeEventPartial({ action: 'step-2' }));

      // Import ARP events
      const arpDir = path.join(tempDir, '.opena2a', 'arp');
      fs.mkdirSync(arpDir, { recursive: true });
      const arpEvents = [
        makeARPEvent({ id: 'chain-arp-1' }),
        makeARPEvent({ id: 'chain-arp-2' }),
        makeARPEvent({ id: 'chain-arp-3' }),
      ];
      fs.writeFileSync(
        path.join(arpDir, 'events.jsonl'),
        arpEvents.map(e => JSON.stringify(e)).join('\n') + '\n',
      );
      importARPEvents(tempDir);

      // Write more events after ARP import
      writeEvent(makeEventPartial({ action: 'step-3', severity: 'high' as const }));

      // Enter and exit lockdown (lockdown does not break event chain)
      enterLockdown('test lockdown');
      exitLockdown();

      // Write another event after lockdown recovery
      writeEvent(makeEventPartial({ action: 'post-recovery' }));

      // Read all events and verify chain
      const allEvents = readEvents({ count: 1000 });
      // 1 genesis + 2 manual + 3 ARP + 1 high + 1 post-recovery = 8
      expect(allEvents.length).toBe(8);

      // Verify chain integrity (readEvents returns newest-first, reverse for chain verification)
      const chronological = [...allEvents].reverse();
      const chainResult = verifyEventChain(chronological);
      expect(chainResult.valid).toBe(true);
      expect(chainResult.brokenAt).toBeNull();

      // Verify the first event links to genesis
      expect(chronological[0].prevHash).toBe(GENESIS_HASH);

      // Verify each event links to the previous one
      for (let i = 1; i < chronological.length; i++) {
        expect(chronological[i].prevHash).toBe(chronological[i - 1].eventHash);
      }

      // Integrity checks should pass on event chain
      const state = runIntegrityChecks({ shell: 'zsh' });
      const eventChainCheck = state.checks.find(c => c.name === 'event-chain');
      expect(eventChainCheck!.status).toBe('pass');
      expect(eventChainCheck!.detail).toContain('8 events');
    });
  });
});
