// Inventory, Optional hardening and Scan details replace the Shadow AI and
// Hygiene tabs, which showed a project with no findings FAIL marks and "2 AI
// agents running without governance" for OpenA2A tools that were not set up and
// tools running on the reviewer's machine. The client script runs here against
// a stub document.

import { describe, it, expect } from 'vitest';
import { runInNewContext } from 'node:vm';
import { assembleReviewClientScript } from '../../src/report/review-assets.js';
import { COMPOSITE_WEIGHTS } from '../../src/commands/review.js';

/** One tab as the report's client script renders it: its markup and its visible text. */
function open(report: object, tab: string): { html: string; text: string } {
  const pages: Record<string, { innerHTML: string; querySelectorAll: () => never[] }> = {};
  let onNav = (_: unknown): void => {};
  const document = {
    getElementById(id: string) {
      if (id === 'report-data') return { textContent: JSON.stringify(report) };
      if (id === 'main-nav') return { addEventListener: (_: string, fn: typeof onNav) => { onNav = fn; } };
      return (pages[id] ??= { innerHTML: '', querySelectorAll: () => [] });
    },
    querySelectorAll: () => [],
  };
  runInNewContext(assembleReviewClientScript(), { document, window: { addEventListener() {} } });
  onNav({ target: { closest: () => ({ getAttribute: () => tab }) } });
  const html = pages['page-' + tab].innerHTML;
  return { html, text: html.replace(/<[^>]+>/g, ' ').replace(/&gt;/g, '>').replace(/\s+/g, ' ').trim() };
}

const scoreModel = (weightSet: keyof typeof COMPOSITE_WEIGHTS, o: object = {}) => ({
  weightSet, weightedScore: 94, floorBand: 30, floorHeldBy: [],
  weights: Object.entries(COMPOSITE_WEIGHTS[weightSet]).map(([dimension, weight]) => ({ dimension, weight, score: weight === 0 ? null : 90 })),
  ...o,
});
const phase = (name: string, status: string, durationMs: number, detail = '') => ({ name, status, durationMs, detail });
const opena2a = (command: string, changes: string | null) => ({ command, tool: 'opena2a', changes });

// A project with no findings, reviewed on a machine where two AI tools run.
const CLEAN = {
  directory: '/work/tiny-clean-repo', projectName: 'tiny-clean-repo', compositeScore: 94,
  phases: [
    phase('Project Scan', 'pass', 310), phase('Credentials', 'pass', 40), phase('Config Integrity', 'warn', 20),
    phase('Shield Analysis', 'fail', 150, 'Posture 35/100'), phase('HMA Scan', 'pass', 4200), phase('Shadow AI', 'fail', 60, 'Governance 20/100'),
  ],
  scoreModel: scoreModel('withHma'),
  optionalHardening: [
    { title: 'Sign the 1 config file', reason: 'package.json is not signed.', fix: opena2a('opena2a guard sign', 'Writes signatures.json.'), recovery: { kind: 'computed', points: 3, from: 94, to: 97 } },
    { title: 'Load a Shield policy', reason: 'No Shield policy is loaded.', fix: opena2a('opena2a shield init', null), recovery: { kind: 'none', points: 0, from: 94, to: 94 } },
  ],
  initData: { envFiles: [], hygieneChecks: [{ label: 'Lock file', detail: 'package-lock.json' }, { label: 'Security config', detail: 'none' }] },
  credentialData: { filesScanned: 5, totalFindings: 0, coverage: { placeholdersSkipped: 0, skippedDirs: ['node_modules', 'dist'] } },
  guardData: { signatureStatus: 'unsigned', candidates: ['package.json'] },
  shieldData: { eventCount: 0, policyLoaded: false },
  hmaData: { available: true, score: 98, maxScore: 100, totalChecks: 47, passed: 46, failed: 1, run: { version: 'hackmyagent 0.30.0' } },
  detectData: {
    governanceScore: 20,
    agents: ['Claude Code', 'GitHub Copilot'].map(name => ({ name, category: 'ai-assistant', governanceStatus: 'no governance' })),
    mcpServers: [{ name: 'files', transport: 'stdio', source: '~/.claude.json', capabilities: ['filesystem'], risk: 'critical' }],
    aiConfigs: [], identity: { aimIdentities: 0, mcpIdentities: 0, soulFiles: 0, capabilityPolicies: 0 },
    findings: [{ severity: 'high', title: '2 AI agents running without governance' }],
  },
};

describe('review report: Inventory, Optional hardening and Scan details', () => {
  const [inventory, hardening, details] = ['inventory', 'hardening', 'details'].map(tab => open(CLEAN, tab));

  it('on a project with no findings, nothing about tool adoption or the machine is marked as a failure', () => {
    expect(details.text).toContain('Shadow AI ran in 0.1 s'); // non-vacuity: an analyzer whose status is "fail" is on the page
    for (const page of [inventory, hardening, details]) {
      expect(page.html).not.toMatch(/sev-badge|status-|var\(--(red|critical|high|amber)\)/);
      expect(page.text).not.toMatch(/\b(fail|warn|risk|governance \d+|posture)\b|without governance/i);
    }
  });

  it('lists the AI tools found on the machine apart from the project, and says they are not scored', () => {
    const [project, machine] = inventory.text.split('On this machine, not part of this project');
    expect(project).toContain('In this project MCP servers (0) No MCP servers are declared in /work/tiny-clean-repo.');
    expect(project).not.toMatch(/Claude Code|GitHub Copilot|claude\.json/);
    expect(machine).toContain('They are not part of tiny-clean-repo and count toward neither its findings nor its score.');
    expect(machine).toContain('Running AI tools (2) Name Kind Claude Code ai-assistant GitHub Copilot ai-assistant');
    expect(machine).toContain('files (stdio) ~/.claude.json reads and writes files');
    expect(inventory.html).toContain('<td class="path">~/.claude.json</td>'); // a long path wraps; names stay whole
  });

  it('`opena2a shield init` is optional and shows "no score change"', () => {
    expect(hardening.text).toContain('optional no score change Load a Shield policy Why No Shield policy is loaded. Run opena2a shield init opena2a Copy');
    expect(hardening.text).toContain('optional +3 Sign the 1 config file');
    expect(hardening.text).toContain('Recovery +3 (94 -> 97, re-scored)');
  });

  it('Scan details shows the numbers the JSON carries and where the Shield runtime view is', () => {
    for (const p of CLEAN.phases) expect(details.text).toContain(`${p.name} ran in ${(p.durationMs / 1000).toFixed(1)} s`);
    expect(details.text).toContain('HMA 0.30.0 ran 47 checks; 1 failed (see Findings). HMA score 98 of 100.');
    expect(details.text).toContain('Credential patterns: 5 files read, 0 provider-format keys. 0 values skipped as placeholders or examples. Folders not entered: node_modules, dist.');
    expect(details.text).toContain('0 Shield events read. The runtime view (events, monitoring, policy state) is not part of this review: opena2a shield report shows it.');
    expect(details.text).toContain('On this machine, not scored: 2 running AI tools, 1 MCP server (see Inventory).');
  });

  it('names why HMA did not run, and which analyzer holds the score', () => {
    const { text } = open({
      ...CLEAN, compositeScore: 0, phases: [phase('HMA Scan', 'skip', 0)], hmaData: { available: false, run: { reason: 'skipped by --skip-hma' } },
      scoreModel: scoreModel('withoutHma', { weightedScore: 62, floorHeldBy: ['Credentials'] }),
    }, 'details');
    expect(text).toContain('HMA Scan skipped Did not run (skipped by --skip-hma).');
    expect(text).toContain('HMA scan 0% did not run');
    expect(text).toContain('with the weights for a run without HMA: 62 of 100. An analyzer that judges the project itself and scores below 30 holds the score at its own. Here Credentials holds it at 0.');
  });

  it.each(['withHma', 'withoutHma'] as const)('the score table shows the weights the score is computed with (%s)', set => {
    const shown = [...open({ ...CLEAN, scoreModel: scoreModel(set) }, 'details').text.matchAll(/ (\d+)% /g)].map(m => Number(m[1]));
    expect(shown).toEqual(Object.values(COMPOSITE_WEIGHTS[set]).map(w => Math.round(w * 100)));
    expect(shown.reduce((a, b) => a + b, 0)).toBe(100);
  });
});
