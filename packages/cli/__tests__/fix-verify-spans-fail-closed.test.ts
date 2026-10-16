/**
 * A Fix, Verify or next-step command the CLI prints for the reader to paste
 * leaves each operand the reader supplies as a shell parameter that refuses
 * when unset, "${NAME:?set NAME to ...}", never as a `<name>` placeholder.
 *
 * Pasted as printed, `<binary>` is a shell redirection, not an operand: the
 * line stops with a syntax error or with "No such file or directory", and
 * where a file of that name exists the command runs reading it. The
 * parameter form stops before anything runs and says what to set. The spans are read the way the reader meets them: a command's
 * own output where it runs offline in a temp dir, a rendered report page, or
 * else the exported string. Each one is then pasted into bash, zsh and dash
 * with its parameters unset.
 *
 * Usage syntax, the expected output of a Verify step, the `shield init` Fix
 * lines and the `export VAULT_TOKEN=` lines keep their angle brackets: they
 * are not operands of a pasted command, or their form is decided separately.
 */
import { describe, it, expect, vi, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { runInNewContext } from 'node:vm';

const SRC = path.join(__dirname, '..', 'src');
const PLACEHOLDER = /<[A-Za-z][^<>\s]*>/;
const PLACEHOLDERS = /<[A-Za-z][^<>\s]*>/g;
/** One operand in the refusing form; group 1 is the name, group 2 the message. */
const PARAMETER = /"\$\{([A-Za-z_][A-Za-z0-9_]*):\?([^"}]*)\}"/g;
const ANSI = /\x1b\[[0-9;]*m/g;
/**
 * `<...>` tokens in the subcommand help's usage, flag and example strings,
 * counted on the tree this conversion started from. Usage syntax keeps its
 * angle brackets, so the count does not move with it.
 */
const USAGE_PLACEHOLDER_TOKENS = 63;

// Every command below runs in-process. HOME is an empty directory so none of
// them reads or writes the real one, auth stays in a file there, and the
// registry URL is a closed local port so nothing leaves the machine.
const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), 'oa2a-fail-closed-'));
const SAVED_ENV = {
  HOME: process.env.HOME,
  OPENA2A_AUTH_FORCE_FILE: process.env.OPENA2A_AUTH_FORCE_FILE,
  OPENA2A_REGISTRY_URL: process.env.OPENA2A_REGISTRY_URL,
};
const SANDBOX_HOME = path.join(SANDBOX, 'home');
fs.mkdirSync(SANDBOX_HOME);
process.env.HOME = SANDBOX_HOME;
process.env.OPENA2A_AUTH_FORCE_FILE = '1';
process.env.OPENA2A_REGISTRY_URL = 'http://127.0.0.1:9';
vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('offline: this test makes no network request'); }));

const { FINDING_CATALOG } = await import('../src/shield/findings.js');
const { SECRET_ROTATION_TABLE } = await import('../../check-core/src/secret-rotation.js');
const { generateShieldHtmlReport } = await import('../src/shield/report-html.js');
const shieldInitModule = await import('../src/shield/init.js');
const { init } = await import('../src/commands/init.js');
const { _protectInternals } = await import('../src/commands/protect.js');
const { mcpCommand } = await import('../src/commands/mcp-audit.js');
const identityModule = await import('../src/commands/identity.js');
const { hardenSkill } = await import('../src/commands/harden-skill.js');
const { login } = await import('../src/commands/login.js');
const setupModule = await import('../src/commands/setup.js');
const { trust, _internals: trustInternals } = await import('../src/commands/trust.js');
const { printAdvisoryWarnings } = await import('../src/util/advisories.js');
const { HELP_CONTRACTS } = await import('../src/util/help-contract.js');
const subcommandHelp = await import('../src/util/subcommand-help.js');

afterAll(() => {
  vi.unstubAllGlobals();
  for (const [k, v] of Object.entries(SAVED_ENV)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  fs.rmSync(SANDBOX, { recursive: true, force: true });
});

/** The spans as the CLI prints them after the conversion. */
const SPANS = {
  initProjectDir: 'opena2a init "${PROJECT_DIR:?set PROJECT_DIR to the folder that holds your code}"',
  shieldInitProjectDir:
    'opena2a shield init --dir "${PROJECT_DIR:?set PROJECT_DIR to the folder that holds your code}"',
  restoreFiles:
    'git checkout -- "${FILES:?set FILES to a file protect changed, and run the line once per file}"',
  vaultGet: 'npx secretless-ai secret get "${SECRET_NAME:?set SECRET_NAME to a name that secret list printed}"',
  mcpSign: 'opena2a mcp sign "${MCP_SERVER:?set MCP_SERVER to a server name listed above}"',
  mcpVerify: 'opena2a mcp verify "${MCP_SERVER:?set MCP_SERVER to a server name listed above}"',
  identityConnect:
    'opena2a identity connect "${AIM_SERVER_URL:?set AIM_SERVER_URL to the URL of your AIM server}"'
    + ' --api-key "${AIM_API_KEY:?set AIM_API_KEY to your API key for that AIM server}"',
  identityConnectLocal:
    'opena2a identity connect localhost:8080 --api-key "${AIM_API_KEY:?set AIM_API_KEY to your API key for that AIM server}"',
  identityServerFlag: '--server "${AIM_SERVER_URL:?set AIM_SERVER_URL to the URL of your AIM server}"',
  identityApiKeyFlag: '--api-key "${AIM_API_KEY:?set AIM_API_KEY to your API key for that AIM server}"',
  identityLogEvent:
    'opena2a identity log'
    + ' --action "${AUDIT_ACTION:?set AUDIT_ACTION to the action to record, for example db:read}"'
    + ' --target "${AUDIT_TARGET:?set AUDIT_TARGET to what it acted on, for example customers}"',
  identityCreateAgent:
    'opena2a identity create --name "${AGENT_NAME:?set AGENT_NAME to a name for the new agent}" --server cloud',
  hardenSkill: 'opena2a harden-skill "${SKILL_FILE:?set SKILL_FILE to the path of the skill file to harden}"',
  loginApiKey: 'opena2a identity list --server cloud --api-key "${AIM_API_KEY:?set AIM_API_KEY to your AIM Cloud API key}"',
  setupTrust: 'opena2a trust "${PACKAGE:?set PACKAGE to an npm package or MCP server name}"',
  trustRegistryUrl: '--registry-url "${REGISTRY_URL:?set REGISTRY_URL to the base URL of the registry to query}"',
  advisoryVerify: 'opena2a verify --package "${PACKAGE:?set PACKAGE to a package named above}"',
  hmaSkillCheck: 'hackmyagent check "${SKILL_PATH:?set SKILL_PATH to the skill file to inspect}"',
} as const;

function parameters(span: string): { name: string; message: string }[] {
  return [...span.matchAll(PARAMETER)].map(m => ({ name: m[1], message: m[2] }));
}

/**
 * Why `span` is not in the fail-closed form, or null when it is. Every `${`
 * opens a refusing parameter whose message says what to set, in characters
 * that stay literal inside double quotes in bash, zsh and dash; a plain
 * `$NAME` refers only to a parameter already checked to its left.
 */
function notFailClosed(span: string): string | null {
  const params = parameters(span);
  if (params.length === 0) return 'no refusing parameter';
  if ((span.match(/\$\{/g) ?? []).length !== params.length) return 'a ${...} that is not "${NAME:?message}"';
  for (const p of params) {
    if (!p.message.startsWith(`set ${p.name} to `)) return `${p.name}: the message does not say what to set`;
    if (!/^[A-Za-z0-9_ ,.:/-]+$/.test(p.message)) return `${p.name}: the message holds a shell-special character`;
  }
  for (const m of span.matchAll(/\$([A-Za-z_][A-Za-z0-9_]*)/g)) {
    const checked = params.some(p => span.indexOf(`\${${p.name}:?`) < (m.index ?? 0) && p.name === m[1]);
    if (!checked) return `$${m[1]} is used before it is checked`;
  }
  return null;
}

function hasParameter(s: string | undefined): s is string {
  return typeof s === 'string' && s.includes('${');
}

async function capture(fn: () => Promise<number> | number): Promise<{ code: number; stdout: string; stderr: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const spies = [
    vi.spyOn(process.stdout, 'write').mockImplementation(((c: unknown) => { out.push(String(c)); return true; }) as never),
    vi.spyOn(process.stderr, 'write').mockImplementation(((c: unknown) => { err.push(String(c)); return true; }) as never),
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ') + '\n'); }),
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ') + '\n'); }),
  ];
  try {
    const code = await fn();
    return { code, stdout: out.join('').replace(ANSI, ''), stderr: err.join('').replace(ANSI, '') };
  } finally {
    for (const s of spies) s.mockRestore();
  }
}

function tempDir(name: string): string {
  const dir = path.join(SANDBOX, name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function decode(s: string): string {
  return s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

/** What a browser's innerHTML gives for a text node: &, <, > and no-break space escaped, quotes kept. */
function serializeText(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/ /g, '&nbsp;');
}

/** Run the Shield report's own script against a stub DOM; return the findings and violations pages. */
function renderShieldPages(): { findings: string; violations: string } {
  const catalog = Object.values(FINDING_CATALOG);
  const report = {
    version: 1,
    generatedAt: '2026-10-16T00:00:00.000Z',
    periodStart: '2026-10-09T00:00:00.000Z',
    periodEnd: '2026-10-16T00:00:00.000Z',
    hostname: 'dev-workstation',
    agentActivity: { totalSessions: 0, totalActions: 0, byAgent: {} },
    policyEvaluation: {
      monitored: catalog.length, wouldBlock: 0, blocked: 0,
      topViolations: catalog.map(f => ({
        action: 'process.spawn', target: 't', agent: 'a', count: 1, severity: f.severity,
        recommendation: 'r', findingId: f.id, remediationCommand: f.remediation, compliance: [],
      })),
    },
    credentialExposure: { accessAttempts: 0, uniqueCredentials: 0, byProvider: {}, recommendations: [] },
    supplyChain: { packagesInstalled: 0, advisoriesFound: 0, blockedInstalls: 0, lowTrustPackages: [] },
    configIntegrity: { filesMonitored: 0, tamperedFiles: [], signatureStatus: 'valid' },
    runtimeProtection: { arpActive: false, processesSpawned: 0, networkConnections: 0, anomalies: 0 },
    posture: { score: 90, grade: 'strong', factors: [], trend: null, comparative: null },
  };
  const findings = catalog.map(finding => ({
    finding, count: 1, firstSeen: '2026-10-10T00:00:00.000Z', lastSeen: '2026-10-11T00:00:00.000Z', examples: [],
  }));
  const html = generateShieldHtmlReport(report as never, null, findings as never);
  const script = html.slice(html.lastIndexOf('<script>') + '<script>'.length, html.lastIndexOf('</script>'));
  const payload = html.slice(html.indexOf('>', html.indexOf('<script id="report-data"')) + 1, html.indexOf('</script>'));
  const nodes = new Map<string, { innerHTML: string }>();
  const handlers = new Map<string, (e: unknown) => void>();
  const node = (id: string) => {
    if (!nodes.has(id)) {
      nodes.set(id, {
        innerHTML: '',
        classList: { toggle: () => {}, add: () => {}, remove: () => {} },
        addEventListener: (type: string, fn: (e: unknown) => void) => handlers.set(`${id}:${type}`, fn),
      } as never);
    }
    return nodes.get(id)!;
  };
  const document = {
    getElementById: (id: string) => (id === 'report-data' ? { textContent: payload } : node(id)),
    querySelectorAll: () => [],
    querySelector: () => null,
    addEventListener: () => {},
    createElement: () => {
      let text = '';
      return {
        set textContent(v: string) { text = v; },
        get innerHTML() { return serializeText(text); },
      };
    },
  };
  // The evaluated string is the report our own generator just produced.
  runInNewContext(script, { document, window: {} });
  const onNav = handlers.get('main-nav:click');
  if (!onNav) throw new Error('the Shield report script did not register its nav listener');
  for (const page of ['findings', 'violations']) {
    onNav({ target: { closest: () => ({ dataset: { page } }) } });
  }
  return { findings: node('page-findings').innerHTML, violations: node('page-violations').innerHTML };
}

/** Run the review report's renderer for the HMA page; return its HTML. */
function renderReviewHmaPage(): string {
  const client = path.join(SRC, 'report', 'review', 'assets', 'client');
  const script = ['00-core.js', '50-hma.js'].map(f => fs.readFileSync(path.join(client, f), 'utf-8')).join('\n');
  const hmaData = {
    available: true, score: 60, maxScore: 100, totalChecks: 100, passed: 96, failed: 4,
    bySeverity: { high: 4 }, byCategory: { skill: 4 }, topFindings: [], allFailedFindings: [],
  };
  const context: Record<string, unknown> = {
    document: {
      getElementById: (id: string) => (id === 'report-data'
        ? { textContent: JSON.stringify({ hmaData }) }
        : { addEventListener: () => {} }),
      querySelectorAll: () => [],
      querySelector: () => null,
    },
    window: { addEventListener: () => {} },
    navigator: {},
    setTimeout,
  };
  // The evaluated string is the report's own client script from this tree.
  runInNewContext(`${script}\n__page = renderHma();`, context);
  return String(context.__page);
}

function attributeValues(page: string, attr: string): string[] {
  return [...page.matchAll(new RegExp(`${attr}="([^"]*)"`, 'g'))].map(m => decode(m[1]));
}

// ---------------------------------------------------------------------------
// (1) Finding fields
// ---------------------------------------------------------------------------

describe('finding fields carry no <placeholder>', () => {
  it('no FINDING_CATALOG remediation holds one', () => {
    const bad = Object.values(FINDING_CATALOG)
      .filter(f => PLACEHOLDER.test(f.remediation))
      .map(f => `${f.id}: ${f.remediation}`);
    expect(bad).toEqual([]);
  });

  it('no SECRET_ROTATION_TABLE rotationCommand holds one', () => {
    const bad = Object.entries(SECRET_ROTATION_TABLE)
      .filter(([, g]) => PLACEHOLDER.test(g.rotationCommand ?? ''))
      .map(([type, g]) => `${type}: ${g.rotationCommand}`);
    expect(bad).toEqual([]);
  });

  it('each operand a finding field leaves to the reader refuses when unset and says what to set', () => {
    const fields = [
      ...Object.values(FINDING_CATALOG).map(f => [f.id, f.remediation] as const),
      ...Object.entries(SECRET_ROTATION_TABLE).map(([type, g]) => [type, g.rotationCommand] as const),
    ].filter((entry): entry is readonly [string, string] => hasParameter(entry[1]));
    expect(fields.map(([id]) => id).sort()).toEqual([
      'SHIELD-BAS-001', 'SHIELD-PROC-001', 'SHIELD-PROC-002', 'SHIELD-SUP-001', 'SHIELD-SUP-002',
      'gcp_service_account_key',
    ]);
    const bad = fields.map(([id, cmd]) => [id, notFailClosed(cmd)]).filter(([, why]) => why);
    expect(bad).toEqual([]);
  });

  it('the Shield HTML report copies and shows each such remediation whole', () => {
    // esc() fills the title and data-cmd attributes, so a quote it left
    // unescaped ended the attribute and Copy dropped the operand.
    const pages = renderShieldPages();
    const withOperand = Object.values(FINDING_CATALOG).map(f => f.remediation).filter(hasParameter);
    expect(withOperand.length).toBeGreaterThan(0);
    for (const page of [pages.findings, pages.violations]) {
      const copies = attributeValues(page, 'data-cmd');
      const titles = attributeValues(page, 'title');
      const codes = [...page.matchAll(/<code class="remediation-code"[^>]*>([^<]*)<\/code>/g)].map(m => decode(m[1]));
      for (const cmd of withOperand) {
        expect(copies, `Copy text of ${cmd}`).toContain(cmd);
        expect(titles, `title of ${cmd}`).toContain(cmd);
        expect(codes, `code element of ${cmd}`).toContain(cmd);
      }
      expect(copies.filter(c => PLACEHOLDER.test(c))).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// (2) Next-step lines, as printed
// ---------------------------------------------------------------------------

/** Lines of `out` that name `verb`; none may hold a placeholder. */
function linesNaming(out: string, verb: string): string[] {
  return out.split('\n').filter(l => l.includes(verb));
}

describe('next-step lines print each operand as a refusing parameter', () => {
  it('init on a missing directory', async () => {
    const r = await capture(() => init({ targetDir: path.join(SANDBOX, 'no-such-dir') }));
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(`Scan a specific path:        ${SPANS.initProjectDir}`);
    expect(linesNaming(r.stderr, 'opena2a init').filter(l => PLACEHOLDER.test(l))).toEqual([]);
  });

  it('init on a directory with no file the credential check reads', async () => {
    const dir = tempDir('init-skipped-only');
    fs.writeFileSync(path.join(dir, 'logo.png'), 'PNG');
    fs.writeFileSync(path.join(dir, 'guide.pdf'), '%PDF-1.4');
    fs.writeFileSync(path.join(dir, '.gitignore'), '.env\nnode_modules\n');
    const r = await capture(() => init({ targetDir: dir }));
    expect(r.stdout).toContain(`Tip: ${SPANS.initProjectDir}`);
    expect(r.stdout).toContain(`    ${SPANS.initProjectDir}\n`);
    expect(linesNaming(r.stdout, 'opena2a init').filter(l => PLACEHOLDER.test(l))).toEqual([]);
  });

  it('protect rollback, in a git tree, outside one, and where git cannot tell', () => {
    const render = (dir: string) =>
      _protectInternals.renderRollbackLines(dir, { migrated: 1 }).join('\n').replace(ANSI, '');
    const repo = tempDir('protect-git');
    execFileSync('git', ['init', '-q'], { cwd: repo, stdio: 'pipe' });
    const plain = tempDir('protect-plain');
    const unknown = path.join(SANDBOX, 'protect-missing');

    const inRepo = render(repo);
    expect(inRepo).toContain(SPANS.restoreFiles);
    expect(inRepo).toMatch(/once per file/);
    const outside = render(plain);
    expect(outside).toContain(SPANS.vaultGet);
    const either = render(unknown);
    expect(either).toContain(SPANS.restoreFiles);
    expect(either).toContain(SPANS.vaultGet);
    for (const text of [inRepo, outside, either]) expect(text).not.toMatch(PLACEHOLDER);
  });

  it('shield init, for a directory it read no file in (exported string)', () => {
    expect(shieldInitModule.SHIELD_INIT_PROJECT_DIR_COMMAND).toBe(SPANS.shieldInitProjectDir);
  });

  it('mcp audit Next Steps', async () => {
    const dir = tempDir('mcp-audit');
    fs.writeFileSync(path.join(dir, 'mcp.json'), JSON.stringify({
      mcpServers: { 'test-server': { command: 'node', args: ['server.js'] } },
    }));
    const r = await capture(() => mcpCommand({ subcommand: 'audit', targetDir: dir, ci: true, format: 'text' }));
    const next = r.stdout.slice(r.stdout.indexOf('Next Steps'));
    expect(next).toContain(`    ${SPANS.mcpSign}\n`);
    expect(next).toContain(`    ${SPANS.mcpVerify}\n`);
    expect(next).not.toMatch(PLACEHOLDER);
  });

  it('identity next steps (exported strings)', () => {
    expect(identityModule.IDENTITY_NEXT_STEPS).toEqual({
      connect: SPANS.identityConnect,
      connectLocal: SPANS.identityConnectLocal,
      serverFlag: SPANS.identityServerFlag,
      apiKeyFlag: SPANS.identityApiKeyFlag,
      logEvent: SPANS.identityLogEvent,
      createAgent: SPANS.identityCreateAgent,
    });
  });

  it('harden-skill in a directory with no skill file', async () => {
    const dir = tempDir('harden-empty');
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      const r = await capture(() => hardenSkill({ format: 'text' }));
      expect(r.code).toBe(1);
      expect(r.stderr).toContain(`Provide a path with: ${SPANS.hardenSkill}\n`);
      expect(r.stderr).not.toMatch(PLACEHOLDER);
    } finally {
      process.chdir(cwd);
    }
  });

  it('login --ci, the non-interactive example', async () => {
    const r = await capture(() => login({ ci: true }));
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(`  ${SPANS.loginApiKey}\n`);
    expect(r.stderr).not.toMatch(PLACEHOLDER);
  });

  it('setup, the trust query after registration (exported string)', () => {
    expect(setupModule.SETUP_TRUST_COMMAND).toBe(SPANS.setupTrust);
  });

  it('trust when the registry cannot be reached', async () => {
    const lookup = vi.spyOn(trustInternals, 'fetchTrustLookup')
      .mockRejectedValue(new Error('connect ECONNREFUSED 127.0.0.1:9'));
    try {
      const r = await capture(() => trust({
        packageName: 'left-pad', registryUrl: 'http://127.0.0.1:9', ci: true, format: 'text',
      }));
      expect(r.code).not.toBe(0);
      expect(r.stderr).toContain(SPANS.trustRegistryUrl);
      expect(r.stderr).not.toMatch(PLACEHOLDER);
    } finally {
      lookup.mockRestore();
    }
  });

  it('advisory warnings', async () => {
    const r = await capture(() => {
      printAdvisoryWarnings({
        advisories: [{
          id: 'OA2A-2026-0001',
          summary: 'Test advisory',
          severity: [{ type: 'ADVISORY', score: 'CRITICAL' }],
          affected: [{ package: { name: 'test-pkg', ecosystem: 'npm' } }],
          published: '2026-03-01T00:00:00Z',
        }],
        matchedPackages: ['test-pkg'],
        total: 1,
        fromCache: false,
        checked: true,
      } as never);
      return 0;
    });
    expect(r.stdout).toContain(`For details, run: ${SPANS.advisoryVerify}\n`);
    expect(r.stdout).not.toMatch(PLACEHOLDER);
  });

  it('review HTML report, How to Fix These Issues', () => {
    const page = renderReviewHmaPage();
    expect(page).toContain('How to Fix These Issues');
    const copies = attributeValues(page, 'data-cmd');
    expect(copies).toContain(SPANS.hmaSkillCheck);
    expect(copies.filter(c => PLACEHOLDER.test(c))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// (3) Pasted into bash, zsh and dash with every parameter unset
// ---------------------------------------------------------------------------

/** Commands a span may start; each is a stub that records that it ran. */
const STUBBED = ['opena2a', 'npm', 'npx', 'git', 'gcloud', 'hackmyagent'];
const SHELLS = ['bash', 'zsh', 'dash'];
const ENV_BIN = ['/usr/bin/env', '/bin/env'].find(p => fs.existsSync(p))!;

function findShell(name: string): string | null {
  for (const dir of ['/bin', '/usr/bin', '/usr/local/bin', '/opt/homebrew/bin']) {
    const p = path.join(dir, name);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function pasteSpans(): { label: string; span: string }[] {
  return [
    ...Object.values(FINDING_CATALOG)
      .filter(f => hasParameter(f.remediation))
      .map(f => ({ label: f.id, span: f.remediation })),
    ...Object.entries(SECRET_ROTATION_TABLE)
      .filter(([, g]) => hasParameter(g.rotationCommand))
      .map(([type, g]) => ({ label: `rotation ${type}`, span: g.rotationCommand! })),
    ...Object.entries(SPANS).map(([label, span]) => ({ label, span })),
  ];
}

describe('each converted span, pasted with its parameters unset, refuses before anything runs', () => {
  const bin = tempDir('paste-bin');
  const log = path.join(SANDBOX, 'paste-ran.log');
  for (const name of STUBBED) {
    fs.writeFileSync(path.join(bin, name), '#!/bin/sh\nprintf \'%s\\n\' "$0 $*" >> "$STUB_LOG"\nexit 0\n', { mode: 0o755 });
  }
  let pasted = 0;

  function paste(shell: string, span: string, unset: string[], set: Record<string, string>) {
    const file = path.join(SANDBOX, `paste-${pasted++}.sh`);
    fs.writeFileSync(file, `${span}\n`);
    fs.writeFileSync(log, '');
    // `--` ends the shell's own options, so a span that is a flag to add to
    // a command (`--server "${...}"`) is read as the command string.
    const args = [
      ...unset.flatMap(v => ['-u', v]),
      ...Object.entries(set).map(([k, v]) => `${k}=${v}`),
      shell, '-c', '--', fs.readFileSync(file, 'utf-8'),
    ];
    const r = spawnSync(ENV_BIN, args, {
      env: { PATH: bin, STUB_LOG: log, HOME: SANDBOX_HOME },
      encoding: 'utf-8',
      timeout: 10_000,
    });
    return { status: r.status, stderr: r.stderr, ran: fs.readFileSync(log, 'utf-8') };
  }

  it('every span is in the fail-closed form', () => {
    const bad = pasteSpans().map(s => [s.label, notFailClosed(s.span)]).filter(([, why]) => why);
    expect(bad).toEqual([]);
  });

  for (const name of SHELLS) {
    const shell = findShell(name);
    it.skipIf(!shell)(`${name}: with the parameter set, the same span runs its command (guards the harness)`, () => {
      const r = paste(shell!, SPANS.initProjectDir, [], { PROJECT_DIR: '/tmp/my project' });
      expect(r.status).toBe(0);
      expect(r.ran).toBe(`${bin}/opena2a init /tmp/my project\n`);
    });

    it.skipIf(!shell)(`${name}: exits non-zero with the message, and runs no command`, () => {
      const spans = pasteSpans();
      expect(spans.length).toBeGreaterThan(Object.keys(SPANS).length);
      const failures: string[] = [];
      for (const { label, span } of spans) {
        const params = parameters(span);
        const names = [...new Set(params.map(p => p.name))];
        const all = paste(shell!, span, names, {});
        console.log(`${name}: exit ${all.status} ${label}: ${params[0]?.message}`);
        if (all.status === 0 || all.status === null) failures.push(`${label}: exit ${all.status}`);
        if (!all.stderr.includes(params[0]?.message ?? '\u0000')) failures.push(`${label}: stderr ${JSON.stringify(all.stderr)}`);
        if (all.ran !== '') failures.push(`${label}: ran ${JSON.stringify(all.ran)}`);
        // With two parameters, each one alone unset still refuses with its own message.
        if (names.length > 1) {
          for (const p of names) {
            const others = Object.fromEntries(names.filter(n => n !== p).map(n => [n, 'value-set-by-test']));
            const one = paste(shell!, span, [p], others);
            const message = params.find(x => x.name === p)!.message;
            if (one.status === 0 || one.status === null) failures.push(`${label} with only ${p} unset: exit ${one.status}`);
            if (!one.stderr.includes(message)) failures.push(`${label} with only ${p} unset: stderr ${JSON.stringify(one.stderr)}`);
          }
        }
      }
      expect(failures).toEqual([]);
    });
    if (!shell) console.log(`${name}: not installed here, so its paste run is skipped`);
  }
});

// ---------------------------------------------------------------------------
// (4) Other classes stay as they are
// ---------------------------------------------------------------------------

describe('spans of other classes keep their form', () => {
  it('usage syntax in the help registries keeps its angle brackets and takes no refusing parameter', () => {
    const registries = Object.entries(subcommandHelp)
      .filter(([name]) => /_HELP$/.test(name))
      .map(([, registry]) => registry as Record<string, { usage?: string; options?: { flag: string }[]; examples?: string[] }>);
    const usage = registries.flatMap(r => Object.values(r).flatMap(h => [
      h.usage ?? '', ...(h.options ?? []).map(o => o.flag), ...(h.examples ?? []),
    ]));
    const tokens = usage.flatMap(s => s.match(PLACEHOLDERS) ?? []);
    expect(tokens.length).toBe(USAGE_PLACEHOLDER_TOKENS);
    expect(usage.filter(s => s.includes('${'))).toEqual([]);
    expect(JSON.stringify(HELP_CONTRACTS)).not.toContain('${');
  });

  it('a Verify step\'s expected output is text to compare, not a command', () => {
    const src = fs.readFileSync(path.join(SRC, 'commands', 'review-findings.ts'), 'utf-8');
    expect(src).toContain("expect: `.gitignore:<line>:${p}  ${p}`");
    expect(src).toContain("expect: '<line>:.env'");
  });

  it('the shield init Fix lines and the export VAULT_TOKEN lines are unchanged', () => {
    const shield = fs.readFileSync(path.join(SRC, 'commands', 'shield.ts'), 'utf-8');
    expect(shield).toContain("'  Fix: opena2a shield init <dir>',");
    expect(shield).toContain("'  Fix: pass one of them, e.g. opena2a shield init <dir>',");
    expect(shield).toContain("'  Fix: opena2a shield init <existing-project-dir>',");
    const vault = fs.readFileSync(path.join(SRC, 'commands', 'vault-migration.ts'), 'utf-8');
    expect(vault).toContain("cyan('export VAULT_TOKEN=<root-token-from-output>')");
    expect(vault).toContain("cyan('export VAULT_TOKEN=<your-token>')");
    const shieldInit = fs.readFileSync(path.join(SRC, 'shield', 'init.ts'), 'utf-8');
    expect(shieldInit).toContain("cyan('export VAULT_TOKEN=<your-token>')");
  });
});
