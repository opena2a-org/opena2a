import * as path from 'path';
import * as fs from 'fs';
import { bold, dim, green, yellow, red, gray, cyan } from '../util/colors.js';
import { resolveServerUrl } from '../util/server-url.js';
import {
  AimClient,
  AimServerError,
  loadServerConfig,
  saveServerConfig,
  removeServerConfig,
  type ServerConfig,
} from '../util/aim-client.js';
import { loadAuth, saveAuth, isAuthValid } from '../util/auth.js';

interface PolicyRule {
  capability: string;
  action: 'allow' | 'deny';
  plugins?: string[];
}

interface Policy {
  version: string;
  defaultAction: 'allow' | 'deny';
  rules: PolicyRule[];
}

interface IdentityOptions {
  subcommand: string;
  name?: string;
  limit?: number;
  dir?: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
  capability?: string;
  plugin?: string;
  action?: string;
  target?: string;
  result?: string;
  file?: string;
  data?: string;
  signature?: string;
  publicKey?: string;
  tools?: string;
  all?: boolean;
  autoSync?: boolean;
  server?: string;
  apiKey?: string;
  json?: boolean;
  /** Positional args passed from Commander (e.g. connect <url>) */
  args?: string[];
}

const USAGE = [
  '',
  'Usage: opena2a identity <subcommand>',
  '',
  'Identity & Keys',
  '  list               Show local agent identity',
  '  create --name <n>  Create a new agent identity (alias: init)',
  '  sign --data <d>    Sign a string with agent private key',
  '  sign --file <f>    Sign a file with agent private key',
  '  verify             Verify a signature against a public key',
  '',
  'Trust & Audit',
  '  trust              Show trust score with factor breakdown',
  '  audit [--limit N]  Show recent audit events',
  '  log                Log an audit event manually',
  '',
  'Policy',
  '  policy             Show current capability policy',
  '  policy load <file> Load a YAML capability policy',
  '  policy --server    List server security policies',
  '  check <capability> Check if a capability is allowed',
  '',
  'Cross-Tool Integration',
  '  attach [--tools <list>]  Wire tools to identity (audit + trust)',
  '  attach --all             Enable all detected tools',
  '  detach                   Remove cross-tool wiring',
  '  sync                     Sync events from enabled tools',
  '',
  'Server Integration',
  '  connect <url>            Connect local identity to an AIM server',
  '  disconnect               Remove server association (keep local identity)',
  '',
  'Tags',
  '  tag list                 List all tags in organization',
  '  tag add <name>           Create a tag and add to current agent',
  '  tag remove <name>        Remove a tag from current agent',
  '',
  'MCPs',
  '  mcp list                 List agent MCP server connections',
  '  mcp add <id>             Add an MCP server to agent',
  '  mcp remove <id>          Remove an MCP server from agent',
  '',
  'Lifecycle',
  '  suspend                  Suspend agent on server (stops all operations)',
  '  reactivate               Reactivate a suspended agent',
  '  revoke                   Permanently delete agent from server (irreversible)',
  '',
  'Activity',
  '  activity [--limit N]     View recent agent activity events',
  '',
  'Server Flags (for create, list, trust, audit, log, tag, mcp, activity, policy, suspend, reactivate, revoke):',
  '  --server <url>           AIM server URL (e.g. localhost:8080, cloud)',
  '  --api-key <key>          AIM API key for authentication',
  '',
].join('\n');

/**
 * Attempt to refresh expired OAuth credentials using the stored refresh token.
 * If the access token is still valid, this is a no-op.
 * If refresh succeeds, the new tokens are saved to ~/.opena2a/auth.json.
 * Returns true if auth is now valid (was valid or refreshed), false otherwise.
 */
async function tryRefreshAuth(): Promise<boolean> {
  const auth = loadAuth();
  if (!auth) return false;

  // Token still valid -- nothing to do
  if (isAuthValid(auth)) return true;

  // Token expired -- attempt refresh if we have a refresh token
  if (!auth.refreshToken) return false;

  try {
    const client = new AimClient(auth.serverUrl);
    const refreshed = await client.refreshAccessToken(auth.refreshToken);
    // Save the new credentials
    const expiresAt = new Date(Date.now() + (refreshed.expiresIn ?? 7200) * 1000).toISOString();
    saveAuth({
      serverUrl: auth.serverUrl,
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken ?? auth.refreshToken,
      expiresAt,
      tokenType: refreshed.tokenType ?? 'Bearer',
      authenticatedAt: new Date().toISOString(),
    });
    return true;
  } catch {
    // Refresh failed -- caller should prompt for re-login
    return false;
  }
}

export async function identity(options: IdentityOptions): Promise<number> {
  // Normalize --json flag to format
  if (options.json) {
    options.format = 'json';
  }

  // Auto-refresh expired OAuth tokens before dispatching subcommands
  await tryRefreshAuth();

  // Resolve --server URL when provided
  if (options.server) {
    options.server = resolveServerUrl(options.server);

    const serverCommands = ['init', 'create', 'list', 'show', 'trust', 'tag', 'mcp', 'activity', 'policy', 'suspend', 'reactivate', 'revoke'];
    if (!serverCommands.includes(options.subcommand)) {
      process.stderr.write(yellow(`Warning: --server is not supported for "identity ${options.subcommand}". Operating in local mode.`) + '\n\n');
      options.server = undefined;
    }
  }

  const sub = options.subcommand;
  switch (sub) {
    case 'list':
    case 'show':
      return handleList(options);
    case 'init':
    case 'create':
      return handleCreate(options);
    case 'trust':
      return handleTrust(options);
    case 'audit':
      return handleAudit(options);
    case 'log':
      return handleLog(options);
    case 'policy':
      return handlePolicy(options);
    case 'check':
      return handleCheck(options);
    case 'sign':
      return handleSign(options);
    case 'verify':
      return handleVerify(options);
    case 'attach':
      return handleAttach(options);
    case 'detach':
      return handleDetach(options);
    case 'sync':
      return handleSync(options);
    case 'connect':
      return handleConnect(options);
    case 'disconnect':
      return handleDisconnect(options);
    case 'tag':
      return handleTag(options);
    case 'mcp':
      return handleMcp(options);
    case 'activity':
      return handleActivity(options);
    case 'suspend':
      return handleSuspend(options);
    case 'reactivate':
      return handleReactivate(options);
    case 'revoke':
      return handleRevoke(options);
    default:
      process.stderr.write(`Unknown identity subcommand: ${sub}\n`);
      process.stderr.write(USAGE + '\n');
      return 1;
  }
}

async function loadAimCore(): Promise<typeof import('@opena2a/aim-core') | null> {
  try {
    return await import('@opena2a/aim-core');
  } catch {
    process.stderr.write('aim-core is not available.\n');
    process.stderr.write('Install: npm install @opena2a/aim-core\n');
    return null;
  }
}

// ---------------------------------------------------------------------------
// Server helpers
// ---------------------------------------------------------------------------

/**
 * Build an AimClient from options. Returns null if no server is specified
 * and no stored config exists.
 */
function getServerClient(options: IdentityOptions): AimClient | null {
  const serverFlag = options.server;
  const config = loadServerConfig();
  const apiKey = options.apiKey ?? config?.apiKey;

  if (serverFlag) {
    const url = resolveServerUrl(serverFlag);
    // If no explicit API key, check global auth for matching server
    if (!apiKey) {
      const globalAuth = loadAuth();
      if (globalAuth && isAuthValid(globalAuth) && globalAuth.serverUrl === url) {
        return new AimClient(url, { accessToken: globalAuth.accessToken });
      }
    }
    return new AimClient(url, { apiKey });
  }
  if (config?.serverUrl) {
    return new AimClient(config.serverUrl, { apiKey });
  }
  // No server flag and no stored config -- try global auth
  const globalAuth = loadAuth();
  if (globalAuth && isAuthValid(globalAuth)) {
    return new AimClient(globalAuth.serverUrl, { accessToken: globalAuth.accessToken });
  }
  return null;
}

/**
 * Check server health. Returns true if reachable, false otherwise.
 * On failure, writes a clear error message.
 */
async function checkServerHealth(client: AimClient, serverUrl: string): Promise<boolean> {
  try {
    await client.health();
    return true;
  } catch (err) {
    if (err instanceof AimServerError && err.serverMessage) {
      process.stderr.write(`Cannot connect to AIM server at ${serverUrl}. Verify the server is running.\n`);
      process.stderr.write(`  Detail: ${err.serverMessage}\n`);
    } else {
      process.stderr.write(`Cannot connect to AIM server at ${serverUrl}. Verify the server is running.\n`);
    }
    return false;
  }
}

/**
 * Resolve the auth token from stored config.
 */
function getStoredAuth(): { token?: string; apiKey?: string; agentId?: string; serverUrl?: string } {
  const config = loadServerConfig();
  if (config) {
    return {
      token: config.accessToken ?? undefined,
      apiKey: config.apiKey ?? undefined,
      agentId: config.agentId,
      serverUrl: config.serverUrl,
    };
  }
  // Fallback: check global auth credentials from "opena2a login"
  const globalAuth = loadAuth();
  if (globalAuth && isAuthValid(globalAuth)) {
    return { token: globalAuth.accessToken, serverUrl: globalAuth.serverUrl };
  }
  return {};
}

/**
 * Format server error for display.
 */
function formatServerError(err: unknown): string {
  if (err instanceof AimServerError) {
    if (err.statusCode === 401) {
      return 'Authentication failed. Check your --api-key or run: opena2a identity connect <url>';
    }
    if (err.statusCode === 403) {
      return 'Access denied. Your API key may lack required permissions.';
    }
    if (err.statusCode === 404) {
      return 'Agent not found on server. It may have been deleted or never registered.';
    }
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// list / show
// ---------------------------------------------------------------------------

async function handleList(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });

    // Check if identity file exists before calling getIdentity(),
    // which auto-creates one if none exists.
    const identityFile = path.join(aim.getDataDir(), 'identity.json');
    if (!fs.existsSync(identityFile)) {
      if (isJson) {
        process.stdout.write(JSON.stringify({ error: 'no identity found' }, null, 2) + '\n');
      } else {
        process.stdout.write('No identity found. Create one with: opena2a identity create --name my-agent\n');
      }
      return 0;
    }

    const id = aim.getIdentity();

    // If server is configured, fetch enriched data
    const client = getServerClient(options);
    const serverConfig = loadServerConfig();
    const auth = getStoredAuth();
    let serverAgent = null;
    let serverAgentList = null;
    const effectiveServerUrl = serverConfig?.serverUrl ?? auth.serverUrl;

    // If we have a server client with auth, try to fetch server data
    if (client && auth.token) {
      try {
        if (serverConfig?.agentId) {
          // Fetch specific agent if we have a registered agent ID
          serverAgent = await client.getAgent(auth.token, serverConfig.agentId);
        } else {
          // No specific agent ID — list all agents from server
          serverAgentList = await client.listAgents(auth.token);
        }
      } catch (err) {
        if (!isJson) {
          process.stderr.write(yellow(`Warning: Could not fetch server data: ${formatServerError(err)}`) + '\n');
          process.stderr.write(yellow('Showing local identity only.') + '\n\n');
        }
      }
    } else if (client && serverConfig?.agentId && auth.apiKey) {
      try {
        const loginResp = await client.login({ name: id.agentName, apiKey: auth.apiKey });
        serverAgent = await client.getAgent(loginResp.accessToken, serverConfig.agentId);
        saveServerConfig({ ...serverConfig, accessToken: loginResp.accessToken, refreshToken: loginResp.refreshToken });
      } catch (err) {
        if (!isJson) {
          process.stderr.write(yellow(`Warning: Could not fetch server data: ${formatServerError(err)}`) + '\n');
          process.stderr.write(yellow('Showing local identity only.') + '\n\n');
        }
      }
    }

    // If server returned a list of agents (from global auth), show them
    if (serverAgentList && serverAgentList.agents?.length > 0) {
      if (isJson) {
        process.stdout.write(JSON.stringify({
          local: { ...id },
          server: { url: effectiveServerUrl, agents: serverAgentList.agents, total: serverAgentList.total },
        }, null, 2) + '\n');
        return 0;
      }

      process.stdout.write(bold('Local Identity') + '\n');
      process.stdout.write(gray('-'.repeat(50)) + '\n');
      process.stdout.write(`  Agent ID:    ${cyan(id.agentId)}\n`);
      process.stdout.write(`  Name:        ${id.agentName}\n`);
      process.stdout.write(`  Public Key:  ${dim(id.publicKey.slice(0, 32) + '...')}\n`);
      process.stdout.write(`  Created:     ${id.createdAt}\n`);
      process.stdout.write(gray('-'.repeat(50)) + '\n\n');

      process.stdout.write(bold(`Server Agents (${effectiveServerUrl})`) + '\n');
      process.stdout.write(gray('-'.repeat(50)) + '\n');
      for (const agent of serverAgentList.agents) {
        const statusColor = agent.status === 'verified' ? green : agent.status === 'active' ? cyan : yellow;
        process.stdout.write(`  ${cyan(agent.name)} (${dim(agent.id)})\n`);
        process.stdout.write(`    Status: ${statusColor(agent.status)}  Trust: ${agent.trustScore}\n`);
      }
      process.stdout.write(gray('-'.repeat(50)) + '\n');
      process.stdout.write(dim(`  ${serverAgentList.total} agent(s) total`) + '\n');
      return 0;
    }

    if (isJson) {
      const result: Record<string, unknown> = { ...id };
      if (serverAgent) {
        result.server = {
          id: serverAgent.id,
          name: serverAgent.name,
          trustScore: serverAgent.trustScore,
          status: serverAgent.status,
          serverUrl: effectiveServerUrl,
        };
      }
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold('Agent Identity') + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(`  Agent ID:    ${cyan(id.agentId)}\n`);
    process.stdout.write(`  Name:        ${id.agentName}\n`);
    process.stdout.write(`  Public Key:  ${dim(id.publicKey.slice(0, 32) + '...')}\n`);
    process.stdout.write(`  Created:     ${id.createdAt}\n`);
    process.stdout.write(`  Data Dir:    ${dim(aim.getDataDir())}\n`);

    if (serverAgent && serverConfig) {
      process.stdout.write('\n' + bold('  Server') + '\n');
      process.stdout.write(`  Server URL:  ${cyan(serverConfig.serverUrl)}\n`);
      process.stdout.write(`  Server ID:   ${serverAgent.id}\n`);
      process.stdout.write(`  Status:      ${serverAgent.status === 'verified' ? green(serverAgent.status) : yellow(serverAgent.status)}\n`);
      process.stdout.write(`  Trust Score: ${serverAgent.trustScore}\n`);
    } else if (serverConfig) {
      process.stdout.write('\n' + bold('  Server') + '\n');
      process.stdout.write(`  Server URL:  ${cyan(serverConfig.serverUrl)}\n`);
      process.stdout.write(`  Server ID:   ${serverConfig.agentId}\n`);
      process.stdout.write(`  Status:      ${dim('offline or unreachable')}\n`);
    }

    process.stdout.write(gray('-'.repeat(50)) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to load identity: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

async function handleCreate(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const name = options.name;
  if (!name) {
    process.stderr.write('Missing required option: --name <name>\n');
    process.stderr.write('Usage: opena2a identity create --name my-agent\n');
    process.stderr.write('       opena2a identity create --name my-agent --server cloud\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    // If --server is provided or global auth exists, register on the server
    const globalAuth = loadAuth();
    if (options.server || (globalAuth && isAuthValid(globalAuth))) {
      return handleServerCreate(options, name, isJson);
    }

    // Local-only creation
    const aim = new mod.AIMCore({ agentName: name });

    const dataDir = aim.getDataDir();
    const identityPath = await import('node:path').then(p => p.join(dataDir, 'identity.json'));
    const { existsSync } = await import('node:fs');
    const existing = existsSync(identityPath);

    const id = aim.getIdentity();

    if (isJson) {
      process.stdout.write(JSON.stringify({ ...id, created: !existing }, null, 2) + '\n');
      return 0;
    }

    if (existing) {
      process.stdout.write(yellow('Identity already exists') + '\n');
      process.stdout.write(dim('  aim-core uses a single identity per data directory.') + '\n');
      process.stdout.write(dim('  To start fresh, remove ~/.opena2a/aim-core/ and re-run.') + '\n\n');
    } else {
      process.stdout.write(green('Identity created') + '\n');
    }
    process.stdout.write(`  Agent ID:    ${cyan(id.agentId)}\n`);
    process.stdout.write(`  Name:        ${id.agentName}\n`);
    process.stdout.write(`  Public Key:  ${dim(id.publicKey.slice(0, 32) + '...')}\n`);
    process.stdout.write(`  Stored in:   ${dim(aim.getDataDir())}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to create identity: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

/**
 * Register agent on the AIM server and store the result locally.
 */
async function handleServerCreate(options: IdentityOptions, name: string, isJson: boolean): Promise<number> {
  // Resolve server URL from flag or stored auth
  const globalAuth = loadAuth();
  const hasOAuth = globalAuth && isAuthValid(globalAuth);
  const serverUrl = options.server
    ? resolveServerUrl(options.server)
    : hasOAuth ? globalAuth!.serverUrl : '';
  const apiKey = options.apiKey;

  if (!serverUrl) {
    process.stderr.write('No server specified. Use --server <url> or run: opena2a login\n');
    return 1;
  }

  if (!apiKey && !hasOAuth) {
    process.stderr.write('Authentication required.\n');
    process.stderr.write('Run "opena2a login" first, or use --api-key <key>.\n');
    return 1;
  }

  // Build client with OAuth token or API key
  const client = hasOAuth && (!options.server || globalAuth!.serverUrl === serverUrl)
    ? new AimClient(serverUrl, { accessToken: globalAuth!.accessToken })
    : new AimClient(serverUrl, { apiKey });

  // 1. Health check
  if (!(await checkServerHealth(client, serverUrl))) {
    return 1;
  }

  try {
    // 2. Register on server (use authenticated endpoint if OAuth, public endpoint if API key)
    let resp: any;
    if (hasOAuth && (!options.server || globalAuth!.serverUrl === serverUrl)) {
      resp = await client.createAgent({ name, displayName: name, description: `Agent ${name} registered via OpenA2A CLI` });
    } else {
      resp = await client.register({ name, displayName: name, description: `Agent ${name} registered via OpenA2A CLI` }, apiKey!);
    }

    // Normalize response - server may return different shapes
    const agentId = resp.agentId ?? resp.id ?? resp.agent?.id;
    const agentName = resp.name ?? resp.agent?.name ?? name;

    // 3. Also create local identity via aim-core
    const mod = await loadAimCore();
    let localId = null;
    if (mod) {
      const aim = new mod.AIMCore({ agentName: name });
      localId = aim.getIdentity();
    }

    // 4. Store server config locally
    const config: ServerConfig = {
      serverUrl,
      agentId: agentId,
      apiKey,
      registeredAt: new Date().toISOString(),
    };
    saveServerConfig(config);

    if (isJson) {
      process.stdout.write(JSON.stringify({
        created: true,
        server: {
          id: agentId,
          name: agentName,
          displayName: resp.displayName ?? agentName,
          publicKey: resp.publicKey,
          trustScore: resp.trustScore,
          status: resp.status,
          serverUrl,
        },
        local: localId ? {
          agentId: localId.agentId,
          agentName: localId.agentName,
          publicKey: localId.publicKey,
        } : null,
      }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green('Agent registered on AIM server') + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(`  Server ID:    ${cyan(agentId)}\n`);
    process.stdout.write(`  Name:         ${agentName}\n`);
    process.stdout.write(`  Display Name: ${resp.displayName ?? agentName}\n`);
    process.stdout.write(`  Public Key:   ${dim((resp.publicKey ?? '').slice(0, 32) + '...')}\n`);
    process.stdout.write(`  Trust Score:  ${resp.trustScore ?? 'pending'}\n`);
    process.stdout.write(`  Status:       ${(resp.status === 'verified' ? green(resp.status) : yellow(resp.status ?? 'pending'))}\n`);
    process.stdout.write(`  Server URL:   ${dim(serverUrl)}\n`);
    if (localId) {
      process.stdout.write(`\n  Local ID:     ${dim(localId.agentId)}\n`);
    }
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(dim('Server config stored in ~/.opena2a/aim-core/identities/server.json') + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to register on server: ${formatServerError(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// trust
// ---------------------------------------------------------------------------

async function handleTrust(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    aim.getIdentity(); // ensure identity exists

    // If server is configured, fetch server-side trust data
    const client = getServerClient(options);
    const serverConfig = loadServerConfig();
    let serverAgent = null;

    if (client && serverConfig?.agentId) {
      try {
        const auth = getStoredAuth();
        if (auth.token) {
          serverAgent = await client.getAgent(auth.token, serverConfig.agentId);
        } else if (auth.apiKey) {
          const id = aim.getIdentity();
          const loginResp = await client.login({ name: id.agentName, apiKey: auth.apiKey });
          serverAgent = await client.getAgent(loginResp.accessToken, serverConfig.agentId);
          saveServerConfig({ ...serverConfig, accessToken: loginResp.accessToken, refreshToken: loginResp.refreshToken });
        }
      } catch (err) {
        if (!isJson) {
          process.stderr.write(yellow(`Warning: Could not fetch server trust data: ${formatServerError(err)}`) + '\n\n');
        }
      }
    }

    // Auto-sync trust hints if a manifest exists (tools are attached)
    const targetDir = path.resolve(options.dir ?? process.cwd());
    let hasManifest = false;
    try {
      const { readManifest } = await import('../identity/manifest.js');
      const { collectTrustHints } = await import('../identity/trust-collector.js');
      const manifest = readManifest(targetDir);
      if (manifest) {
        hasManifest = true;
        const { hints } = collectTrustHints(targetDir, manifest);
        (aim as any).setTrustHints(hints);
      }
    } catch {
      // Identity module not available or manifest missing
    }

    const trust = aim.calculateTrust();

    if (isJson) {
      const result: Record<string, unknown> = { ...trust, attached: hasManifest };
      if (serverAgent) {
        result.server = {
          trustScore: serverAgent.trustScore,
          status: serverAgent.status,
          serverUrl: serverConfig?.serverUrl,
        };
      }
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      return 0;
    }

    const displayScore = trust.score ?? Math.round((trust.overall ?? 0) * 100);
    const displayGrade = trust.grade ?? scoreToGrade(displayScore);
    const gradeColor = displayScore >= 80 ? green : displayScore >= 60 ? yellow : red;

    process.stdout.write(bold('Trust Score') + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(`  Score:  ${gradeColor(bold(String(displayScore) + '/100'))}  (${gradeColor(displayGrade)})\n`);

    // Show server trust score if available
    if (serverAgent) {
      const serverScore = serverAgent.trustScore;
      const serverColor = serverScore >= 80 ? green : serverScore >= 60 ? yellow : red;
      process.stdout.write(`  Server: ${serverColor(bold(String(serverScore) + '/100'))}  ${dim('(from AIM server)')}\n`);
    }

    process.stdout.write('\n');
    process.stdout.write(bold('  Factors:') + '\n');
    for (const [factor, value] of Object.entries(trust.factors)) {
      const label = factor.replace(/([A-Z])/g, ' $1').toLowerCase().trim();
      const pct = Math.round((value as number) * 100);
      const bar = progressBar(pct, 20);
      process.stdout.write(`    ${label.padEnd(18)} ${bar} ${pct}%\n`);
    }
    process.stdout.write(gray('-'.repeat(50)) + '\n');

    if (options.verbose) {
      if (trust.calculatedAt) {
        process.stdout.write(dim(`  Calculated: ${trust.calculatedAt}`) + '\n');
      }
      const zeroFactors = Object.entries(trust.factors).filter(([, v]) => (v as number) === 0);
      if (zeroFactors.length > 0) {
        process.stdout.write('\n' + bold('  How to improve:') + '\n');
        const factorSuggestions: Record<string, string> = {
          secretsManaged: 'npx secretless-ai init',
          configSigned: 'opena2a guard sign',
          skillsVerified: 'npx hackmyagent secure',
          networkControlled: 'opena2a runtime --init',
          heartbeatMonitored: 'opena2a shield init',
        };
        for (const [factor] of zeroFactors) {
          const suggestion = factorSuggestions[factor];
          if (suggestion) {
            const label = factor.replace(/([A-Z])/g, ' $1').toLowerCase().trim();
            process.stdout.write(`    ${label.padEnd(18)} ${dim(suggestion)}\n`);
          }
        }
      }
    }

    if (!hasManifest) {
      process.stdout.write('\n' + dim('  No tools attached. Run: opena2a identity attach --all') + '\n');
      process.stdout.write(dim('  Attaching tools improves trust by syncing real security state.') + '\n');
    }

    // Community contribution: share trust score with registry
    try {
      const { recordScanAndMaybePrompt, isContributeEnabled, getRegistryUrl, submitScanReport } =
        await import('../util/report-submission.js');
      await recordScanAndMaybePrompt();

      if (await isContributeEnabled()) {
        const registryUrl = await getRegistryUrl();
        if (registryUrl) {
          await submitScanReport(registryUrl, {
            packageName: 'agent-trust',
            packageType: 'trust',
            scannerName: 'opena2a-identity',
            scannerVersion: '0.6.3',
            overallScore: displayScore,
            scanDurationMs: 0,
            criticalCount: 0,
            highCount: 0,
            mediumCount: 0,
            lowCount: 0,
            infoCount: Object.keys(trust.factors).length,
            verdict: displayScore >= 70 ? 'pass' : displayScore >= 40 ? 'warnings' : 'fail',
            findings: Object.entries(trust.factors)
              .filter(([, v]) => (v as number) === 0)
              .map(([factor], i) => ({
                findingId: `TRUST-${String(i + 1).padStart(3, '0')}`,
                severity: 'medium',
                category: 'trust',
                title: `${factor.replace(/([A-Z])/g, ' $1').trim()} not active`,
              })),
          }, options.verbose);
        }
      }
    } catch {
      // Non-critical
    }

    return 0;
  } catch (err) {
    process.stderr.write(`Failed to calculate trust: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

async function handleAudit(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';
  const limit = options.limit ?? 10;

  // If server is configured, fetch server-side audit logs
  const client = getServerClient(options);
  const serverConfig = loadServerConfig();

  if (client && serverConfig?.agentId) {
    try {
      const auth = getStoredAuth();
      let token = auth.token;

      if (!token && auth.apiKey) {
        const aim = new mod.AIMCore({ agentName: 'default' });
        const id = aim.getIdentity();
        const loginResp = await client.login({ name: id.agentName, apiKey: auth.apiKey });
        token = loginResp.accessToken;
        saveServerConfig({ ...serverConfig, accessToken: loginResp.accessToken, refreshToken: loginResp.refreshToken });
      }

      if (token) {
        const resp = await client.getAuditLogs(token, serverConfig.agentId, { pageSize: limit });

        if (isJson) {
          process.stdout.write(JSON.stringify({
            source: 'server',
            serverUrl: serverConfig.serverUrl,
            total: resp.total,
            auditLogs: resp.auditLogs,
          }, null, 2) + '\n');
          return 0;
        }

        process.stdout.write(bold(`Server Audit Log (${resp.auditLogs.length} of ${resp.total})`) + '\n');
        process.stdout.write(dim(`  Server: ${serverConfig.serverUrl}`) + '\n');
        process.stdout.write(gray('-'.repeat(70)) + '\n');

        if (resp.auditLogs.length === 0) {
          process.stdout.write(dim('  No server audit events recorded yet.') + '\n');
        } else {
          for (const e of resp.auditLogs) {
            const ts = (e.createdAt ?? '').slice(0, 19).replace('T', ' ');
            process.stdout.write(`  ${dim(ts)}  ${(e.action ?? '').padEnd(16)} ${(e.resource ?? '').padEnd(16)} ${dim(e.details ?? '')}\n`);
          }
        }
        process.stdout.write(gray('-'.repeat(70)) + '\n');

        // Also show local audit events if --verbose
        if (options.verbose) {
          process.stdout.write('\n');
          return showLocalAudit(mod, limit, isJson);
        }
        return 0;
      }
    } catch (err) {
      if (!isJson) {
        process.stderr.write(yellow(`Warning: Could not fetch server audit logs: ${formatServerError(err)}`) + '\n');
        process.stderr.write(yellow('Showing local audit log.') + '\n\n');
      }
    }
  }

  return showLocalAudit(mod, limit, isJson);
}

async function showLocalAudit(mod: typeof import('@opena2a/aim-core'), limit: number, isJson: boolean): Promise<number> {
  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    const events = aim.readAuditLog({ limit });

    if (isJson) {
      process.stdout.write(JSON.stringify(events, null, 2) + '\n');
      return 0;
    }

    if (events.length === 0) {
      process.stdout.write(dim('No audit events recorded yet.') + '\n');
      process.stdout.write(dim('Log events with: opena2a identity log --action <action> --target <target>') + '\n');
      return 0;
    }

    process.stdout.write(bold(`Audit Log (last ${events.length})`) + '\n');
    process.stdout.write(gray('-'.repeat(70)) + '\n');
    for (const e of events) {
      const ts = e.timestamp.slice(0, 19).replace('T', ' ');
      const resultColor = e.result === 'allowed' ? green : e.result === 'denied' ? red : yellow;
      const pluginLabel = e.plugin && e.plugin !== 'unknown' ? dim(` [${e.plugin}]`) : '';
      process.stdout.write(`  ${dim(ts)}  ${(e.action ?? '').padEnd(16)} ${(e.target ?? '').padEnd(16)} ${resultColor(e.result ?? '')}${pluginLabel}\n`);
    }
    process.stdout.write(gray('-'.repeat(70)) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to read audit log: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// log -- write an audit event
// ---------------------------------------------------------------------------

async function handleLog(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const action = options.action;
  if (!action) {
    process.stderr.write('Missing required option: --action <action>\n');
    process.stderr.write('Usage: opena2a identity log --action db:read --target customers [--result allowed]\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    aim.getIdentity(); // ensure identity exists

    const validResults = ['allowed', 'denied', 'error'] as const;
    const resultInput = options.result ?? 'allowed';
    if (!validResults.includes(resultInput as typeof validResults[number])) {
      process.stderr.write(`Invalid --result value: ${resultInput}\n`);
      process.stderr.write('Valid values: allowed, denied, error\n');
      return 1;
    }

    const event = aim.logEvent({
      action,
      target: options.target ?? '',
      result: resultInput as 'allowed' | 'denied' | 'error',
      plugin: options.plugin ?? 'cli',
    });

    if (isJson) {
      process.stdout.write(JSON.stringify(event, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green('Event logged') + '\n');
    process.stdout.write(`  Action:  ${event.action}\n`);
    process.stdout.write(`  Target:  ${event.target}\n`);
    process.stdout.write(`  Result:  ${event.result}\n`);
    process.stdout.write(`  Time:    ${dim(event.timestamp)}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to log event: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// connect -- connect existing local identity to an AIM server
// ---------------------------------------------------------------------------

async function handleConnect(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  // The URL comes from the positional arg or --server flag
  const rawUrl = options.args?.[0] ?? options.server;
  if (!rawUrl) {
    process.stderr.write('Missing server URL.\n');
    process.stderr.write('Usage: opena2a identity connect <url> --api-key <key>\n');
    process.stderr.write('       opena2a identity connect localhost:8080 --api-key <key>\n');
    return 1;
  }

  const apiKey = options.apiKey;
  if (!apiKey) {
    process.stderr.write('Missing required option: --api-key <key>\n');
    process.stderr.write('The AIM server requires an API key for agent registration.\n');
    return 1;
  }

  const serverUrl = resolveServerUrl(rawUrl);
  const client = new AimClient(serverUrl);
  const isJson = options.format === 'json';

  // 1. Health check
  if (!(await checkServerHealth(client, serverUrl))) {
    return 1;
  }

  try {
    // 2. Load local identity
    const aim = new mod.AIMCore({ agentName: 'default' });
    const identityFile = path.join(aim.getDataDir(), 'identity.json');
    if (!fs.existsSync(identityFile)) {
      process.stderr.write('No local identity found. Create one first: opena2a identity create --name my-agent\n');
      return 1;
    }
    const id = aim.getIdentity();

    // 3. Register on server
    const resp = await client.register(
      { name: id.agentName, displayName: id.agentName, description: `Agent ${id.agentName} registered via OpenA2A CLI` },
      apiKey,
    );

    // 4. Store server config
    const config: ServerConfig = {
      serverUrl,
      agentId: resp.agentId,
      apiKey,
      registeredAt: new Date().toISOString(),
    };
    saveServerConfig(config);

    // 5. Log the connect event
    aim.logEvent({
      action: 'identity.connect',
      target: serverUrl,
      result: 'allowed',
      plugin: 'opena2a-cli',
    });

    if (isJson) {
      process.stdout.write(JSON.stringify({
        connected: true,
        localAgentId: id.agentId,
        serverAgentId: resp.agentId,
        serverUrl,
        trustScore: resp.trustScore,
        status: resp.status,
      }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green('Connected to AIM server') + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(`  Local ID:    ${cyan(id.agentId)}\n`);
    process.stdout.write(`  Server ID:   ${cyan(resp.agentId)}\n`);
    process.stdout.write(`  Server URL:  ${dim(serverUrl)}\n`);
    process.stdout.write(`  Trust Score: ${resp.trustScore}\n`);
    process.stdout.write(`  Status:      ${resp.status === 'verified' ? green(resp.status) : yellow(resp.status)}\n`);
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(dim('Future commands will automatically use this server.') + '\n');
    process.stdout.write(dim('Disconnect with: opena2a identity disconnect') + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to connect to server: ${formatServerError(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// disconnect -- remove server association
// ---------------------------------------------------------------------------

async function handleDisconnect(options: IdentityOptions): Promise<number> {
  const isJson = options.format === 'json';
  const config = loadServerConfig();

  if (!config) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ disconnected: false, reason: 'no server configured' }, null, 2) + '\n');
    } else {
      process.stdout.write('No server connection configured.\n');
    }
    return 0;
  }

  const removed = removeServerConfig();

  // Log the disconnect event
  try {
    const mod = await loadAimCore();
    if (mod) {
      const aim = new mod.AIMCore({ agentName: 'default' });
      aim.logEvent({
        action: 'identity.disconnect',
        target: config.serverUrl,
        result: 'allowed',
        plugin: 'opena2a-cli',
      });
    }
  } catch {
    // Non-critical
  }

  if (isJson) {
    process.stdout.write(JSON.stringify({
      disconnected: removed,
      serverUrl: config.serverUrl,
      agentId: config.agentId,
    }, null, 2) + '\n');
  } else {
    process.stdout.write(green('Disconnected from AIM server') + '\n');
    process.stdout.write(`  Server URL: ${dim(config.serverUrl)}\n`);
    process.stdout.write(`  Server ID:  ${dim(config.agentId)}\n`);
    process.stdout.write(dim('\n  Local identity and audit log are preserved.') + '\n');
    process.stdout.write(dim('  Only the server association was removed.') + '\n');
  }
  return 0;
}

// ---------------------------------------------------------------------------
// policy -- show or load capability policy
// ---------------------------------------------------------------------------

async function handlePolicy(options: IdentityOptions): Promise<number> {
  const isJson = options.format === 'json';

  // When --server is specified, fetch server security policies
  if (options.server) {
    return handleServerPolicies(options);
  }

  const mod = await loadAimCore();
  if (!mod) return 1;

  const args = options.file ? ['load', options.file] : [];

  // If first positional arg is "load", load a YAML policy
  if (args[0] === 'load' || options.file) {
    return handlePolicyLoad(mod, options);
  }

  // Otherwise show the current local policy
  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    const p = aim.loadPolicy() as Policy;

    if (isJson) {
      process.stdout.write(JSON.stringify(p, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold('Capability Policy') + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(`  Default: ${p.defaultAction === 'deny' ? red('deny') : green('allow')}\n`);
    process.stdout.write(`  Rules:   ${p.rules.length}\n`);
    process.stdout.write('\n');

    if (p.rules.length === 0) {
      process.stdout.write(dim('  No rules defined.') + '\n');
      process.stdout.write(dim('  Load a policy: opena2a identity policy --file policy.yaml') + '\n');
    } else {
      for (const rule of p.rules) {
        const actionColor = rule.action === 'allow' ? green : red;
        const pluginNote = rule.plugins?.length ? dim(` (plugins: ${rule.plugins.join(', ')})`) : '';
        process.stdout.write(`  ${actionColor(rule.action.padEnd(5))}  ${rule.capability}${pluginNote}\n`);
      }
    }
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to read policy: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

async function handleServerPolicies(options: IdentityOptions): Promise<number> {
  const isJson = options.format === 'json';

  const auth = getStoredAuth();
  if (!auth.token) {
    process.stderr.write('Not authenticated. Run: opena2a login\n');
    return 1;
  }

  const serverUrl = auth.serverUrl ?? loadServerConfig()?.serverUrl ?? '';
  const authedClient = new AimClient(serverUrl, { accessToken: auth.token });

  try {
    const resp = await authedClient.listPolicies();
    const policies = resp.policies ?? [];

    if (isJson) {
      process.stdout.write(JSON.stringify({ policies }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold(`Server Policies (${serverUrl})`) + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');

    if (policies.length === 0) {
      process.stdout.write(dim('  No policies found.') + '\n');
    } else {
      for (const p of policies) {
        const name = p.name ?? 'unnamed';
        const id = p.id ?? '';
        const pType = p.type ?? p.policyType ?? 'unknown';
        const status = p.enabled !== undefined
          ? (p.enabled ? 'active' : 'inactive')
          : (p.status ?? 'unknown');
        const statusColor = status === 'active' ? green : status === 'inactive' ? dim : yellow;
        const rules = p.rules ?? [];
        const allowCount = rules.filter((r: any) => r.action === 'allow').length;
        const denyCount = rules.filter((r: any) => r.action === 'deny').length;

        process.stdout.write(`  ${bold(name)} ${dim(`(id: ${id})`)}\n`);
        process.stdout.write(`    Type: ${pType} | Status: ${statusColor(status)}\n`);
        process.stdout.write(`    Rules: ${allowCount} allow, ${denyCount} deny\n`);
      }
    }

    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(dim(`  ${policies.length} ${policies.length === 1 ? 'policy' : 'policies'} total`) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to list server policies: ${formatServerError(err)}\n`);
    return 1;
  }
}

async function handlePolicyLoad(mod: typeof import('@opena2a/aim-core'), options: IdentityOptions): Promise<number> {
  const filePath = options.file;
  if (!filePath) {
    process.stderr.write('Missing file path.\n');
    process.stderr.write('Usage: opena2a identity policy --file policy.yaml\n');
    return 1;
  }

  const isJson = options.format === 'json';
  const resolved = path.resolve(filePath);

  if (!fs.existsSync(resolved)) {
    process.stderr.write(`File not found: ${resolved}\n`);
    return 1;
  }

  try {
    const content = fs.readFileSync(resolved, 'utf-8');
    let parsed: Policy;

    if (resolved.endsWith('.json')) {
      parsed = JSON.parse(content);
    } else if (resolved.endsWith('.yaml') || resolved.endsWith('.yml')) {
      parsed = parseSimpleYamlPolicy(content);
    } else {
      process.stderr.write('Unsupported file format. Use .json or .yaml/.yml\n');
      return 1;
    }

    const aim = new mod.AIMCore({ agentName: 'default' });
    (aim as any).savePolicy(parsed);

    if (isJson) {
      process.stdout.write(JSON.stringify({ loaded: true, rules: parsed.rules?.length ?? 0, path: resolved }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green('Policy loaded') + '\n');
    process.stdout.write(`  File:    ${dim(resolved)}\n`);
    process.stdout.write(`  Default: ${parsed.defaultAction}\n`);
    process.stdout.write(`  Rules:   ${parsed.rules?.length ?? 0}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to load policy: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// check -- check if a capability is allowed
// ---------------------------------------------------------------------------

async function handleCheck(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const capability = options.capability;
  if (!capability) {
    process.stderr.write('Missing capability to check.\n');
    process.stderr.write('Usage: opena2a identity check <capability> [--plugin <name>]\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    aim.loadPolicy(); // load from file

    const allowed = aim.checkCapability(capability, options.plugin);

    if (isJson) {
      process.stdout.write(JSON.stringify({ capability, allowed, plugin: options.plugin ?? null }, null, 2) + '\n');
      return 0;
    }

    const label = allowed ? green('ALLOWED') : red('DENIED');
    process.stdout.write(`${label}  ${capability}`);
    if (options.plugin) process.stdout.write(dim(` (plugin: ${options.plugin})`));
    process.stdout.write('\n');
    return allowed ? 0 : 1;
  } catch (err) {
    process.stderr.write(`Failed to check capability: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// sign -- sign data with agent private key
// ---------------------------------------------------------------------------

async function handleSign(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  let data: string | undefined = options.data;
  let label = data;
  let dataBytes: Uint8Array;

  if (options.file && options.subcommand === 'sign') {
    // Sign file contents
    const resolved = path.resolve(options.file);
    if (!fs.existsSync(resolved)) {
      process.stderr.write(`File not found: ${resolved}\n`);
      return 1;
    }
    const fileContents = fs.readFileSync(resolved);
    dataBytes = new Uint8Array(fileContents);
    label = path.basename(resolved);
  } else if (data) {
    dataBytes = new TextEncoder().encode(data);
  } else {
    process.stderr.write('Missing required option: --data <string> or --file <path>\n');
    process.stderr.write('Usage:\n');
    process.stderr.write('  opena2a identity sign --data "message to sign"\n');
    process.stderr.write('  opena2a identity sign --file ./config.json\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    const id = aim.getIdentity();
    const signature = aim.sign(dataBytes);
    const sigBase64 = Buffer.from(signature).toString('base64');

    if (isJson) {
      process.stdout.write(JSON.stringify({
        ...(options.file ? { file: path.resolve(options.file) } : { data }),
        signature: sigBase64,
        publicKey: id.publicKey,
        agentId: id.agentId,
      }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold('Signature') + '\n');
    const displayLabel = label && label.length > 60 ? label.slice(0, 60) + '...' : (label ?? '');
    if (options.file) {
      process.stdout.write(`  File:       ${dim(path.resolve(options.file))}\n`);
    } else {
      process.stdout.write(`  Data:       ${dim(displayLabel)}\n`);
    }
    process.stdout.write(`  Signature:  ${sigBase64}\n`);
    process.stdout.write(`  Public Key: ${dim(id.publicKey)}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to sign: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// verify -- verify a signature
// ---------------------------------------------------------------------------

async function handleVerify(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const data = options.data;
  const signature = options.signature;
  const publicKey = options.publicKey;

  if (!data || !signature || !publicKey) {
    process.stderr.write('Missing required options.\n');
    process.stderr.write('Usage: opena2a identity verify --data "message" --signature <base64> --public-key <base64>\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    const dataBytes = new TextEncoder().encode(data);
    const sigBytes = new Uint8Array(Buffer.from(signature, 'base64'));
    const valid = aim.verify(dataBytes, sigBytes, publicKey);

    if (isJson) {
      process.stdout.write(JSON.stringify({ valid, data, publicKey }, null, 2) + '\n');
      return 0;
    }

    if (valid) {
      process.stdout.write(green('VALID') + '  Signature verified\n');
    } else {
      process.stdout.write(red('INVALID') + '  Signature verification failed\n');
    }
    return valid ? 0 : 1;
  } catch (err) {
    process.stderr.write(`Failed to verify: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// attach -- wire tools to identity
// ---------------------------------------------------------------------------

async function handleAttach(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';
  const targetDir = path.resolve(options.dir ?? process.cwd());

  try {
    // 1. Get or create identity
    const agentName = options.name ?? 'default';
    const aim = new mod.AIMCore({ agentName });
    const id = aim.getIdentity();

    if (!isJson) {
      process.stdout.write(bold('Attaching identity to tools') + '\n');
      process.stdout.write(gray('-'.repeat(60)) + '\n');
      process.stdout.write(`  Agent:     ${cyan(id.agentId)}\n`);
      process.stdout.write(`  Name:      ${id.agentName}\n`);
      process.stdout.write(`  Directory: ${dim(targetDir)}\n\n`);
    }

    // 2. Determine which tools to enable
    const { readManifest, writeManifest } = await import('../identity/manifest.js');
    const { collectTrustHints } = await import('../identity/trust-collector.js');
    const { importAllToolEvents } = await import('../identity/bridges.js');

    const existing = readManifest(targetDir);
    let enabledTools = {
      secretless: false,
      configguard: false,
      arp: false,
      hma: false,
      shield: false,
    };

    if (options.all) {
      enabledTools = { secretless: true, configguard: true, arp: true, hma: true, shield: true };
    } else if (options.tools) {
      const requested = options.tools.split(',').map(t => t.trim().toLowerCase());
      const knownTools = ['secretless', 'configguard', 'guard', 'arp', 'hma', 'hackmyagent', 'shield'];
      const unknown = requested.filter(t => !knownTools.includes(t));
      if (unknown.length > 0) {
        process.stderr.write(`Unknown tool(s): ${unknown.join(', ')}\n`);
        process.stderr.write(`Valid tools: secretless, configguard, arp, hma, shield\n`);
        return 1;
      }
      if (existing) {
        enabledTools = { ...existing.tools };
      }
      for (const tool of requested) {
        if (tool === 'secretless') enabledTools.secretless = true;
        if (tool === 'configguard' || tool === 'guard') enabledTools.configguard = true;
        if (tool === 'arp') enabledTools.arp = true;
        if (tool === 'hma' || tool === 'hackmyagent') enabledTools.hma = true;
        if (tool === 'shield') enabledTools.shield = true;
      }
    } else if (existing) {
      enabledTools = existing.tools;
    } else {
      enabledTools = { secretless: true, configguard: true, arp: true, hma: true, shield: true };
    }

    // 3. Collect trust hints from enabled tools
    const manifest = {
      version: '1',
      agent: { name: id.agentName, agentId: id.agentId, publicKey: id.publicKey, created: id.createdAt },
      tools: enabledTools,
      bridging: { autoSync: options.autoSync ?? true, lastSyncAt: null as string | null },
      registry: { contribute: false, gtin: false, sensorToken: null },
    };

    const { hints, details } = collectTrustHints(targetDir, manifest);

    if (!isJson) {
      if (options.tools) {
        process.stdout.write(bold('  Requested tools: ') + options.tools + '\n\n');
      }
      process.stdout.write(bold('  Tool Detection:') + '\n');

      const allToolNames = [
        { key: 'secretless' as const, label: 'Secretless' },
        { key: 'configguard' as const, label: 'ConfigGuard' },
        { key: 'arp' as const, label: 'ARP' },
        { key: 'hma' as const, label: 'HMA' },
        { key: 'shield' as const, label: 'Shield' },
      ];
      for (const t of allToolNames) {
        const isEnabled = enabledTools[t.key];
        const detail = details.find(d => d.tool === t.label);
        let icon: string;
        let reason: string;
        if (!isEnabled) {
          icon = dim(' SKIP ');
          reason = 'not requested';
        } else if (detail?.active) {
          icon = green('ACTIVE');
          reason = detail.reason;
        } else {
          icon = yellow(' OFF  ');
          reason = detail?.reason ?? 'not detected';
        }
        const suffix = '';
        process.stdout.write(`    ${icon}  ${t.label.padEnd(14)} ${dim(reason)}${suffix}\n`);
      }
      process.stdout.write('\n');
    }

    // 4. Apply trust hints
    (aim as any).setTrustHints(hints);

    // 5. Calculate trust score BEFORE sync
    const trustBefore = aim.calculateTrust();

    // 6. Import events from enabled tools
    const bridgeResults = importAllToolEvents(aim, targetDir, enabledTools);

    // 7. Calculate trust score AFTER sync
    const trustAfter = aim.calculateTrust();

    // 8. Write manifest
    manifest.bridging.lastSyncAt = new Date().toISOString();
    writeManifest(targetDir, manifest);

    // 9. Log the attach event
    aim.logEvent({
      action: 'identity.attach',
      target: targetDir,
      result: 'allowed',
      plugin: 'opena2a-cli',
    });

    if (isJson) {
      process.stdout.write(JSON.stringify({
        agentId: id.agentId,
        name: id.agentName,
        tools: enabledTools,
        hints,
        bridgeResults: bridgeResults.total,
        trustBefore: { score: trustBefore.score, grade: trustBefore.grade },
        trustAfter: { score: trustAfter.score, grade: trustAfter.grade },
        manifestPath: path.join(targetDir, '.opena2a', 'agent.yaml'),
      }, null, 2) + '\n');
      return 0;
    }

    // 10. Display results
    if (bridgeResults.total.imported > 0) {
      process.stdout.write(bold('  Event Sync:') + '\n');
      const tools = ['shield', 'arp', 'hma', 'configguard', 'secretless'] as const;
      for (const t of tools) {
        const r = bridgeResults[t];
        if (r.imported > 0 || r.skipped > 0) {
          process.stdout.write(`    ${t.padEnd(14)} ${green(`+${r.imported}`)} imported${r.skipped > 0 ? dim(`, ${r.skipped} skipped`) : ''}\n`);
        }
      }
      process.stdout.write('\n');
    }

    process.stdout.write(bold('  Trust Score:') + '\n');
    const beforeColor = trustBefore.score >= 60 ? yellow : red;
    const afterColor = trustAfter.score >= 80 ? green : trustAfter.score >= 60 ? yellow : red;
    const delta = trustAfter.score - trustBefore.score;
    const deltaLabel = delta > 0 ? green(`+${delta}`) : delta < 0 ? red(`${delta}`) : dim('+0');

    process.stdout.write(`    ${beforeColor(String(trustBefore.score))} -> ${afterColor(bold(String(trustAfter.score)))} (${deltaLabel})\n`);
    process.stdout.write(`    Grade: ${afterColor(trustAfter.grade)}\n\n`);

    // Active hints
    const activeHintCount = Object.values(hints).filter(Boolean).length;
    const totalHintCount = Object.keys(hints).length;
    process.stdout.write(`  Trust factors active: ${green(String(activeHintCount))}/${totalHintCount}\n`);

    process.stdout.write(gray('-'.repeat(60)) + '\n');
    process.stdout.write(dim(`  Manifest: ${path.join(targetDir, '.opena2a', 'agent.yaml')}`) + '\n');

    // Suggestions for inactive tools
    const inactiveTools = details.filter(d => !d.active);
    if (inactiveTools.length > 0) {
      process.stdout.write('\n' + dim('  To improve your trust score:') + '\n');
      for (const t of inactiveTools) {
        const suggestion = getToolSuggestion(t.tool);
        if (suggestion) {
          process.stdout.write(dim(`    ${t.tool}: ${suggestion}`) + '\n');
        }
      }
    }

    return 0;
  } catch (err) {
    process.stderr.write(`Failed to attach: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

function getToolSuggestion(tool: string): string | null {
  switch (tool) {
    case 'Secretless': return 'npx secretless-ai init';
    case 'ConfigGuard': return 'opena2a guard sign';
    case 'ARP': return 'opena2a runtime --init';
    case 'HMA': return 'npx hackmyagent secure';
    case 'Shield': return 'opena2a shield init';
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// detach -- remove cross-tool wiring
// ---------------------------------------------------------------------------

async function handleDetach(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';
  const targetDir = path.resolve(options.dir ?? process.cwd());

  try {
    const { readManifest, removeManifest } = await import('../identity/manifest.js');

    const manifest = readManifest(targetDir);
    if (!manifest) {
      if (isJson) {
        process.stdout.write(JSON.stringify({ detached: false, reason: 'no manifest found' }, null, 2) + '\n');
      } else {
        process.stderr.write('No identity attachment found in this directory.\n');
        process.stderr.write(dim('Run: opena2a identity attach') + '\n');
      }
      return 1;
    }

    // Log detach event before removing
    const aim = new mod.AIMCore({ agentName: manifest.agent.name });
    aim.logEvent({
      action: 'identity.detach',
      target: targetDir,
      result: 'allowed',
      plugin: 'opena2a-cli',
    });

    // Clear trust hints
    (aim as any).setTrustHints({});

    // Remove manifest
    removeManifest(targetDir);

    if (isJson) {
      process.stdout.write(JSON.stringify({ detached: true, agentId: manifest.agent.agentId }, null, 2) + '\n');
    } else {
      process.stdout.write(green('Identity detached') + '\n');
      process.stdout.write(`  Agent:     ${manifest.agent.agentId}\n`);
      process.stdout.write(`  Directory: ${dim(targetDir)}\n`);
      process.stdout.write(dim('\n  Identity, audit log, and tool configs are preserved.') + '\n');
      process.stdout.write(dim('  Only the cross-tool wiring was removed.') + '\n');
    }
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to detach: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// sync -- re-sync events from enabled tools
// ---------------------------------------------------------------------------

async function handleSync(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';
  const targetDir = path.resolve(options.dir ?? process.cwd());

  try {
    const { readManifest, writeManifest } = await import('../identity/manifest.js');
    const { applyTrustHints } = await import('../identity/trust-collector.js');
    const { importAllToolEvents } = await import('../identity/bridges.js');

    const manifest = readManifest(targetDir);
    if (!manifest) {
      if (isJson) {
        process.stdout.write(JSON.stringify({ synced: false, reason: 'no manifest found' }, null, 2) + '\n');
      } else {
        process.stderr.write('No identity attachment found. Run: opena2a identity attach\n');
      }
      return 1;
    }

    const aim = new mod.AIMCore({ agentName: manifest.agent.name });

    // Refresh trust hints
    const { hints, score } = applyTrustHints(aim, targetDir, manifest);

    // Import new events
    const bridgeResults = importAllToolEvents(aim, targetDir, manifest.tools);

    // Update manifest sync timestamp
    manifest.bridging.lastSyncAt = new Date().toISOString();
    writeManifest(targetDir, manifest);

    if (isJson) {
      process.stdout.write(JSON.stringify({
        synced: true,
        imported: bridgeResults.total.imported,
        skipped: bridgeResults.total.skipped,
        trustScore: score.score,
        trustGrade: score.grade,
      }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green('Sync complete') + '\n');
    process.stdout.write(`  Events imported: ${bridgeResults.total.imported}\n`);
    if (bridgeResults.total.skipped > 0) {
      process.stdout.write(`  Skipped (dedup): ${bridgeResults.total.skipped}\n`);
    }

    const scoreColor = score.score >= 80 ? green : score.score >= 60 ? yellow : red;
    process.stdout.write(`  Trust score:     ${scoreColor(bold(`${score.score}/100`))} (${scoreColor(score.grade)})\n`);

    const activeHints = Object.entries(hints).filter(([, v]) => v).map(([k]) => k);
    if (activeHints.length > 0) {
      process.stdout.write(`  Active factors:  ${activeHints.join(', ')}\n`);
    }
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to sync: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scoreToGrade(score: number): string {
  if (score >= 80) return 'strong';
  if (score >= 60) return 'good';
  if (score >= 40) return 'moderate';
  if (score >= 20) return 'improving';
  return 'needs-attention';
}

function progressBar(pct: number, width: number): string {
  const filled = Math.round((pct / 100) * width);
  const empty = width - filled;
  return green('#'.repeat(filled)) + dim('.'.repeat(empty));
}

/**
 * Parse a simple YAML capability policy file.
 *
 * Supports the format:
 *   version: "1"
 *   defaultAction: deny
 *   rules:
 *     - capability: "db:read"
 *       action: allow
 *     - capability: "net:*"
 *       action: deny
 *       plugins:
 *         - untrusted-plugin
 */
function parseSimpleYamlPolicy(content: string): Policy {
  const lines = content.split('\n');
  let version = '1';
  let defaultAction: 'allow' | 'deny' = 'deny';
  const rules: Array<{ capability: string; action: 'allow' | 'deny'; plugins?: string[] }> = [];

  let inRules = false;
  let currentRule: { capability?: string; action?: string; plugins?: string[] } | null = null;
  let inPlugins = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    // Top-level keys
    if (!line.startsWith(' ') && !line.startsWith('\t')) {
      inRules = false;
      inPlugins = false;
      if (currentRule?.capability && currentRule?.action) {
        rules.push(currentRule as { capability: string; action: 'allow' | 'deny'; plugins?: string[] });
        currentRule = null;
      }
    }

    const kvMatch = trimmed.match(/^(\w+):\s*(.*)$/);

    if (kvMatch && !inRules) {
      const [, key, val] = kvMatch;
      const cleanVal = val.replace(/^["']|["']$/g, '');
      if (key === 'version') version = cleanVal;
      if (key === 'defaultAction') defaultAction = cleanVal as 'allow' | 'deny';
      if (key === 'rules') inRules = true;
      continue;
    }

    if (inRules) {
      // New rule entry (starts with "- ")
      if (trimmed.startsWith('- ')) {
        if (currentRule?.capability && currentRule?.action) {
          rules.push(currentRule as { capability: string; action: 'allow' | 'deny'; plugins?: string[] });
        }
        currentRule = {};
        inPlugins = false;
        const inlineKv = trimmed.slice(2).match(/^(\w+):\s*(.*)$/);
        if (inlineKv) {
          const cleanVal = inlineKv[2].replace(/^["']|["']$/g, '');
          if (inlineKv[1] === 'capability') currentRule.capability = cleanVal;
          if (inlineKv[1] === 'action' || inlineKv[1] === 'effect') currentRule.action = cleanVal;
        }
        continue;
      }

      // Rule properties
      if (currentRule && kvMatch) {
        const [, key, val] = kvMatch;
        const cleanVal = val.replace(/^["']|["']$/g, '');
        if (key === 'capability') currentRule.capability = cleanVal;
        if (key === 'action' || key === 'effect') currentRule.action = cleanVal;
        if (key === 'plugins') {
          inPlugins = true;
          currentRule.plugins = [];
        }
        continue;
      }

      // Plugin list items
      if (inPlugins && currentRule && trimmed.startsWith('- ')) {
        const pluginName = trimmed.slice(2).replace(/^["']|["']$/g, '');
        if (!currentRule.plugins) currentRule.plugins = [];
        currentRule.plugins.push(pluginName);
      }
    }
  }

  // Flush last rule
  if (currentRule?.capability && currentRule?.action) {
    rules.push(currentRule as { capability: string; action: 'allow' | 'deny'; plugins?: string[] });
  }

  return { version, defaultAction, rules };
}

// ---------------------------------------------------------------------------
// tag
// ---------------------------------------------------------------------------

async function handleTag(options: IdentityOptions): Promise<number> {
  const isJson = options.format === 'json';
  const args = options.args ?? [];
  const sub = args[0];

  if (!sub || !['list', 'add', 'remove'].includes(sub)) {
    process.stderr.write('Usage: opena2a identity tag <list|add|remove> [name]\n');
    process.stderr.write('\n');
    process.stderr.write('  list               List all tags in organization\n');
    process.stderr.write('  add <name>         Create a tag and add to current agent\n');
    process.stderr.write('  remove <name>      Remove a tag from current agent\n');
    return 1;
  }

  const client = getServerClient(options);
  if (!client) {
    process.stderr.write('No server configured. Run: opena2a login\n');
    return 1;
  }

  const auth = getStoredAuth();
  if (!auth.token) {
    process.stderr.write('Not authenticated. Run: opena2a login\n');
    return 1;
  }

  const agentId = auth.agentId ?? loadServerConfig()?.agentId;

  // Temporarily create an authenticated client
  const serverUrl = auth.serverUrl ?? loadServerConfig()?.serverUrl ?? '';
  const authedClient = new AimClient(serverUrl, { accessToken: auth.token });

  if (sub === 'list') {
    try {
      const resp = await authedClient.listTags();
      const tags = resp.tags ?? [];
      if (isJson) {
        process.stdout.write(JSON.stringify({ tags }, null, 2) + '\n');
        return 0;
      }
      process.stdout.write(bold('Organization Tags') + '\n');
      process.stdout.write(gray('-'.repeat(50)) + '\n');
      if (tags.length === 0) {
        process.stdout.write(dim('  No tags found.') + '\n');
      } else {
        for (const tag of tags) {
          const color = tag.color ? dim(` (${tag.color})`) : '';
          process.stdout.write(`  ${cyan(tag.name)}${color}  ${dim(tag.id)}\n`);
        }
      }
      process.stdout.write(gray('-'.repeat(50)) + '\n');
      process.stdout.write(dim(`  ${tags.length} tag(s)`) + '\n');
      return 0;
    } catch (err) {
      process.stderr.write(`Failed to list tags: ${formatServerError(err)}\n`);
      return 1;
    }
  }

  const tagName = args[1];
  if (!tagName) {
    process.stderr.write(`Usage: opena2a identity tag ${sub} <name>\n`);
    return 1;
  }

  if (sub === 'add') {
    if (!agentId) {
      process.stderr.write('No agent ID found. Register an agent first: opena2a identity create --name <n> --server cloud\n');
      return 1;
    }
    try {
      // List existing tags to check if one with this name already exists
      const existing = await authedClient.listTags();
      let tag = (existing.tags ?? []).find((t: any) => t.name === tagName);
      if (!tag) {
        tag = await authedClient.createTag(tagName);
      }
      await authedClient.addTagsToAgent(agentId, [tag.id]);
      if (isJson) {
        process.stdout.write(JSON.stringify({ action: 'added', tag, agentId }, null, 2) + '\n');
        return 0;
      }
      process.stdout.write(green(`Tag "${tagName}" added to agent ${agentId}.`) + '\n');
      return 0;
    } catch (err) {
      process.stderr.write(`Failed to add tag: ${formatServerError(err)}\n`);
      return 1;
    }
  }

  if (sub === 'remove') {
    if (!agentId) {
      process.stderr.write('No agent ID found. Register an agent first: opena2a identity create --name <n> --server cloud\n');
      return 1;
    }
    try {
      // Find tag by name from agent's current tags
      const agentTags = await authedClient.getAgentTags(agentId);
      const tag = (agentTags.tags ?? []).find((t: any) => t.name === tagName);
      if (!tag) {
        process.stderr.write(`Tag "${tagName}" not found on this agent.\n`);
        return 1;
      }
      await authedClient.removeTagFromAgent(agentId, tag.id);
      if (isJson) {
        process.stdout.write(JSON.stringify({ action: 'removed', tagName, tagId: tag.id, agentId }, null, 2) + '\n');
        return 0;
      }
      process.stdout.write(green(`Tag "${tagName}" removed from agent ${agentId}.`) + '\n');
      return 0;
    } catch (err) {
      process.stderr.write(`Failed to remove tag: ${formatServerError(err)}\n`);
      return 1;
    }
  }

  return 0;
}

// ---------------------------------------------------------------------------
// mcp
// ---------------------------------------------------------------------------

async function handleMcp(options: IdentityOptions): Promise<number> {
  const isJson = options.format === 'json';
  const args = options.args ?? [];
  const sub = args[0];

  if (!sub || !['list', 'add', 'remove'].includes(sub)) {
    process.stderr.write('Usage: opena2a identity mcp <list|add|remove> [id]\n');
    process.stderr.write('\n');
    process.stderr.write('  list               List agent MCP server connections\n');
    process.stderr.write('  add <id>           Add an MCP server to agent\n');
    process.stderr.write('  remove <id>        Remove an MCP server from agent\n');
    return 1;
  }

  const client = getServerClient(options);
  if (!client) {
    process.stderr.write('No server configured. Run: opena2a login\n');
    return 1;
  }

  const auth = getStoredAuth();
  if (!auth.token) {
    process.stderr.write('Not authenticated. Run: opena2a login\n');
    return 1;
  }

  const agentId = auth.agentId ?? loadServerConfig()?.agentId;
  if (!agentId) {
    process.stderr.write('No agent ID found. Register an agent first: opena2a identity create --name <n> --server cloud\n');
    return 1;
  }

  const serverUrl = auth.serverUrl ?? loadServerConfig()?.serverUrl ?? '';
  const authedClient = new AimClient(serverUrl, { accessToken: auth.token });

  if (sub === 'list') {
    try {
      const resp = await authedClient.getAgentMCPs(agentId);
      const mcps = resp.mcpServers ?? [];
      if (isJson) {
        process.stdout.write(JSON.stringify({ agentId, mcpServers: mcps }, null, 2) + '\n');
        return 0;
      }
      process.stdout.write(bold('Agent MCP Servers') + '\n');
      process.stdout.write(gray('-'.repeat(50)) + '\n');
      if (mcps.length === 0) {
        process.stdout.write(dim('  No MCP servers connected.') + '\n');
      } else {
        for (const mcp of mcps) {
          const name = mcp.name ? `  ${cyan(mcp.name)}` : '';
          process.stdout.write(`  ${dim(mcp.id)}${name}\n`);
        }
      }
      process.stdout.write(gray('-'.repeat(50)) + '\n');
      process.stdout.write(dim(`  ${mcps.length} MCP server(s)`) + '\n');
      return 0;
    } catch (err) {
      process.stderr.write(`Failed to list MCP servers: ${formatServerError(err)}\n`);
      return 1;
    }
  }

  const mcpId = args[1];
  if (!mcpId) {
    process.stderr.write(`Usage: opena2a identity mcp ${sub} <id>\n`);
    return 1;
  }

  if (sub === 'add') {
    try {
      await authedClient.addMCPsToAgent(agentId, [mcpId]);
      if (isJson) {
        process.stdout.write(JSON.stringify({ action: 'added', mcpServerId: mcpId, agentId }, null, 2) + '\n');
        return 0;
      }
      process.stdout.write(green(`MCP server "${mcpId}" added to agent ${agentId}.`) + '\n');
      return 0;
    } catch (err) {
      process.stderr.write(`Failed to add MCP server: ${formatServerError(err)}\n`);
      return 1;
    }
  }

  if (sub === 'remove') {
    try {
      await authedClient.removeMCPFromAgent(agentId, mcpId);
      if (isJson) {
        process.stdout.write(JSON.stringify({ action: 'removed', mcpServerId: mcpId, agentId }, null, 2) + '\n');
        return 0;
      }
      process.stdout.write(green(`MCP server "${mcpId}" removed from agent ${agentId}.`) + '\n');
      return 0;
    } catch (err) {
      process.stderr.write(`Failed to remove MCP server: ${formatServerError(err)}\n`);
      return 1;
    }
  }

  return 0;
}

// ---------------------------------------------------------------------------
// activity
// ---------------------------------------------------------------------------

async function handleActivity(options: IdentityOptions): Promise<number> {
  const isJson = options.format === 'json';
  const limit = options.limit ?? 10;

  const client = getServerClient(options);
  if (!client) {
    process.stderr.write('No server configured. Run: opena2a login\n');
    return 1;
  }

  const auth = getStoredAuth();
  if (!auth.token) {
    process.stderr.write('Not authenticated. Run: opena2a login\n');
    return 1;
  }

  const agentId = auth.agentId ?? loadServerConfig()?.agentId;
  if (!agentId) {
    process.stderr.write('No agent ID found. Register an agent first: opena2a identity create --name <n> --server cloud\n');
    return 1;
  }

  const serverUrl = auth.serverUrl ?? loadServerConfig()?.serverUrl ?? '';
  const authedClient = new AimClient(serverUrl, { accessToken: auth.token });

  try {
    const resp = await authedClient.getAgentActivity(agentId, { pageSize: limit });
    const events = resp.events ?? resp.activity ?? [];
    const total = resp.total ?? events.length;

    if (isJson) {
      process.stdout.write(JSON.stringify({ agentId, total, events }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold(`Agent Activity (${events.length} of ${total})`) + '\n');
    process.stdout.write(dim(`  Agent: ${agentId}`) + '\n');
    process.stdout.write(gray('-'.repeat(70)) + '\n');

    if (events.length === 0) {
      process.stdout.write(dim('  No activity events recorded.') + '\n');
    } else {
      for (const e of events) {
        const ts = (e.createdAt ?? e.timestamp ?? '').slice(0, 19).replace('T', ' ');
        const action = (e.action ?? e.type ?? '').padEnd(20);
        const detail = e.details ?? e.description ?? '';
        process.stdout.write(`  ${dim(ts)}  ${action} ${dim(detail)}\n`);
      }
    }
    process.stdout.write(gray('-'.repeat(70)) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to fetch activity: ${formatServerError(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// suspend -- suspend agent on server
// ---------------------------------------------------------------------------

async function handleSuspend(options: IdentityOptions): Promise<number> {
  const isJson = options.format === 'json';

  const auth = getStoredAuth();
  if (!auth.token) {
    process.stderr.write('Not authenticated. Run: opena2a login\n');
    return 1;
  }

  const agentId = auth.agentId ?? loadServerConfig()?.agentId;
  if (!agentId) {
    process.stderr.write('No agent connected to server. Run: opena2a identity create --name <name> --server cloud\n');
    return 1;
  }

  const serverUrl = auth.serverUrl ?? loadServerConfig()?.serverUrl ?? '';
  const authedClient = new AimClient(serverUrl, { accessToken: auth.token });

  try {
    const resp = await authedClient.suspendAgent(agentId);

    if (isJson) {
      process.stdout.write(JSON.stringify({ action: 'suspended', agentId, ...resp }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green(`Agent ${agentId} suspended.`) + '\n');
    process.stdout.write(dim('  All operations for this agent are now paused.') + '\n');
    process.stdout.write(dim('  To reactivate: opena2a identity reactivate --server cloud') + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to suspend agent: ${formatServerError(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// reactivate -- reactivate a suspended agent on server
// ---------------------------------------------------------------------------

async function handleReactivate(options: IdentityOptions): Promise<number> {
  const isJson = options.format === 'json';

  const auth = getStoredAuth();
  if (!auth.token) {
    process.stderr.write('Not authenticated. Run: opena2a login\n');
    return 1;
  }

  const agentId = auth.agentId ?? loadServerConfig()?.agentId;
  if (!agentId) {
    process.stderr.write('No agent connected to server. Run: opena2a identity create --name <name> --server cloud\n');
    return 1;
  }

  const serverUrl = auth.serverUrl ?? loadServerConfig()?.serverUrl ?? '';
  const authedClient = new AimClient(serverUrl, { accessToken: auth.token });

  try {
    const resp = await authedClient.reactivateAgent(agentId);

    if (isJson) {
      process.stdout.write(JSON.stringify({ action: 'reactivated', agentId, ...resp }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green(`Agent ${agentId} reactivated.`) + '\n');
    process.stdout.write(dim('  Agent operations have been resumed.') + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to reactivate agent: ${formatServerError(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// revoke -- permanently delete agent from server (irreversible)
// ---------------------------------------------------------------------------

async function handleRevoke(options: IdentityOptions): Promise<number> {
  const isJson = options.format === 'json';

  const auth = getStoredAuth();
  if (!auth.token) {
    process.stderr.write('Not authenticated. Run: opena2a login\n');
    return 1;
  }

  const agentId = auth.agentId ?? loadServerConfig()?.agentId;
  if (!agentId) {
    process.stderr.write('No agent connected to server. Run: opena2a identity create --name <name> --server cloud\n');
    return 1;
  }

  // Require --ci or explicit confirmation via --name matching
  if (!options.ci && !isJson) {
    process.stderr.write(red('WARNING: This will revoke the agent on the server.') + '\n');
    process.stderr.write('Data is retained for 30 days. You can reactivate within that window.\n');
    process.stderr.write('After 30 days, all data will be permanently deleted.\n');
    process.stderr.write('\n');
    process.stderr.write(`To confirm, run: opena2a identity revoke --server cloud --ci\n`);
    process.stderr.write(`To temporarily disable instead: opena2a identity suspend --server cloud\n`);
    return 1;
  }

  const serverUrl = auth.serverUrl ?? loadServerConfig()?.serverUrl ?? '';
  const authedClient = new AimClient(serverUrl, { accessToken: auth.token });

  try {
    await authedClient.revokeAgent(agentId);

    if (isJson) {
      process.stdout.write(JSON.stringify({ action: 'revoked', agentId, retentionDays: 30 }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(red(`Agent ${agentId} revoked.`) + '\n');
    process.stdout.write('  Data retained for 30 days.\n');
    process.stdout.write('  To restore within 30 days: opena2a identity reactivate --server cloud\n');
    process.stdout.write(dim('  After 30 days, all data will be permanently deleted.') + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to revoke agent: ${formatServerError(err)}\n`);
    return 1;
  }
}
