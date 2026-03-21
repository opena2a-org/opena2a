import * as fs from 'node:fs';
import * as path from 'node:path';
import { bold, dim, green, yellow, red, cyan, gray } from '../util/colors.js';
import { AimClient, loadServerConfig, saveServerConfig } from '../util/aim-client.js';
import { loadAuth, isAuthValid } from '../util/auth.js';
import { scanMcpServers } from './detect.js';

export interface SetupOptions {
  targetDir: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
  json?: boolean;
  name?: string;  // Override auto-detected name
}

/**
 * Auto-detect a project name from package.json, pyproject.toml, or directory basename.
 */
function detectProjectName(dir: string): string {
  // Try package.json
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      if (pkg.name && typeof pkg.name === 'string') {
        // Strip npm scope prefix (@org/name -> name)
        return pkg.name.replace(/^@[^/]+\//, '');
      }
    } catch { /* ignore parse errors */ }
  }

  // Try pyproject.toml
  const pyprojectPath = path.join(dir, 'pyproject.toml');
  if (fs.existsSync(pyprojectPath)) {
    try {
      const content = fs.readFileSync(pyprojectPath, 'utf-8');
      const match = content.match(/\[project\]\s*\n(?:.*\n)*?name\s*=\s*"([^"]+)"/);
      if (match) return match[1];
    } catch { /* ignore */ }
  }

  // Fallback to directory basename
  return path.basename(path.resolve(dir));
}

/**
 * Return a human-readable description of where the project name came from.
 */
function detectProjectNameSource(dir: string): string {
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      if (pkg.name) return 'package.json';
    } catch { /* ignore */ }
  }
  const pyprojectPath = path.join(dir, 'pyproject.toml');
  if (fs.existsSync(pyprojectPath)) {
    try {
      const content = fs.readFileSync(pyprojectPath, 'utf-8');
      if (content.match(/\[project\]\s*\n(?:.*\n)*?name\s*=/)) return 'pyproject.toml';
    } catch { /* ignore */ }
  }
  return 'directory name';
}

export async function setup(options: SetupOptions): Promise<number> {
  const isJson = options.json || options.format === 'json';
  const dir = options.targetDir;

  // Step 1: Check authentication
  const auth = loadAuth();
  if (!auth || !isAuthValid(auth)) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'not_authenticated', message: 'Run: opena2a login' }, null, 2) + '\n');
    } else {
      process.stderr.write(red('Not authenticated.') + '\n');
      process.stderr.write('Run: ' + cyan('opena2a login') + '\n');
    }
    return 1;
  }

  if (!isJson) {
    process.stdout.write(green('  Authenticating...') + ' done\n');
  }

  // Step 2: Auto-detect project name
  const name = options.name ?? detectProjectName(dir);

  if (!isJson) {
    process.stdout.write(green('  Detecting project...') + ` ${name}` + dim(options.name ? ' (specified)' : ` (from ${detectProjectNameSource(dir)})`) + '\n');
  }

  // Step 3: Create identity on server
  const client = new AimClient(auth.serverUrl, { accessToken: auth.accessToken });

  let agentId = '';
  let trustScore = 0;
  try {
    const resp: any = await client.createAgent({ name, displayName: name });
    // Normalize response — server returns `id`, typed interface says `agentId`
    agentId = resp.agentId ?? resp.id ?? resp.agent?.id ?? '';
    trustScore = resp.trustScore ?? resp.agent?.trustScore ?? 0;

    if (!agentId) {
      if (isJson) {
        process.stdout.write(JSON.stringify({ error: 'create_failed', message: 'Server returned no agent ID' }, null, 2) + '\n');
      } else {
        process.stderr.write(red('  Failed to create identity: server returned no agent ID') + '\n');
      }
      return 1;
    }

    // Save server config locally
    saveServerConfig({
      serverUrl: auth.serverUrl,
      agentId,
      accessToken: auth.accessToken,
      refreshToken: auth.refreshToken ?? undefined,
      registeredAt: new Date().toISOString(),
    });

    if (!isJson) {
      process.stdout.write(green('  Creating identity...') + ` done (Agent ID: ${cyan(agentId.slice(0, 8))})\n`);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    // Check if it's a "already exists" error - try to load existing
    if (msg.includes('already exists') || msg.includes('duplicate') || msg.includes('conflict')) {
      // Agent already registered — resolve its ID from the server
      let found = false;
      try {
        const listResp = await client.listAgents(auth.accessToken);
        const match = (listResp.agents ?? []).find((a: any) => a.name === name);
        if (match) {
          agentId = match.id;
          trustScore = match.trustScore ?? 0;
          found = true;
          saveServerConfig({
            serverUrl: auth.serverUrl,
            agentId,
            accessToken: auth.accessToken,
            refreshToken: auth.refreshToken ?? undefined,
            registeredAt: new Date().toISOString(),
          });
        }
      } catch { /* server lookup failed */ }

      // Fallback: local config
      if (!found) {
        const config = loadServerConfig();
        if (config?.agentId) {
          agentId = config.agentId;
          trustScore = 0;
          found = true;
        }
      }

      if (found) {
        if (!isJson) {
          process.stdout.write(yellow('  Identity exists...') + ` using ${cyan(agentId.slice(0, 8))}\n`);
        }
      } else {
        if (isJson) {
          process.stdout.write(JSON.stringify({ error: 'create_failed', message: 'Agent exists but could not resolve ID' }, null, 2) + '\n');
        } else {
          process.stderr.write(red('  Agent exists but could not resolve ID from server.') + '\n');
          process.stderr.write(dim('  Try: opena2a identity list --server cloud') + '\n');
        }
        return 1;
      }
    } else {
      if (isJson) {
        process.stdout.write(JSON.stringify({ error: 'create_failed', message: msg }, null, 2) + '\n');
      } else {
        process.stderr.write(red(`  Failed to create identity: ${msg}`) + '\n');
      }
      return 1;
    }
  }

  // Step 4: Discover and attach MCP servers
  let mcpCount = 0;
  let mcpAttached = 0;
  try {
    const mcpServers = scanMcpServers(dir);
    mcpCount = mcpServers.length;

    if (mcpCount > 0) {
      // Get already-attached MCPs to deduplicate
      let existingIds: Set<string> = new Set();
      try {
        const existing = await client.getAgentMCPs(agentId);
        existingIds = new Set((existing.mcpServers ?? []).map((m: any) => m.name ?? m.id));
      } catch { /* ignore - may not have any yet */ }

      const newMcpIds = mcpServers
        .map(s => s.name)
        .filter(n => !existingIds.has(n));

      if (newMcpIds.length > 0) {
        await client.addMCPsToAgent(agentId, newMcpIds);
        mcpAttached = newMcpIds.length;
      }
    }

    if (!isJson) {
      process.stdout.write(green('  Discovering MCP servers...') + ` ${mcpCount} found, ${mcpAttached} attached\n`);
    }
  } catch {
    if (!isJson) {
      process.stdout.write(yellow('  Discovering MCP servers...') + ' skipped (discovery error)\n');
    }
  }

  // Step 5: Fetch trust score (refresh after MCP attachment)
  try {
    const agentData = await client.getAgent(auth.accessToken, agentId);
    trustScore = agentData?.trustScore ?? trustScore;
  } catch { /* use initial trust score */ }

  // Output results
  const dashboardUrl = `${auth.serverUrl.replace(/\/+$/, '')}/dashboard`;

  if (isJson) {
    process.stdout.write(JSON.stringify({
      agentId,
      name,
      trustScore,
      mcpServersDiscovered: mcpCount,
      mcpServersAttached: mcpAttached,
      dashboard: dashboardUrl,
    }, null, 2) + '\n');
  } else {
    // Server returns 0-1 scale; display as percentage
    const displayScore = trustScore <= 1 ? Math.round(trustScore * 100) : Math.round(trustScore);
    process.stdout.write(green('  Trust score:') + ` ${displayScore}/100\n`);
    process.stdout.write(green('  Dashboard:') + ` ${cyan(dashboardUrl)}\n`);
    process.stdout.write('\n' + dim('  Agent is registered and monitored.') + '\n');
  }

  return 0;
}
