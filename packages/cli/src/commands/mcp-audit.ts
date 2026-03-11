import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { bold, dim, green, yellow, red, cyan, gray } from '../util/colors.js';

interface McpCommandOptions {
  subcommand: string;
  server?: string;
  targetDir: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
}

interface McpServerEntry {
  name: string;
  transport: 'stdio' | 'sse';
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
  capabilities?: string[];
  pinnedVersion: boolean;
  sourceFile: string;
  sourceLabel: string;
}

interface McpIdentity {
  serverName: string;
  publicKey: string;
  privateKey: string;
  configHash: string;
  signature: string;
  createdAt: string;
}

/**
 * MCP server identity audit, sign, and verify.
 */
export async function mcpCommand(options: McpCommandOptions): Promise<number> {
  switch (options.subcommand) {
    case 'audit':
      return handleAudit(options);
    case 'sign':
      return handleSign(options);
    case 'verify':
      return handleVerify(options);
    default:
      process.stderr.write(`Unknown mcp subcommand: ${options.subcommand}\n`);
      process.stderr.write('\nUsage: opena2a mcp <audit|sign|verify>\n\n');
      process.stderr.write('  audit               Audit MCP server configurations\n');
      process.stderr.write('  sign <server>       Sign an MCP server with AIM identity\n');
      process.stderr.write('  verify <server>     Verify server signature and trust score\n');
      return 1;
  }
}

// ── Config discovery ──────────────────────────────────────────────────

interface ConfigSource {
  filePath: string;
  label: string;
}

function getConfigSources(targetDir: string): ConfigSource[] {
  const home = os.homedir();
  return [
    { filePath: path.join(home, '.claude', 'mcp_servers.json'), label: 'Claude Code' },
    { filePath: path.join(home, '.cursor', 'mcp.json'), label: 'Cursor' },
    { filePath: path.join(home, '.config', 'windsurf', 'mcp.json'), label: 'Windsurf' },
    { filePath: path.join(targetDir, 'mcp.json'), label: 'project-local' },
    { filePath: path.join(targetDir, '.mcp.json'), label: 'project-local' },
  ];
}

function parseConfigFile(filePath: string, label: string): McpServerEntry[] {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    const servers: Record<string, any> = parsed.mcpServers ?? parsed;
    if (typeof servers !== 'object' || servers === null) return [];

    const entries: McpServerEntry[] = [];
    for (const [name, config] of Object.entries(servers)) {
      if (typeof config !== 'object' || config === null) continue;

      const hasUrl = typeof config.url === 'string';
      const hasCommand = typeof config.command === 'string';
      if (!hasUrl && !hasCommand) continue;

      const transport: 'stdio' | 'sse' = hasUrl ? 'sse' : 'stdio';
      const args = Array.isArray(config.args) ? config.args.map(String) : undefined;
      const capabilities = extractCapabilities(config);
      const pinnedVersion = detectPinnedVersion(config.command, args);

      entries.push({
        name,
        transport,
        command: config.command,
        args,
        url: config.url,
        env: config.env,
        capabilities,
        pinnedVersion,
        sourceFile: filePath,
        sourceLabel: label,
      });
    }
    return entries;
  } catch {
    return [];
  }
}

function extractCapabilities(config: any): string[] {
  const caps: string[] = [];
  if (config.tools) caps.push('tools');
  if (config.resources) caps.push('resources');
  if (config.prompts) caps.push('prompts');
  return caps;
}

function detectPinnedVersion(command?: string, args?: string[]): boolean {
  if (!args) return false;
  // Look for version specifiers like @1.2.3 in package names
  for (const arg of args) {
    if (arg.match(/@\d+\.\d+/)) return true;
  }
  return false;
}

function getIdentityDir(targetDir: string): string {
  return path.join(targetDir, '.opena2a', 'mcp-identities');
}

function getIdentityPath(targetDir: string, serverName: string): string {
  return path.join(getIdentityDir(targetDir), `${serverName}.json`);
}

function computeConfigHash(entry: McpServerEntry): string {
  const data = entry.transport === 'stdio'
    ? JSON.stringify({ command: entry.command, args: entry.args })
    : JSON.stringify({ url: entry.url });
  return crypto.createHash('sha256').update(data).digest('hex');
}

// ── Registry trust score ──────────────────────────────────────────────

async function fetchTrustScore(serverName: string): Promise<number | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(
      `https://registry.opena2a.org/api/v1/packages/${encodeURIComponent(serverName)}`,
      { signal: controller.signal },
    );
    clearTimeout(timeout);
    if (!resp.ok) return null;
    const data = await resp.json() as any;
    return typeof data.trustScore === 'number' ? data.trustScore : null;
  } catch {
    return null;
  }
}

// ── Subcommand: audit ─────────────────────────────────────────────────

async function handleAudit(options: McpCommandOptions): Promise<number> {
  const sources = getConfigSources(options.targetDir);
  const isJson = options.format === 'json';

  // Collect all servers grouped by source
  const grouped: { source: ConfigSource; servers: McpServerEntry[] }[] = [];
  for (const source of sources) {
    const servers = parseConfigFile(source.filePath, source.label);
    if (servers.length > 0) {
      grouped.push({ source, servers });
    }
  }

  const allServers = grouped.flatMap(g => g.servers);

  // Check identity status for each server
  const identityDir = getIdentityDir(options.targetDir);
  const identityStatus: Map<string, { signed: boolean; verified: boolean }> = new Map();
  for (const server of allServers) {
    const idPath = getIdentityPath(options.targetDir, server.name);
    const signed = fs.existsSync(idPath);
    let verified = false;
    if (signed) {
      try {
        const identity: McpIdentity = JSON.parse(fs.readFileSync(idPath, 'utf-8'));
        const currentHash = computeConfigHash(server);
        verified = identity.configHash === currentHash;
      } catch {
        verified = false;
      }
    }
    identityStatus.set(server.name, { signed, verified });
  }

  // Fetch trust scores (best-effort, parallel)
  const trustScores: Map<string, number | null> = new Map();
  if (!options.ci) {
    const promises = allServers.map(async (s) => {
      const score = await fetchTrustScore(s.name);
      trustScores.set(s.name, score);
    });
    await Promise.all(promises);
  }

  // Count summary
  const total = allServers.length;
  const signedCount = [...identityStatus.values()].filter(s => s.signed).length;
  const verifiedCount = [...identityStatus.values()].filter(s => s.verified).length;
  const trustCount = [...trustScores.values()].filter(s => s !== null).length;

  if (isJson) {
    const result = {
      servers: allServers.map(s => ({
        name: s.name,
        transport: s.transport,
        command: s.transport === 'stdio' ? [s.command, ...(s.args ?? [])].join(' ') : undefined,
        url: s.url,
        sourceFile: s.sourceFile,
        sourceLabel: s.sourceLabel,
        pinnedVersion: s.pinnedVersion,
        capabilities: s.capabilities,
        signed: identityStatus.get(s.name)?.signed ?? false,
        verified: identityStatus.get(s.name)?.verified ?? false,
        trustScore: trustScores.get(s.name) ?? null,
      })),
      summary: { total, signed: signedCount, verified: verifiedCount, trustScores: trustCount },
    };
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return 0;
  }

  // Text output
  if (total === 0) {
    process.stdout.write(bold('MCP Server Audit') + '\n');
    process.stdout.write(gray('='.repeat(50)) + '\n\n');
    process.stdout.write(dim('No MCP server configurations found.') + '\n');
    process.stdout.write(dim('Checked locations:') + '\n');
    for (const source of sources) {
      process.stdout.write(dim(`  ${source.filePath}`) + '\n');
    }
    return 0;
  }

  process.stdout.write(bold('MCP Server Audit') + '\n');
  process.stdout.write(gray('='.repeat(50)) + '\n\n');

  for (const group of grouped) {
    const shortPath = group.source.filePath.replace(os.homedir(), '~');
    process.stdout.write(bold(`Source: ${shortPath}`) + dim(` (${group.source.label})`) + '\n');

    for (const server of group.servers) {
      const status = identityStatus.get(server.name);
      const signLabel = status?.signed ? green('signed') : yellow('not signed');
      const trustScore = trustScores.get(server.name);
      const trustLabel = trustScore !== null && trustScore !== undefined
        ? cyan(`trust: ${trustScore}`)
        : dim('no trust score');

      const commandStr = server.transport === 'stdio'
        ? [server.command, ...(server.args ?? [])].filter(a => a !== '-y').join(' ')
        : server.url ?? '';

      const nameCol = server.name.padEnd(20);
      const transportCol = server.transport.padEnd(8);

      process.stdout.write(`  ${nameCol} ${dim(transportCol)} ${dim(commandStr.substring(0, 45).padEnd(45))}  ${signLabel}  ${trustLabel}\n`);

      if (options.verbose) {
        if (server.pinnedVersion) {
          process.stdout.write(dim(`                     version pinned`) + '\n');
        }
        if (server.capabilities && server.capabilities.length > 0) {
          process.stdout.write(dim(`                     capabilities: ${server.capabilities.join(', ')}`) + '\n');
        }
        if (server.env) {
          const envKeys = Object.keys(server.env);
          process.stdout.write(dim(`                     env vars: ${envKeys.join(', ')}`) + '\n');
        }
      }
    }
    process.stdout.write('\n');
  }

  process.stdout.write(bold('Summary') + '\n');
  process.stdout.write(`  Servers found:     ${total}\n`);
  process.stdout.write(`  Signed:            ${signedCount} / ${total}\n`);
  process.stdout.write(`  Verified:          ${verifiedCount} / ${total}\n`);
  process.stdout.write(`  Trust scores:      ${trustCount} / ${total}\n`);
  process.stdout.write('\n');

  process.stdout.write(bold('Next Steps') + '\n');
  process.stdout.write(`  ${cyan('opena2a mcp sign <name>')}       Sign an MCP server with AIM identity\n`);
  process.stdout.write(`  ${cyan('opena2a mcp verify <name>')}     Verify server signature and trust score\n`);

  return 0;
}

// ── Subcommand: sign ──────────────────────────────────────────────────

async function handleSign(options: McpCommandOptions): Promise<number> {
  const serverName = options.server;
  if (!serverName) {
    process.stderr.write('Missing required argument: <server-name>\n');
    process.stderr.write('Usage: opena2a mcp sign <server-name>\n');
    return 1;
  }

  // Find the server in configs
  const server = findServer(options.targetDir, serverName);
  if (!server) {
    process.stderr.write(`MCP server "${serverName}" not found in any configuration file.\n`);
    process.stderr.write('Run "opena2a mcp audit" to see available servers.\n');
    return 1;
  }

  // Load aim-core
  const aimCore = await loadAimCore();
  if (!aimCore) return 1;

  const isJson = options.format === 'json';

  try {
    // Generate Ed25519 keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pubKeyDer = publicKey.export({ type: 'spki', format: 'der' });
    const privKeyDer = privateKey.export({ type: 'pkcs8', format: 'der' });
    const pubKeyHex = pubKeyDer.toString('hex');
    const privKeyHex = privKeyDer.toString('hex');

    // Compute config hash
    const configHash = computeConfigHash(server);

    // Sign the config hash
    const signature = crypto.sign(null, Buffer.from(configHash), privateKey).toString('hex');

    // Compute fingerprint
    const fingerprint = crypto.createHash('sha256').update(pubKeyDer).digest('hex').substring(0, 16);

    // Store identity
    const identityDir = getIdentityDir(options.targetDir);
    fs.mkdirSync(identityDir, { recursive: true });

    const identity: McpIdentity = {
      serverName,
      publicKey: pubKeyHex,
      privateKey: privKeyHex,
      configHash,
      signature,
      createdAt: new Date().toISOString(),
    };

    const idPath = getIdentityPath(options.targetDir, serverName);
    fs.writeFileSync(idPath, JSON.stringify(identity, null, 2));

    if (isJson) {
      process.stdout.write(JSON.stringify({
        status: 'signed',
        serverName,
        fingerprint,
        configHash,
        identityFile: idPath,
      }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green('MCP server signed successfully') + '\n\n');
    process.stdout.write(`  Server:       ${bold(serverName)}\n`);
    process.stdout.write(`  Transport:    ${server.transport}\n`);
    process.stdout.write(`  Fingerprint:  ${cyan(fingerprint)}\n`);
    process.stdout.write(`  Config hash:  ${dim(configHash.substring(0, 32) + '...')}\n`);
    process.stdout.write(`  Stored in:    ${dim(idPath)}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to sign server: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ── Subcommand: verify ────────────────────────────────────────────────

async function handleVerify(options: McpCommandOptions): Promise<number> {
  const serverName = options.server;
  if (!serverName) {
    process.stderr.write('Missing required argument: <server-name>\n');
    process.stderr.write('Usage: opena2a mcp verify <server-name>\n');
    return 1;
  }

  const isJson = options.format === 'json';

  // Check identity file exists
  const idPath = getIdentityPath(options.targetDir, serverName);
  if (!fs.existsSync(idPath)) {
    if (isJson) {
      process.stdout.write(JSON.stringify({
        status: 'not_signed',
        serverName,
        message: 'No identity file found. Run "opena2a mcp sign" first.',
      }, null, 2) + '\n');
      return 1;
    }
    process.stderr.write(`No identity found for MCP server "${serverName}".\n`);
    process.stderr.write(`Run "opena2a mcp sign ${serverName}" to create one.\n`);
    return 1;
  }

  // Load identity
  let identity: McpIdentity;
  try {
    identity = JSON.parse(fs.readFileSync(idPath, 'utf-8'));
  } catch {
    process.stderr.write(`Failed to read identity file: ${idPath}\n`);
    return 1;
  }

  // Find server in configs
  const server = findServer(options.targetDir, serverName);

  // Verify signature
  let signatureValid = false;
  let configMatch = false;

  try {
    const pubKeyObj = crypto.createPublicKey({
      key: Buffer.from(identity.publicKey, 'hex'),
      type: 'spki',
      format: 'der',
    });

    signatureValid = crypto.verify(
      null,
      Buffer.from(identity.configHash),
      pubKeyObj,
      Buffer.from(identity.signature, 'hex'),
    );
  } catch {
    signatureValid = false;
  }

  if (server) {
    const currentHash = computeConfigHash(server);
    configMatch = currentHash === identity.configHash;
  }

  // Fetch trust score
  const trustScore = await fetchTrustScore(serverName);

  // Compute fingerprint
  let fingerprint = '';
  try {
    const pubKeyDer = Buffer.from(identity.publicKey, 'hex');
    fingerprint = crypto.createHash('sha256').update(pubKeyDer).digest('hex').substring(0, 16);
  } catch {
    fingerprint = 'unknown';
  }

  const passed = signatureValid && configMatch;

  if (isJson) {
    process.stdout.write(JSON.stringify({
      status: passed ? 'verified' : 'failed',
      serverName,
      signatureValid,
      configMatch,
      configFound: server !== null,
      fingerprint,
      trustScore,
      createdAt: identity.createdAt,
    }, null, 2) + '\n');
    return passed ? 0 : 1;
  }

  process.stdout.write(bold('MCP Server Verification') + '\n');
  process.stdout.write(gray('='.repeat(50)) + '\n\n');

  process.stdout.write(`  Server:          ${bold(serverName)}\n`);
  process.stdout.write(`  Fingerprint:     ${cyan(fingerprint)}\n`);
  process.stdout.write(`  Created:         ${dim(identity.createdAt)}\n\n`);

  process.stdout.write(`  Signature:       ${signatureValid ? green('valid') : red('invalid')}\n`);
  process.stdout.write(`  Config match:    ${configMatch ? green('current config matches signed config') : (server ? red('config has changed since signing') : yellow('server not found in current configs'))}\n`);

  if (trustScore !== null) {
    process.stdout.write(`  Trust score:     ${cyan(String(trustScore))}\n`);
  } else {
    process.stdout.write(`  Trust score:     ${dim('not available')}\n`);
  }

  process.stdout.write('\n');

  if (passed) {
    process.stdout.write(green('PASS') + ' -- server identity verified\n');
  } else {
    process.stdout.write(red('FAIL') + ' -- verification failed\n');
    if (!signatureValid) {
      process.stdout.write(dim('  The cryptographic signature could not be verified.') + '\n');
    }
    if (!configMatch && server) {
      process.stdout.write(dim('  The server configuration has changed since it was signed.') + '\n');
      process.stdout.write(dim('  Run "opena2a mcp sign ' + serverName + '" to re-sign.') + '\n');
    }
    if (!server) {
      process.stdout.write(dim('  The server was not found in any configuration file.') + '\n');
    }
  }

  return passed ? 0 : 1;
}

// ── Helpers ───────────────────────────────────────────────────────────

function findServer(targetDir: string, serverName: string): McpServerEntry | null {
  const sources = getConfigSources(targetDir);
  for (const source of sources) {
    const servers = parseConfigFile(source.filePath, source.label);
    const found = servers.find(s => s.name === serverName);
    if (found) return found;
  }
  return null;
}

async function loadAimCore(): Promise<any | null> {
  try {
    return await import('@opena2a/aim-core');
  } catch {
    process.stderr.write('aim-core is not available.\n');
    process.stderr.write('Install: npm install @opena2a/aim-core\n');
    return null;
  }
}

// ── Exports for testing ───────────────────────────────────────────────

export const _internals = {
  parseConfigFile,
  getConfigSources,
  computeConfigHash,
  findServer,
  getIdentityPath,
  getIdentityDir,
  extractCapabilities,
  detectPinnedVersion,
  fetchTrustScore,
};
