import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import * as shared from '@opena2a/shared';

/**
 * Where `opena2a mcp sign` keeps MCP server identities. Each identity file holds
 * the server's Ed25519 private key, so it lives in the per-project user store,
 * `<OpenA2A user home>/projects/<key>/mcp-identities`, and never in the project
 * tree, where it would be one `git add .` away from being published.
 */

/** The directory releases before the project store wrote identities to; read, never written. */
export function legacyMcpIdentityDir(projectDir: string): string {
  return path.join(projectDir, '.opena2a', 'mcp-identities');
}

/**
 * The project store directory from `@opena2a/shared`. A published shared
 * package older than the store resolver has no `getProjectStoreDir`; the same
 * path is then computed here, by the rule shared pins (user home is
 * $OPENA2A_HOME when non-blank, else ~/.opena2a; the key is the first 16 hex
 * characters of the SHA-256 of the project's canonical path).
 */
function projectStoreDir(projectDir: string): string {
  const resolver = (shared as Partial<typeof shared>).getProjectStoreDir;
  if (typeof resolver === 'function') return resolver(projectDir);
  const configured = process.env.OPENA2A_HOME?.trim();
  const home = configured ? path.resolve(configured) : path.join(os.homedir(), '.opena2a');
  const absolute = path.resolve(projectDir);
  let canonical = absolute;
  try {
    canonical = fs.realpathSync.native(absolute);
  } catch {
    // Not on disk: key the absolute path as given.
  }
  const key = crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 16);
  return path.join(home, 'projects', key);
}

/** The directory `mcp sign` writes identities to, outside the project tree. */
export function mcpIdentityStoreDir(projectDir: string): string {
  return path.join(projectStoreDir(projectDir), 'mcp-identities');
}

/** The path `mcp sign` writes a server's identity to. */
export function mcpIdentityStorePath(projectDir: string, serverName: string): string {
  return path.join(mcpIdentityStoreDir(projectDir), `${serverName}.json`);
}

/** The in-tree path an older release wrote a server's identity to. */
export function legacyMcpIdentityPath(projectDir: string, serverName: string): string {
  return path.join(legacyMcpIdentityDir(projectDir), `${serverName}.json`);
}

/**
 * The identity file for a server: the store's when present, else one an older
 * release left in the project tree, else null.
 */
export function findMcpIdentityFile(projectDir: string, serverName: string): string | null {
  for (const candidate of [mcpIdentityStorePath(projectDir, serverName), legacyMcpIdentityPath(projectDir, serverName)]) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

/** Names of the servers with an identity, in the store or left in the project tree. */
export function listMcpIdentityNames(projectDir: string): string[] {
  const names = new Set<string>();
  for (const dir of [mcpIdentityStoreDir(projectDir), legacyMcpIdentityDir(projectDir)]) {
    try {
      for (const f of fs.readdirSync(dir)) {
        if (f.endsWith('.json')) names.add(f.slice(0, -'.json'.length));
      }
    } catch {
      // Directory absent or unreadable: no identities there.
    }
  }
  return [...names];
}
