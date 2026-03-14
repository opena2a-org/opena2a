/**
 * opena2a claim -- Claim ownership of a discovered agent in the trust registry.
 * Verifies package ownership via npm, GitHub, or PyPI and links the profile
 * to the developer's verified identity.
 *
 * Usage:
 *   opena2a claim @anthropic/mcp-server-fetch
 *   opena2a claim langchain --source pypi
 *   opena2a claim                              # reads package.json in cwd
 */

import { bold, green, yellow, red, dim, cyan } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';
import type {
  TrustLookupResponse,
  OwnershipProof,
  ClaimResponse,
} from './atp-types.js';

// --- Types ---

export interface ClaimOptions {
  packageName?: string;
  source?: string;
  registryUrl?: string;
  ci?: boolean;
  format?: 'text' | 'json';
  json?: boolean;
  verbose?: boolean;
}

// --- Constants ---

const DEFAULT_REGISTRY_URL = 'https://api.oa2a.org';

// --- Testable internals ---

export const _internals = {
  readLocalPackageName(): string | null {
    try {
      const fs = require('node:fs');
      const path = require('node:path');
      const pkgPath = path.join(process.cwd(), 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        return pkg.name ?? null;
      }
    } catch { /* ignore */ }
    return null;
  },

  async fetchTrustLookup(
    registryUrl: string,
    packageName: string,
    source?: string,
  ): Promise<{ ok: boolean; status: number; data?: TrustLookupResponse }> {
    const params = new URLSearchParams({ package: packageName });
    if (source) params.set('source', source);
    const url = `${registryUrl}/v1/trust/lookup?${params}`;

    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(15_000),
    });

    if (!response.ok) {
      return { ok: false, status: response.status };
    }

    const data = (await response.json()) as TrustLookupResponse;
    return { ok: true, status: response.status, data };
  },

  async verifyNpmOwnership(packageName: string): Promise<OwnershipProof | null> {
    try {
      const { execSync } = require('node:child_process');

      // Get current npm user
      const whoami = execSync('npm whoami', { encoding: 'utf-8', timeout: 10_000 }).trim();
      if (!whoami) return null;

      // Check if user has publish access
      const accessOutput = execSync('npm access ls-packages', {
        encoding: 'utf-8',
        timeout: 15_000,
      }).trim();

      const packages = JSON.parse(accessOutput || '{}') as Record<string, string>;
      const hasAccess = packages[packageName] === 'read-write';

      if (!hasAccess) return null;

      return {
        method: 'npm',
        identity: whoami,
        evidence: JSON.stringify({ username: whoami, access: packages[packageName] }),
      };
    } catch {
      return null;
    }
  },

  async verifyGithubOwnership(packageName: string): Promise<OwnershipProof | null> {
    try {
      const { execSync } = require('node:child_process');

      // Derive owner/repo from scoped package name or plain name
      let owner: string;
      let repo: string;

      if (packageName.startsWith('@')) {
        // @scope/name -> scope, name
        const parts = packageName.slice(1).split('/');
        owner = parts[0];
        repo = parts[1] ?? parts[0];
      } else {
        // Try to find repo info from local git remote
        try {
          const remoteUrl = execSync('git remote get-url origin', {
            encoding: 'utf-8',
            timeout: 5_000,
          }).trim();

          const match = remoteUrl.match(/github\.com[:/]([^/]+)\/([^/.]+)/);
          if (match) {
            owner = match[1];
            repo = match[2];
          } else {
            return null;
          }
        } catch {
          return null;
        }
      }

      // Verify repo access via gh CLI
      const repoData = execSync(`gh api repos/${owner}/${repo} --jq '.permissions.push'`, {
        encoding: 'utf-8',
        timeout: 10_000,
      }).trim();

      if (repoData !== 'true') return null;

      return {
        method: 'github',
        identity: `${owner}/${repo}`,
        evidence: JSON.stringify({ owner, repo, pushAccess: true }),
      };
    } catch {
      return null;
    }
  },

  async generateKeypair(): Promise<{ publicKey: string; privateKey: string }> {
    const { generateKeyPairSync } = require('node:crypto');

    const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    return { publicKey, privateKey };
  },

  async submitClaim(
    registryUrl: string,
    agentId: string,
    proof: OwnershipProof,
    publicKey: string,
  ): Promise<{ ok: boolean; status: number; data?: ClaimResponse }> {
    const url = `${registryUrl}/v1/trust/claim`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ agentId, proof, publicKey }),
      signal: AbortSignal.timeout(15_000),
    });

    if (!response.ok) {
      let errorData: any = {};
      try { errorData = await response.json(); } catch { /* ignore */ }
      return {
        ok: false,
        status: response.status,
        data: {
          success: false,
          agentId,
          previousTrustLevel: 'discovered',
          newTrustLevel: 'discovered',
          previousTrustScore: 0,
          newTrustScore: 0,
          profileUrl: '',
          error: errorData.error ?? errorData.message ?? `HTTP ${response.status}`,
        },
      };
    }

    const data = (await response.json()) as ClaimResponse;
    return { ok: true, status: response.status, data };
  },

  async storeKeypair(agentId: string, publicKey: string, privateKey: string): Promise<string> {
    const fs = require('node:fs');
    const path = require('node:path');
    const os = require('node:os');

    const dir = path.join(os.homedir(), '.opena2a', 'keys');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    const sanitizedId = agentId.replace(/[^a-zA-Z0-9_-]/g, '_');
    const pubPath = path.join(dir, `${sanitizedId}.pub`);
    const privPath = path.join(dir, `${sanitizedId}.key`);

    fs.writeFileSync(pubPath, publicKey, { mode: 0o644 });
    fs.writeFileSync(privPath, privateKey, { mode: 0o600 });

    return dir;
  },
};

// --- Core ---

export async function claim(options: ClaimOptions): Promise<number> {
  const registryUrl = await resolveRegistryUrl(options.registryUrl);
  const isJson = options.json || options.format === 'json';
  const isCi = options.ci ?? false;

  // Resolve package name
  let packageName = options.packageName;

  // Auto-detect GitHub URLs
  if (packageName && packageName.startsWith('https://github.com/')) {
    const match = packageName.match(/github\.com\/([^/]+\/[^/]+)/);
    if (match) {
      packageName = match[1].replace(/\.git$/, '');
      if (!options.source) options.source = 'github';
    }
  }

  if (!packageName) {
    packageName = _internals.readLocalPackageName() ?? undefined;
    if (!packageName) {
      const msg = 'No package name provided and no package.json found in current directory.';
      if (isJson) {
        process.stdout.write(JSON.stringify({ error: msg }) + '\n');
      } else {
        process.stderr.write(red(msg) + '\n');
        process.stderr.write('Usage: opena2a claim <package-name> [--source npm|pypi|github]\n');
      }
      return 1;
    }
  }

  if (!isJson && !isCi) {
    process.stdout.write(`Claiming ${bold(packageName)}...\n\n`);
  }

  const spinner = new Spinner('');

  // Default source to "npm" -- same pattern as trust.ts.
  // Without a source the registry API returns 400 "source parameter is required".
  const source = options.source ?? 'npm';

  // Step 1: Look up the package in the registry
  if (!isCi && !isJson) {
    spinner.update('Looking up trust profile...');
    spinner.start();
  }

  let lookupData: TrustLookupResponse;
  try {
    const result = await _internals.fetchTrustLookup(registryUrl, packageName, source);
    if (!isCi && !isJson) spinner.stop();

    if (!result.ok || !result.data) {
      const msg = `No trust profile found. Run \`opena2a self-register ${packageName}\` to add it first.`;
      if (isJson) {
        process.stdout.write(JSON.stringify({ error: 'not_found', package: packageName, message: msg }) + '\n');
      } else {
        process.stdout.write(yellow(msg) + '\n');
        if (options.verbose) {
          const params = new URLSearchParams({ package: packageName });
          params.set('source', source);
          process.stdout.write(dim(`Registry: ${registryUrl}`) + '\n');
          process.stdout.write(dim(`Request: GET /v1/trust/lookup?${params}`) + '\n');
        }
      }
      return 1;
    }
    lookupData = result.data;
  } catch (err) {
    if (!isCi && !isJson) spinner.stop();
    const errMsg = err instanceof Error ? err.message : String(err);
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'lookup_failed', message: errMsg }) + '\n');
    } else {
      process.stderr.write(red(`Failed to look up trust profile: ${errMsg}`) + '\n');
      if (options.verbose) {
        process.stderr.write(dim(`Registry: ${registryUrl}`) + '\n');
        process.stderr.write(dim(`Full error: ${err instanceof Error ? err.stack ?? err.message : String(err)}`) + '\n');
      }
    }
    return 1;
  }

  // Step 2: Check if already claimed
  if (lookupData.trustLevel === 'claimed' || lookupData.trustLevel === 'verified' || lookupData.trustLevel === 'certified') {
    const msg = `This agent is already claimed by ${lookupData.publisher}.`;
    if (isJson) {
      process.stdout.write(JSON.stringify({
        error: 'already_claimed',
        package: packageName,
        publisher: lookupData.publisher,
        trustLevel: lookupData.trustLevel,
        message: msg,
      }) + '\n');
    } else {
      process.stdout.write(yellow(msg) + '\n');
      process.stdout.write(dim(`Trust level: ${lookupData.trustLevel}, Score: ${Math.round(lookupData.trustScore * 100)}/100`) + '\n');
      process.stdout.write(dim(`Profile: ${lookupData.profileUrl}`) + '\n');
    }
    return 1;
  }

  // Step 3: Verify ownership
  if (!isCi && !isJson) {
    spinner.update('Verifying ownership...');
    spinner.start();
  }

  // Re-resolve source: prefer explicit option, then registry-reported source, then default
  const ownershipSource = options.source ?? lookupData.source ?? source;
  let proof: OwnershipProof | null = null;

  if (ownershipSource === 'npm' || (!options.source && !lookupData.source)) {
    if (!isCi && !isJson) spinner.update('Verifying npm publish access...');
    proof = await _internals.verifyNpmOwnership(packageName);
  }

  if (!proof && (ownershipSource === 'github' || !options.source)) {
    if (!isCi && !isJson) spinner.update('Verifying GitHub repository access...');
    proof = await _internals.verifyGithubOwnership(packageName);
  }

  if (!isCi && !isJson) spinner.stop();

  if (!proof) {
    const msg = `Could not verify ownership of ${packageName}.`;
    if (isJson) {
      process.stdout.write(JSON.stringify({
        error: 'verification_failed',
        package: packageName,
        message: msg,
      }) + '\n');
    } else {
      process.stderr.write(red(msg) + '\n');
      process.stderr.write('\n');
      process.stderr.write('Ownership verification requires one of:\n');
      process.stderr.write('  npm:    Logged in with publish access (npm login)\n');
      process.stderr.write('  GitHub: Push access to the repository (gh auth login)\n');
    }
    return 1;
  }

  if (!isJson && !isCi) {
    const methodLabel = proof.method === 'npm' ? 'npm publish access'
      : proof.method === 'github' ? 'GitHub repository access'
      : 'PyPI API token';
    process.stdout.write(`Verifying ${methodLabel}... ${green('verified')}\n`);
  }

  // Step 4: Generate Ed25519 keypair
  if (!isCi && !isJson) {
    spinner.update('Generating Ed25519 keypair...');
    spinner.start();
  }

  let publicKey: string;
  let privateKey: string;
  try {
    const keypair = await _internals.generateKeypair();
    publicKey = keypair.publicKey;
    privateKey = keypair.privateKey;
  } catch (err) {
    if (!isCi && !isJson) spinner.stop();
    const errMsg = err instanceof Error ? err.message : String(err);
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'keygen_failed', message: errMsg }) + '\n');
    } else {
      process.stderr.write(red(`Failed to generate keypair: ${errMsg}`) + '\n');
    }
    return 1;
  }

  if (!isCi && !isJson) {
    spinner.stop();
    process.stdout.write(`Generating Ed25519 keypair... ${green('done')}\n`);
  }

  // Step 5: Submit claim to registry
  if (!isCi && !isJson) {
    spinner.update('Registering claim with registry...');
    spinner.start();
  }

  try {
    const claimResult = await _internals.submitClaim(
      registryUrl,
      lookupData.agentId,
      proof,
      publicKey,
    );

    if (!isCi && !isJson) spinner.stop();

    if (!claimResult.ok || !claimResult.data?.success) {
      const errMsg = claimResult.data?.error ?? 'Unknown error';
      if (isJson) {
        const { error: _discardError, ...rest } = claimResult.data ?? {} as any;
        process.stdout.write(JSON.stringify({
          ...rest,
          error: 'claim_failed',
          message: errMsg,
        }) + '\n');
      } else {
        process.stderr.write(red(`Claim failed: ${errMsg}`) + '\n');
      }
      return 1;
    }

    // Store keypair locally
    const keyDir = await _internals.storeKeypair(lookupData.agentId, publicKey, privateKey);

    const claimData = claimResult.data;

    if (isJson) {
      process.stdout.write(JSON.stringify(claimData, null, 2) + '\n');
    } else {
      process.stdout.write(`Registering claim with registry... ${green('done')}\n`);
      process.stdout.write('\n');
      process.stdout.write(green(bold('Claimed successfully.')) + '\n');

      const prevScore = Math.round(claimData.previousTrustScore * 100);
      const newScore = Math.round(claimData.newTrustScore * 100);
      process.stdout.write(`  Trust level: ${claimData.previousTrustLevel} -> ${green(claimData.newTrustLevel)}\n`);
      process.stdout.write(`  Trust score: ${prevScore}/100 -> ${green(`${newScore}/100`)}\n`);
      process.stdout.write(`  Profile: ${cyan(claimData.profileUrl)}\n`);
      process.stdout.write(`  Keys: ${dim(keyDir)}\n`);

      process.stdout.write('\n');
      process.stdout.write(bold('Next steps:') + '\n');
      process.stdout.write(`  Run \`hackmyagent scan . --publish\` to improve your trust score\n`);

      const badgeUrl = claimData.profileUrl.replace('/agents/', '/v1/trust/') + '/badge.svg';
      process.stdout.write(`  Add badge to README:\n`);
      process.stdout.write(dim(`    [![Trust](${badgeUrl})](${claimData.profileUrl})`) + '\n');
    }

    return 0;
  } catch (err) {
    if (!isCi && !isJson) spinner.stop();
    const errMsg = err instanceof Error ? err.message : String(err);
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'claim_failed', message: errMsg }) + '\n');
    } else {
      process.stderr.write(red(`Failed to submit claim: ${errMsg}`) + '\n');
      process.stderr.write(dim(`Registry: ${registryUrl}`) + '\n');
      if (options.verbose) {
        process.stderr.write(dim(`Full error: ${err instanceof Error ? err.stack ?? err.message : String(err)}`) + '\n');
      }
    }
    return 1;
  }
}

// --- Helpers ---

async function resolveRegistryUrl(override?: string): Promise<string> {
  if (override) return override.replace(/\/$/, '');

  const envUrl = process.env.OPENA2A_REGISTRY_URL;
  if (envUrl) return envUrl.replace(/\/$/, '');

  try {
    const shared = await (Function('return import("@opena2a/shared")')() as Promise<any>);
    const mod = 'default' in shared ? shared.default : shared;
    const config = mod.loadUserConfig();
    if (config.registry.url) return config.registry.url;
  } catch { /* not available */ }

  return DEFAULT_REGISTRY_URL;
}
