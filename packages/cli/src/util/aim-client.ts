/**
 * AIM Server HTTP Client
 *
 * Minimal HTTP client for communicating with the AIM (Agent Identity Management)
 * server. Uses Node's built-in fetch (available in Node 18+).
 *
 * All methods return typed response objects or throw AimServerError on failure.
 */

// ---------------------------------------------------------------------------
// Types — mirror the AIM server API shapes (camelCase)
// ---------------------------------------------------------------------------

export interface ServerAgent {
  id: string;
  name: string;
  displayName: string;
  publicKey: string;
  privateKey?: string;
  apiKey?: string;
  trustScore: number;
  status: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface RegisterRequest {
  name: string;
  displayName?: string;
  description?: string;
  agentType?: string;
}

/**
 * An API-key registration carries the public half of a keypair the client
 * generated; the route never returns a private key.
 */
export interface ApiKeyRegisterRequest extends RegisterRequest {
  /** Base64 of the raw 32-byte Ed25519 public key. */
  publicKey: string;
}

export interface RegisterResponse {
  agentId: string;
  name: string;
  displayName: string;
  publicKey: string;
  privateKey?: string;
  aimUrl?: string;
  status: string;
  trustScore: number;
  message?: string;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
}

export interface AgentListResponse {
  agents: ServerAgent[];
  total: number;
  page: number;
  pageSize: number;
}

export interface AuditLogEntry {
  id: string;
  agentId: string;
  action: string;
  resource?: string;
  resourceType?: string;
  resourceId?: string;
  details?: string;
  ipAddress?: string;
  createdAt: string;
  timestamp?: string;
  metadata?: Record<string, any>;
}

export interface AuditLogResponse {
  auditLogs: AuditLogEntry[];
  total: number;
  page: number;
  pageSize: number;
}

export interface ServerStatus {
  status: string;
  version?: string;
  uptime?: number;
}

export interface DeviceCodeResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresIn: number;
  interval: number;
}

export interface DeviceTokenResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
}

export interface DeviceTokenError {
  error: string;  // "authorization_pending", "slow_down", "expired_token", "access_denied"
  errorDescription?: string;
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

/**
 * The header the AIM backend reads for an agent API key (its API-key
 * middleware, after "Authorization: Bearer"). The Python and TypeScript SDKs
 * send the same name. Pinned on the backend side by
 * agent-identity-management apps/backend/cmd/server/sdk_api_key_registration_contract_test.go;
 * no backend route reads the header name this client sent before this change.
 */
export const API_KEY_HEADER = 'X-API-Key' as const;

/**
 * An agent API key as the backend mints it: "aim_live_" followed by the
 * padded URL-safe base64 of 32 random bytes, 44 characters ending in "="
 * (apps/backend/internal/application/api_key_service.go: base64.URLEncoding).
 */
const AGENT_API_KEY_PATTERN = /^aim_live_[A-Za-z0-9_-]{43}=$/;

/**
 * True when `key` has the shape of an agent API key. A shape check against a public format,
 * run before any request so a malformed key never leaves the machine; it compares against no
 * stored secret, and the server remains the authority on whether the key is valid.
 */
export function isAgentApiKey(key: string): boolean {
  return AGENT_API_KEY_PATTERN.test(key);
}

/** Base64 of a raw 32-byte Ed25519 public key: 43 characters and one pad. */
const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9+/]{43}=$/;

/**
 * True when `publicKey` is strict base64 (43 characters and one pad) that decodes to the
 * 32 bytes of a raw Ed25519 public key. Anything longer is refused before it is sent.
 */
export function isEd25519PublicKey(publicKey: string): boolean {
  return PUBLIC_KEY_PATTERN.test(publicKey) && Buffer.from(publicKey, 'base64').length === 32;
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export class AimServerError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly serverMessage?: string,
  ) {
    super(message);
    this.name = 'AimServerError';
  }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class AimClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly apiKey?: string;
  private readonly accessToken?: string;

  constructor(serverUrl: string, options?: { timeoutMs?: number; apiKey?: string; accessToken?: string }) {
    // Normalize: strip trailing slash
    this.baseUrl = serverUrl.replace(/\/+$/, '');
    this.timeoutMs = options?.timeoutMs ?? 10_000;
    this.apiKey = options?.apiKey;
    this.accessToken = options?.accessToken;
  }

  // ---- Health / Status ---------------------------------------------------

  async health(): Promise<{ status: string }> {
    return this.get('/health');
  }

  async status(): Promise<ServerStatus> {
    return this.get('/api/v1/status');
  }

  // ---- Registration with an agent API key --------------------------------

  /**
   * Register an agent with an agent API key: POST /api/v1/agents, the key in
   * X-API-Key. The key is one issued for an agent that already exists in the
   * organization, and the new agent joins that organization. The route returns
   * no private key, so the caller supplies the public half of a keypair it
   * generated and keeps the private half.
   */
  async register(body: ApiKeyRegisterRequest, apiKey: string): Promise<RegisterResponse> {
    if (!body.publicKey) {
      throw new AimServerError(
        'Registration needs the public key of a locally generated Ed25519 keypair; the server never returns a private key.',
        0,
      );
    }
    if (!isEd25519PublicKey(body.publicKey)) {
      throw new AimServerError(
        'The public key is not the base64 of a 32-byte Ed25519 key; nothing was sent.',
        0,
      );
    }
    if (!isAgentApiKey(apiKey)) {
      throw new AimServerError(
        'The API key is not an AIM agent API key (aim_live_ followed by 44 characters); nothing was sent.',
        0,
      );
    }
    const serverBody = {
      name: body.name,
      displayName: body.displayName ?? body.name,
      description: body.description ?? '',
      agentType: body.agentType ?? 'custom',
      publicKey: body.publicKey,
    };
    const resp = await this.post<Record<string, unknown>>('/api/v1/agents', serverBody, {
      [API_KEY_HEADER]: apiKey,
    });
    const agentId = resp.agentId ?? resp.id;
    if (typeof agentId !== 'string' || agentId === '') {
      throw new AimServerError(
        'The AIM server answered the registration without an agent id; nothing was stored.',
        0,
      );
    }
    return {
      agentId,
      name: typeof resp.name === 'string' ? resp.name : body.name,
      displayName: typeof resp.displayName === 'string' ? resp.displayName : serverBody.displayName,
      publicKey: typeof resp.publicKey === 'string' ? resp.publicKey : body.publicKey,
      status: typeof resp.status === 'string' ? resp.status : '',
      trustScore: typeof resp.trustScore === 'number' ? resp.trustScore : 0,
    };
  }

  // ---- Login -------------------------------------------------------------

  async login(credentials: { name: string; apiKey: string }): Promise<LoginResponse> {
    return this.post('/api/v1/public/login', credentials);
  }

  // ---- Agent CRUD (requires Bearer token) --------------------------------

  async createAgent(body: RegisterRequest): Promise<RegisterResponse> {
    const serverBody = {
      name: body.name,
      displayName: body.displayName ?? body.name,
      description: body.description ?? '',
      agentType: body.agentType ?? 'custom',
    };
    return this.post('/api/v1/agents', serverBody);
  }

  async listAgents(token: string, params?: { page?: number; pageSize?: number }): Promise<AgentListResponse> {
    const qs = new URLSearchParams();
    if (params?.page) qs.set('page', String(params.page));
    if (params?.pageSize) qs.set('pageSize', String(params.pageSize));
    const query = qs.toString();
    return this.get(`/api/v1/agents${query ? '?' + query : ''}`, token);
  }

  async getAgent(token: string, agentId: string): Promise<ServerAgent> {
    return this.get(`/api/v1/agents/${encodeURIComponent(agentId)}`, token);
  }

  async getAuditLogs(
    token: string,
    agentId: string,
    params?: { page?: number; pageSize?: number },
  ): Promise<AuditLogResponse> {
    const qs = new URLSearchParams();
    if (params?.page) qs.set('page', String(params.page));
    if (params?.pageSize) qs.set('pageSize', String(params.pageSize));
    const query = qs.toString();
    const result = await this.get<any>(
      `/api/v1/agents/${encodeURIComponent(agentId)}/audit-logs${query ? '?' + query : ''}`,
      token,
    );
    // Normalize server response: server returns { logs } but client expects { auditLogs }
    return {
      auditLogs: result.auditLogs ?? result.logs ?? [],
      total: result.total ?? (result.auditLogs ?? result.logs ?? []).length,
      page: result.page ?? 1,
      pageSize: result.pageSize ?? result.limit ?? params?.pageSize ?? 50,
    };
  }

  // ---- Device Authorization (OAuth 2.0 Device Flow) -----------------------

  async requestDeviceCode(clientId: string = 'opena2a-cli'): Promise<DeviceCodeResponse> {
    return this.post('/api/v1/oauth/device/code', { clientId });
  }

  async pollDeviceToken(deviceCode: string): Promise<DeviceTokenResponse> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    };
    // The device token route reads no API key (it is rate-limited, not authenticated).

    const response = await this.fetch('/api/v1/oauth/device/token', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        deviceCode,
        grantType: 'urn:ietf:params:oauth:grant-type:device_code',
      }),
    });

    const text = await response.text();
    const parsed = JSON.parse(text);

    // Device token polling returns 400 with error field for pending/slow_down
    if (!response.ok) {
      if (parsed.error) {
        const err = new AimServerError(
          parsed.error,
          response.status,
          parsed.errorDescription,
        );
        (err as any).oauthError = parsed.error;
        throw err;
      }
      throw new AimServerError(
        `AIM server returned ${response.status}: ${parsed.error ?? parsed.message ?? text}`,
        response.status,
        parsed.error ?? parsed.message,
      );
    }

    return parsed as DeviceTokenResponse;
  }

  async refreshAccessToken(refreshToken: string): Promise<DeviceTokenResponse> {
    return this.post('/api/v1/auth/refresh', { refreshToken });
  }

  // ---- Tags ---------------------------------------------------------------

  async listTags(): Promise<{ tags: any[] }> {
    const result = await this.get<any>('/api/v1/tags');
    // Server may return array directly or { tags: [...] }
    if (Array.isArray(result)) return { tags: result };
    return result;
  }

  async createTag(key: string, value: string, category?: string, color?: string): Promise<any> {
    return this.post('/api/v1/tags', {
      key,
      value,
      category: category ?? 'custom',
      color: color ?? '#06b6d4',
    });
  }

  async addTagsToAgent(agentId: string, tagIds: string[]): Promise<any> {
    return this.post(`/api/v1/agents/${encodeURIComponent(agentId)}/tags`, { tagIds });
  }

  async removeTagFromAgent(agentId: string, tagId: string): Promise<any> {
    return this.del(`/api/v1/agents/${encodeURIComponent(agentId)}/tags/${encodeURIComponent(tagId)}`);
  }

  async getAgentTags(agentId: string): Promise<{ tags: any[] }> {
    const result = await this.get<any>(`/api/v1/agents/${encodeURIComponent(agentId)}/tags`);
    if (Array.isArray(result)) return { tags: result };
    return result;
  }

  // ---- MCPs ---------------------------------------------------------------

  async getAgentMCPs(agentId: string): Promise<{ mcpServers: any[] }> {
    return this.get(`/api/v1/agents/${encodeURIComponent(agentId)}/mcp-servers`);
  }

  async addMCPsToAgent(agentId: string, mcpServerIds: string[]): Promise<any> {
    return this.put(`/api/v1/agents/${encodeURIComponent(agentId)}/mcp-servers`, { mcpServerIds });
  }

  async removeMCPFromAgent(agentId: string, mcpId: string): Promise<any> {
    return this.del(`/api/v1/agents/${encodeURIComponent(agentId)}/mcp-servers/${encodeURIComponent(mcpId)}`);
  }

  // ---- Org-level MCP Server Registry ------------------------------------

  async listOrgMcpServers(): Promise<{ mcpServers: any[]; total: number }> {
    return this.get('/api/v1/mcp-servers');
  }

  async createOrgMcpServer(body: { name: string; description?: string; url?: string; transport?: string }): Promise<any> {
    return this.post('/api/v1/mcp-servers', body);
  }

  // ---- Lifecycle ----------------------------------------------------------

  async suspendAgent(agentId: string): Promise<any> {
    return this.post(`/api/v1/agents/${encodeURIComponent(agentId)}/suspend`, {});
  }

  async reactivateAgent(agentId: string): Promise<any> {
    return this.post(`/api/v1/agents/${encodeURIComponent(agentId)}/reactivate`, {});
  }

  async revokeAgent(agentId: string): Promise<any> {
    return this.post(`/api/v1/agents/${encodeURIComponent(agentId)}/revoke`, {});
  }

  async deleteAgent(agentId: string): Promise<void> {
    await this.del(`/api/v1/agents/${encodeURIComponent(agentId)}`);
  }

  // ---- Server Policies (admin) -------------------------------------------

  async listPolicies(): Promise<{ policies: any[] }> {
    return this.get('/api/v1/admin/security-policies');
  }

  async getPolicy(policyId: string): Promise<any> {
    return this.get(`/api/v1/admin/security-policies/${encodeURIComponent(policyId)}`);
  }

  // ---- Activity -----------------------------------------------------------

  async getAgentActivity(agentId: string, params?: { page?: number; pageSize?: number }): Promise<any> {
    const qs = new URLSearchParams();
    if (params?.page) qs.set('page', String(params.page));
    if (params?.pageSize) qs.set('pageSize', String(params.pageSize));
    const query = qs.toString();
    return this.get(`/api/v1/agents/${encodeURIComponent(agentId)}/activity${query ? '?' + query : ''}`);
  }

  // ---- Generic HTTP helpers -----------------------------------------------

  private async get<T>(path: string, token?: string): Promise<T> {
    const headers: Record<string, string> = { 'Accept': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    else if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;
    if (this.apiKey) headers[API_KEY_HEADER] = this.apiKey;

    const response = await this.fetch(path, { method: 'GET', headers });
    return this.parseResponse<T>(response);
  }

  private async post<T>(path: string, body: unknown, extraHeaders?: Record<string, string>): Promise<T> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    };
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;
    if (this.apiKey) headers[API_KEY_HEADER] = this.apiKey;
    Object.assign(headers, extraHeaders);

    const response = await this.fetch(path, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    return this.parseResponse<T>(response);
  }

  private async put<T>(path: string, body: unknown): Promise<T> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    };
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;
    if (this.apiKey) headers[API_KEY_HEADER] = this.apiKey;

    const response = await this.fetch(path, {
      method: 'PUT',
      headers,
      body: JSON.stringify(body),
    });
    return this.parseResponse<T>(response);
  }

  private async del<T>(path: string): Promise<T> {
    const headers: Record<string, string> = { 'Accept': 'application/json' };
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;
    if (this.apiKey) headers[API_KEY_HEADER] = this.apiKey;

    const response = await this.fetch(path, { method: 'DELETE', headers });
    return this.parseResponse<T>(response);
  }

  private async fetch(path: string, init: RequestInit): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      return await globalThis.fetch(url, { ...init, signal: controller.signal });
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new AimServerError(
          `Request timed out after ${this.timeoutMs}ms: ${init.method} ${path}`,
          0,
        );
      }
      // Connection refused, DNS failure, etc.
      const msg = err instanceof Error ? err.message : String(err);
      throw new AimServerError(
        `Cannot connect to AIM server at ${this.baseUrl}. ${msg}`,
        0,
        msg,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  private async parseResponse<T>(response: Response): Promise<T> {
    // Handle 204 No Content (and other empty-body success responses)
    if (response.status === 204) return {} as T;

    const text = await response.text();

    // Handle empty body on success (some endpoints return 200/201 with no body)
    if (!text.trim() && response.ok) return {} as T;

    if (!response.ok) {
      let serverMsg: string | undefined;
      try {
        const parsed = JSON.parse(text);
        serverMsg = parsed.error ?? parsed.message ?? text;
      } catch {
        serverMsg = text;
      }
      throw new AimServerError(
        `AIM server returned ${response.status}: ${serverMsg}`,
        response.status,
        serverMsg,
      );
    }

    try {
      return JSON.parse(text) as T;
    } catch {
      throw new AimServerError(
        `Invalid JSON response from AIM server: ${text.slice(0, 200)}`,
        response.status,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Server config persistence
// ---------------------------------------------------------------------------

/**
 * Server connection details stored alongside the local identity.
 */
export interface ServerConfig {
  serverUrl: string;
  agentId: string;
  apiKey?: string;
  accessToken?: string;
  refreshToken?: string;
  registeredAt: string;
}

import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const AIM_DIR = join(homedir(), '.opena2a', 'aim-core', 'identities');

function serverConfigPath(): string {
  return join(AIM_DIR, 'server.json');
}

export function loadServerConfig(): ServerConfig | null {
  const p = serverConfigPath();
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, 'utf-8')) as ServerConfig;
  } catch {
    return null;
  }
}

export function saveServerConfig(config: ServerConfig): void {
  if (!existsSync(AIM_DIR)) {
    mkdirSync(AIM_DIR, { recursive: true });
  }
  writeFileSync(serverConfigPath(), JSON.stringify(config, null, 2), { encoding: 'utf-8', mode: 0o600 });
}

export function removeServerConfig(): boolean {
  const p = serverConfigPath();
  if (!existsSync(p)) return false;
  unlinkSync(p);
  return true;
}
