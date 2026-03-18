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

export interface RegisterResponse {
  agentId: string;
  name: string;
  displayName: string;
  publicKey: string;
  privateKey: string;
  aimUrl: string;
  status: string;
  trustScore: number;
  message: string;
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
  details?: string;
  ipAddress?: string;
  createdAt: string;
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

  // ---- Registration (public, requires API key header) --------------------

  async register(body: RegisterRequest, apiKey: string): Promise<RegisterResponse> {
    const serverBody = {
      name: body.name,
      displayName: body.displayName ?? body.name,
      description: body.description ?? '',
      agentType: body.agentType ?? 'custom',
    };
    return this.post('/api/v1/public/agents/register', serverBody, {
      'X-AIM-API-Key': apiKey,
    });
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
    return this.get(
      `/api/v1/agents/${encodeURIComponent(agentId)}/audit-logs${query ? '?' + query : ''}`,
      token,
    );
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
    if (this.apiKey) headers['X-AIM-API-Key'] = this.apiKey;

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
    return this.get('/api/v1/tags');
  }

  async createTag(name: string, color?: string): Promise<any> {
    return this.post('/api/v1/tags', { name, color: color ?? '#06b6d4' });
  }

  async addTagsToAgent(agentId: string, tagIds: string[]): Promise<any> {
    return this.post(`/api/v1/agents/${encodeURIComponent(agentId)}/tags`, { tagIds });
  }

  async removeTagFromAgent(agentId: string, tagId: string): Promise<any> {
    return this.del(`/api/v1/agents/${encodeURIComponent(agentId)}/tags/${encodeURIComponent(tagId)}`);
  }

  async getAgentTags(agentId: string): Promise<{ tags: any[] }> {
    return this.get(`/api/v1/agents/${encodeURIComponent(agentId)}/tags`);
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
    if (this.apiKey) headers['X-AIM-API-Key'] = this.apiKey;

    const response = await this.fetch(path, { method: 'GET', headers });
    return this.parseResponse<T>(response);
  }

  private async post<T>(path: string, body: unknown, extraHeaders?: Record<string, string>): Promise<T> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    };
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;
    if (this.apiKey) headers['X-AIM-API-Key'] = this.apiKey;
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
    if (this.apiKey) headers['X-AIM-API-Key'] = this.apiKey;

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
    if (this.apiKey) headers['X-AIM-API-Key'] = this.apiKey;

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
    const text = await response.text();

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
