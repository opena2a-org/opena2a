/**
 * Vault namespace management.
 *
 * Namespaces group credentials by service/purpose and define access policies
 * (allowed operations, URL patterns). Metadata is stored in a separate JSON
 * file — no credential material here.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { VaultNamespace, VaultOperation, NamespaceStatus } from './types';

const NAMESPACES_FILE = 'namespaces.json';

interface NamespacesFile {
  namespaces: Record<string, VaultNamespace>;
}

/** Load the namespaces file from the vault directory */
function loadNamespaces(vaultDir: string): NamespacesFile {
  const filePath = path.join(vaultDir, NAMESPACES_FILE);
  if (!fs.existsSync(filePath)) {
    return { namespaces: {} };
  }
  const raw = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(raw) as NamespacesFile;
}

/** Atomically write the namespaces file */
function saveNamespaces(vaultDir: string, data: NamespacesFile): void {
  const filePath = path.join(vaultDir, NAMESPACES_FILE);
  const tmpPath = filePath + '.tmp.' + process.pid;
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), 'utf-8');
  try { fs.chmodSync(tmpPath, 0o600); } catch { /* Windows */ }
  fs.renameSync(tmpPath, filePath);
}

export interface CreateNamespaceOptions {
  id: string;
  description: string;
  agentId: string;
  operations: VaultOperation[];
  urlPatterns: string[];
}

/**
 * Create a new namespace in the vault.
 *
 * @throws if namespace ID already exists
 */
export function createNamespace(
  vaultDir: string,
  options: CreateNamespaceOptions
): VaultNamespace {
  const data = loadNamespaces(vaultDir);

  if (data.namespaces[options.id]) {
    throw new Error(`Namespace "${options.id}" already exists`);
  }

  const now = new Date().toISOString();
  const ns: VaultNamespace = {
    id: options.id,
    description: options.description,
    agentId: options.agentId,
    operations: options.operations,
    urlPatterns: options.urlPatterns,
    status: 'active',
    createdAt: now,
    updatedAt: now,
  };

  data.namespaces[options.id] = ns;
  saveNamespaces(vaultDir, data);

  return ns;
}

/** List all namespaces (including revoked) */
export function listNamespaces(vaultDir: string): VaultNamespace[] {
  const data = loadNamespaces(vaultDir);
  return Object.values(data.namespaces);
}

/**
 * Get a single namespace by ID.
 *
 * @returns The namespace, or null if not found
 */
export function getNamespace(vaultDir: string, id: string): VaultNamespace | null {
  const data = loadNamespaces(vaultDir);
  return data.namespaces[id] ?? null;
}

export interface UpdateNamespaceOptions {
  description?: string;
  operations?: VaultOperation[];
  urlPatterns?: string[];
}

/**
 * Update an existing namespace's metadata.
 *
 * @throws if namespace not found or is revoked
 */
export function updateNamespace(
  vaultDir: string,
  id: string,
  updates: UpdateNamespaceOptions
): VaultNamespace {
  const data = loadNamespaces(vaultDir);
  const ns = data.namespaces[id];
  if (!ns) {
    throw new Error(`Namespace "${id}" not found`);
  }
  if (ns.status === 'revoked') {
    throw new Error(`Namespace "${id}" is revoked and cannot be updated`);
  }

  if (updates.description !== undefined) ns.description = updates.description;
  if (updates.operations !== undefined) ns.operations = updates.operations;
  if (updates.urlPatterns !== undefined) ns.urlPatterns = updates.urlPatterns;
  ns.updatedAt = new Date().toISOString();

  data.namespaces[id] = ns;
  saveNamespaces(vaultDir, data);

  return ns;
}

/**
 * Revoke a namespace — marks it as revoked. Credentials for this namespace
 * will no longer be resolvable.
 *
 * @param deleteCredentials - If true, also deletes the credential from the VaultStore.
 *                            Caller is responsible for calling store.deleteCredential().
 * @throws if namespace not found
 * @returns true if newly revoked, false if already revoked
 */
export function revokeNamespace(vaultDir: string, id: string): boolean {
  const data = loadNamespaces(vaultDir);
  const ns = data.namespaces[id];
  if (!ns) {
    throw new Error(`Namespace "${id}" not found`);
  }
  if (ns.status === 'revoked') {
    return false; // Already revoked
  }

  ns.status = 'revoked';
  ns.updatedAt = new Date().toISOString();
  data.namespaces[id] = ns;
  saveNamespaces(vaultDir, data);

  return true;
}
