export type { Adapter, AdapterConfig, AdapterMethod, RunOptions, RunResult } from './types.js';
export { ADAPTER_REGISTRY, getAdapter, listAdapters, getAdaptersByMethod } from './registry.js';
export { SpawnAdapter } from './spawn.js';
export { DockerAdapter } from './docker.js';
export { PythonAdapter } from './python.js';
export { ImportAdapter } from './import.js';

import type { Adapter } from './types.js';
import { ADAPTER_REGISTRY } from './registry.js';
import { ImportAdapter } from './import.js';
import { SpawnAdapter } from './spawn.js';
import { DockerAdapter } from './docker.js';
import { PythonAdapter } from './python.js';

export function createAdapter(name: string): Adapter | null {
  const config = ADAPTER_REGISTRY[name];
  if (!config) return null;

  switch (config.method) {
    case 'import':
      return new ImportAdapter(config);
    case 'spawn':
      return new SpawnAdapter(config);
    case 'docker':
      return new DockerAdapter(config);
    case 'python':
      return new PythonAdapter(config);
    default:
      return null;
  }
}
