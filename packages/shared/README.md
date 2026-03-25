# @opena2a/shared

[![npm version](https://img.shields.io/npm/v/@opena2a/shared.svg)](https://www.npmjs.com/package/@opena2a/shared)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Shared types, config schema, and utilities for the [OpenA2A](https://github.com/opena2a-org/opena2a) platform.

## Install

```bash
npm install @opena2a/shared
```

## What's Inside

This package provides the common foundation used by `opena2a-cli` and other OpenA2A tools:

- **Project config** -- `loadProjectConfig()` reads and validates `.opena2a.yml` / `opena2a.config.json` using Zod schemas
- **User config** -- `loadUserConfig()` / `saveUserConfig()` manage per-user preferences stored in `~/.opena2a/`
- **Scan history** -- `loadScanHistory()` / `appendScanEntry()` track past scan results locally
- **Shared types** -- `AdapterType`, `AdapterResult`, `Finding`, and other interfaces used across adapters

## Usage

```typescript
import {
  loadProjectConfig,
  loadUserConfig,
  saveUserConfig,
  isContributeEnabled,
  loadScanHistory,
  appendScanEntry,
} from '@opena2a/shared';

// Load project config from current directory
const config = loadProjectConfig('./');

// Check user preferences
const userConfig = loadUserConfig();
console.log('Contribute enabled:', isContributeEnabled());

// Track scan history
appendScanEntry({
  tool: 'hackmyagent',
  target: 'my-project',
  score: 85,
  timestamp: new Date().toISOString(),
});
```

## API

| Export | Description |
|--------|------------|
| `loadProjectConfig(dir)` | Load and validate project config from a directory |
| `projectConfigSchema` | Zod schema for project configuration |
| `loadUserConfig()` | Load user preferences from `~/.opena2a/` |
| `saveUserConfig(config)` | Persist user preferences |
| `isContributeEnabled()` | Check if anonymous data contribution is enabled |
| `setContributeEnabled(bool)` | Toggle data contribution |
| `loadScanHistory()` | Load local scan history |
| `appendScanEntry(entry)` | Add a scan result to history |
| `getLastScan()` | Get the most recent scan entry |
| `getRecentScans()` | Get recent scan entries |

## Part of OpenA2A

This is an internal package used by [opena2a-cli](https://github.com/opena2a-org/opena2a) and other OpenA2A tools. For the CLI, see the [main repository](https://github.com/opena2a-org/opena2a).

## License

Apache-2.0
