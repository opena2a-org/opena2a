# @opena2a/contribute

[![npm version](https://img.shields.io/npm/v/@opena2a/contribute.svg)](https://www.npmjs.com/package/@opena2a/contribute)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Shared community trust data contribution client for [OpenA2A](https://github.com/opena2a-org/opena2a) tools.

## Install

```bash
npm install @opena2a/contribute
```

## What It Does

When users opt in, OpenA2A tools (HackMyAgent, opena2a-cli, Browser Guard) can contribute anonymized scan results to the [OpenA2A Registry](https://registry.opena2a.org). This package provides the shared client that all tools use to queue and submit that data.

- **Opt-in only** -- no data is sent unless the user explicitly enables contribution
- **Anonymized** -- only aggregate scan summaries are submitted, never source code or secrets
- **Batched** -- events are queued locally and flushed in batches to reduce network calls
- **Consistent** -- all OpenA2A tools use this same client, ensuring uniform data format

## Usage

```typescript
import { contribute } from '@opena2a/contribute';

// Record a scan result (no-op if contribution is disabled)
await contribute.scanResult({
  tool: 'hackmyagent',
  toolVersion: '0.15.7',
  packageName: 'my-mcp-server',
  packageVersion: '1.0.0',
  ecosystem: 'npm',
  totalChecks: 42,
  passed: 38,
  critical: 0,
  high: 1,
  medium: 2,
  low: 1,
  score: 85,
  verdict: 'WARN',
  durationMs: 1200,
});

// Record a detection event
await contribute.detection({
  tool: 'opena2a-cli',
  toolVersion: '0.8.21',
  agentsFound: 3,
  mcpServersFound: 5,
  frameworkTypes: ['claude', 'openai'],
});

// Manually flush queued events
await contribute.flush();
```

## API

| Export | Description |
|--------|------------|
| `contribute.scanResult(params)` | Queue a scan result event |
| `contribute.detection(params)` | Queue a detection event |
| `contribute.flush()` | Submit all queued events to the Registry |
| `isContributeEnabled()` | Check if contribution is enabled |
| `queueEvent(event)` | Low-level: add an event to the local queue |
| `getQueuedEvents()` | Low-level: read queued events |
| `clearQueue()` | Low-level: clear the local queue |
| `shouldFlush()` | Check if the queue has reached the flush threshold |
| `buildBatch(events)` | Build a submission batch from queued events |
| `submitBatch(batch)` | Submit a batch to the Registry API |
| `getContributorToken()` | Get or create an anonymous contributor token |

## Part of OpenA2A

This is an internal package used by [opena2a-cli](https://github.com/opena2a-org/opena2a), [HackMyAgent](https://github.com/opena2a-org/hackmyagent), and other OpenA2A tools. For the CLI, see the [main repository](https://github.com/opena2a-org/opena2a).

## License

Apache-2.0
