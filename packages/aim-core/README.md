# @opena2a/aim-core

[![npm version](https://img.shields.io/npm/v/@opena2a/aim-core.svg)](https://www.npmjs.com/package/@opena2a/aim-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Lightweight agent identity library. Ed25519 identity, local audit log, capability policy, and trust scoring. No server required.

Part of the [HackMyAgent](https://github.com/opena2a-org/hackmyagent) security toolkit.

## Install

```bash
npm install @opena2a/aim-core
```

## Quick Start

```typescript
import { AIMCore } from '@opena2a/aim-core';

// Identity, audit log and policy are stored in dataDir (default: ~/.opena2a/aim-core)
const aim = new AIMCore({ agentName: 'my-agent' });

// Ed25519 identity (generated and persisted on the first call)
const identity = aim.getOrCreateIdentity();
console.log(identity.publicKey); // base64-encoded Ed25519 public key

// Sign, then verify against the public key (base64 string or Uint8Array)
const message = Buffer.from('hello');
const signature = aim.sign(message);
console.log(aim.verify(message, signature, identity.publicKey)); // => true

// Audit logging
aim.logEvent({
  plugin: 'my-agent',
  action: 'tool_call',
  target: 'read_file',
  result: 'allowed',
  metadata: { path: '/etc/config' },
});
const events = aim.readAuditLog({ limit: 10 }); // the 10 most recent events

// Capability policy: rules are checked in order and the first match wins;
// a capability that matches no rule gets defaultAction
aim.savePolicy({
  version: '1',
  defaultAction: 'deny',
  rules: [
    { capability: 'db:read', action: 'allow' },
    { capability: 'net:*', action: 'deny' },
  ],
});
console.log(aim.checkCapability('db:read'));   // => true
console.log(aim.checkCapability('net:fetch')); // => false
console.log(aim.checkCapability('db:write'));  // => false

// Trust scoring: a 0-100 score from eight weighted factors, each 0 or 1
const trust = aim.calculateTrust();
console.log(trust.score); // => 45
console.log(trust.grade); // => 'moderate'
console.log(trust.factors);
// => { identity: 1, capabilities: 1, auditLog: 1, secretsManaged: 0,
//      configSigned: 0, skillsVerified: 0, networkControlled: 0, heartbeatMonitored: 0 }
```

The identity, the policy file and the audit log give the 45 above. The other five factors are reported by your code through `setTrustHints()`: `aim.setTrustHints({ secretsManaged: true })` adds 15 points to the next `calculateTrust()`, and `configSigned`, `skillsVerified`, `networkControlled` and `heartbeatMonitored` add 10 each.

## API

| Method | Description |
|--------|-------------|
| `getOrCreateIdentity()` | Load the identity from `dataDir`, creating an Ed25519 keypair on the first call |
| `sign(data)` | Sign bytes with the agent's private key |
| `verify(data, signature, publicKey)` | Verify a signature against a public key (base64 string or `Uint8Array`) |
| `logEvent(event)` | Append `{ plugin, action, target, result, metadata? }` to the local audit log |
| `readAuditLog(options?)` | Read audit log entries (`limit` keeps the most recent, `since` takes an ISO timestamp) |
| `loadPolicy(inline?)` | Load the capability policy from `dataDir`, or build one from `{ allow, deny, default }` |
| `savePolicy(policy)` | Save a capability policy to `dataDir` |
| `checkCapability(capability, plugin?)` | Check a capability against the policy rules |
| `calculateTrust()` | Compute the 0-100 trust score and its eight factors |
| `setTrustHints(hints)` | Report the factors the library cannot observe itself |

Lower-level functions are exported as well (`createIdentity`, `loadIdentity`, `getOrCreateIdentity`, `sign`, `verify`, `logEvent`, `readAuditLog`, `loadPolicy`, `savePolicy`, `checkCapability`, `calculateTrust`); each takes the data directory, the policy or the key as an explicit argument.

## License

Apache-2.0
