# Post-incident review

Once `opena2a identity integrate` runs once, every event the OpenA2A toolchain captures auto-bridges into a single local audit log. No decorator in your agent code. No server. When something goes wrong:

```bash
opena2a identity audit --limit 200
# 200 most recent events: credential injections, file accesses, config
# changes, scan findings, ARP runtime events. All in one timestamp-
# ordered table, sourced from Secretless, HackMyAgent, ConfigGuard,
# Shield, and ARP.

jq 'select(.result == "denied")' ~/.opena2a/aim-core/audit.jsonl
# just the denies, read from the log file
```

The audit log lives at `~/.opena2a/aim-core/audit.jsonl`. Append-only. Rotation at 50 MB, last 5 generations kept. Forward to Splunk or Sentinel via the standard tail-and-forward pattern.

Encryption at rest is filesystem-level. The JSONL stores unencrypted so `grep` and `jq` work without ceremony. For compliance use cases, encrypt `~/.opena2a/` with FileVault on macOS, LUKS on Linux, or BitLocker on Windows, or ship to a KMS-backed log aggregator.
