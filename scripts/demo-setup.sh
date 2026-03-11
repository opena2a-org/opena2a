#!/bin/bash
# OpenA2A Demo Setup Script
# Creates a realistic sample project for demo recording.
#
# Usage:
#   source scripts/demo-setup.sh
#   cd "$DEMO_DIR"
#
# The exported DEMO_DIR variable points to the temporary project.
# Cleanup: rm -rf "$DEMO_DIR"
set -e

DEMO_DIR=$(mktemp -d /tmp/opena2a-demo-XXXX)
echo "Setting up demo project at $DEMO_DIR"

cd "$DEMO_DIR"

# -- Node project scaffold --------------------------------------------------
cat > package.json << 'PKGJSON'
{
  "name": "my-ai-agent",
  "version": "1.0.0",
  "description": "A sample AI agent project with MCP tools",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.0"
  }
}
PKGJSON

# -- Source file with a FAKE hardcoded credential ---------------------------
cat > config.js << 'CONFIGJS'
// Agent configuration
const API_KEY = "sk-FAKE-demo-key-not-real-abc123";
const AGENT_NAME = "research-assistant";
const MODEL = "claude-sonnet-4-20250514";

module.exports = { API_KEY, AGENT_NAME, MODEL };
CONFIGJS

cat > index.js << 'INDEXJS'
const { API_KEY, AGENT_NAME, MODEL } = require("./config");

async function main() {
  console.log(`Starting agent: ${AGENT_NAME}`);
  // ... agent logic ...
}

main().catch(console.error);
INDEXJS

# -- MCP server configuration -----------------------------------------------
cat > .mcp.json << 'MCPJSON'
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    },
    "memory": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-memory"]
    }
  }
}
MCPJSON

# -- Governance file (SOUL.md) ----------------------------------------------
cat > SOUL.md << 'SOUL'
---
name: research-assistant
version: 1.0.0
---

# Research Assistant Governance

## Purpose
Assist users with research tasks by searching, summarizing, and citing sources.

## Boundaries
- Do not access private databases without explicit permission
- Do not fabricate citations or statistics
SOUL

# -- Git init so opena2a detects it as a project ----------------------------
git init -q
git add -A
git commit -q -m "Initial commit" --no-gpg-sign

export DEMO_DIR
echo "Demo project ready at $DEMO_DIR"
