#!/bin/bash
# Set up a consistent test lab for VHS tape recordings.
# Creates /tmp/vhs-demo with a realistic project containing credentials.

set -e

LAB_DIR="/tmp/vhs-demo"
rm -rf "$LAB_DIR"
mkdir -p "$LAB_DIR" && cd "$LAB_DIR"
git init -q

cat > package.json << 'EOF'
{
  "name": "acme-agent",
  "version": "2.1.0",
  "description": "ACME Corp AI Agent",
  "main": "src/index.js",
  "dependencies": {
    "@anthropic-ai/sdk": "^0.25.0",
    "@google-cloud/aiplatform": "^3.5.0",
    "express": "^4.18.2"
  }
}
EOF

echo '{}' > package-lock.json

cat > .gitignore << 'EOF'
node_modules/
dist/
EOF

cat > mcp.json << 'EOF'
{
  "mcpServers": {
    "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"] }
  }
}
EOF

cat > tsconfig.json << 'EOF'
{ "compilerOptions": { "target": "ES2022", "module": "nodenext", "strict": true } }
EOF

mkdir -p src
cat > src/agent.js << 'EOF'
const Anthropic = require("@anthropic-ai/sdk");

const client = new Anthropic({
  apiKey: "sk-ant-api03-YzM2NjJhZDAtOWI0My00M2UwLWIzZTctMGZlZGQ4ZjE2NWUwLTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0",
});

// Google Maps key -- also grants Gemini access (scope drift)
const MAPS_KEY = "AIzaSyC8x4i-FaKe_Key12345678901234567890abc";

async function chat(message) {
  return client.messages.create({
    model: "claude-sonnet-4-5-20250929",
    max_tokens: 1024,
    messages: [{ role: "user", content: message }],
  });
}

module.exports = { chat, MAPS_KEY };
EOF

cat > src/aws.js << 'EOF'
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GH_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234";

module.exports = { AWS_KEY, GH_TOKEN };
EOF

# Claude Code detection stub (for shield init demo)
mkdir -p .claude
cat > .claude/settings.json << 'EOF'
{
  "permissions": {
    "allow": ["Read", "Write"],
    "deny": []
  }
}
EOF

cat > CLAUDE.md << 'EOF'
# ACME Agent

This is the ACME Corp AI agent project.
EOF

git add -A && git commit -m "Initial commit" --no-verify -q
echo "Lab ready: $LAB_DIR"
