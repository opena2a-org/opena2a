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
  apiKey: "sk-ant-api03-FAKE-xJ7kQ9mN2vL5pR8wT3y",
});

// Google Maps key -- also grants Gemini access (scope drift)
const MAPS_KEY = "AIzaSyFAKE-dG7hK9mN2vL5pR8wT3yXz";

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
const AWS_KEY = "AKIAFAKE7K9MN2VL5PR8";
const AWS_SECRET = "wT3yXzFAKEsecretkey9mN2vL5pR8wT3yXz1234";
const GH_TOKEN = "ghp_FAKE7k9mN2vL5pR8wT3yXzAbCdEf123456";

module.exports = { AWS_KEY, AWS_SECRET, GH_TOKEN };
EOF

cat > src/config.js << 'EOF'
// Database connection with embedded password
const DB_URL = "postgresql://admin:FAKE_p4ssw0rd_demo@db.acme.internal:5432/agents";
const OPENAI_KEY = "sk-FAKE-proj-xJ7kQ9mN2vL5pR8wT3yXzAbCdEf";
const STRIPE_KEY = "sk_live_FAKE_51234567890abcdefghijklmnop";

module.exports = { DB_URL, OPENAI_KEY, STRIPE_KEY };
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
