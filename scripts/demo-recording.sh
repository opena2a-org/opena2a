#!/bin/bash
# =============================================================================
# OpenA2A Demo Recording Script (full -- ~3 minutes)
#
# Record with:
#   asciinema rec demo.cast -c "bash scripts/demo-recording.sh"
#
# Prerequisites:
#   brew install asciinema
#   npm install -g opena2a-cli
#
# Before recording, run:
#   source scripts/demo-setup.sh && cd "$DEMO_DIR"
# =============================================================================
set -e

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI="${OPENA2A_CLI:-opena2a}"

# If DEMO_DIR is not set, create a temp project on the fly
if [ -z "$DEMO_DIR" ]; then
  source "$SCRIPT_DIR/demo-setup.sh"
  cd "$DEMO_DIR"
fi

# ---------------------------------------------------------------------------
# Typing simulator -- types each character with realistic jitter
# ---------------------------------------------------------------------------
type_cmd() {
  local cmd="$1"
  printf '$ '
  for ((i = 0; i < ${#cmd}; i++)); do
    printf '%s' "${cmd:$i:1}"
    sleep 0.0$(( RANDOM % 4 + 4 ))   # 40-70 ms per character
  done
  echo
  sleep 0.3
}

# Pause between scenes with a comment
scene() {
  echo ""
  echo "# $1"
  sleep 1.5
}

# Run a command after typing it
run_cmd() {
  type_cmd "$1"
  eval "$1"
  sleep "${2:-2}"
}

# ---------------------------------------------------------------------------
# Scene 1: Orientation (10s)
# ---------------------------------------------------------------------------
clear
echo "# OpenA2A -- Open-source security platform for AI agents"
echo "# https://opena2a.org"
sleep 2

scene "What can opena2a do?"
run_cmd "$CLI --help" 3

# ---------------------------------------------------------------------------
# Scene 2: Initialize security (30s)
# ---------------------------------------------------------------------------
scene "Step 1: Initialize security for this AI agent project"
run_cmd "$CLI init --ci" 3

# ---------------------------------------------------------------------------
# Scene 3: MCP Audit (30s)
# ---------------------------------------------------------------------------
scene "Step 2: Audit MCP server configurations"
run_cmd "$CLI mcp audit --ci" 3

# ---------------------------------------------------------------------------
# Scene 4: Security Scan (30s)
# ---------------------------------------------------------------------------
scene "Step 3: Run a full security scan"
run_cmd "$CLI scan secure --ci" 4

# ---------------------------------------------------------------------------
# Scene 5: Governance Scan (20s)
# ---------------------------------------------------------------------------
scene "Step 4: Check governance file coverage"
run_cmd "$CLI scan-soul --ci" 3

# ---------------------------------------------------------------------------
# Scene 6: Protect Credentials (20s)
# ---------------------------------------------------------------------------
scene "Step 5: Detect hardcoded credentials"
run_cmd "$CLI protect --dry-run --ci" 3

# ---------------------------------------------------------------------------
# Scene 7: Sign Configs (15s)
# ---------------------------------------------------------------------------
scene "Step 6: Sign config files for tamper detection"
run_cmd "$CLI guard sign --ci" 2

# ---------------------------------------------------------------------------
# Scene 8: Identity (15s)
# ---------------------------------------------------------------------------
scene "Step 7: Create a cryptographic identity for this agent"
run_cmd "$CLI identity create --name demo-agent --ci" 2

# ---------------------------------------------------------------------------
# Scene 9: Final Status (15s)
# ---------------------------------------------------------------------------
scene "Step 8: Check overall security posture"
run_cmd "$CLI status --ci" 3

# ---------------------------------------------------------------------------
# Outro
# ---------------------------------------------------------------------------
echo ""
echo "# -------------------------------------------------------"
echo "# Secure your AI agents in minutes."
echo "#"
echo "#   Install:  npm install -g opena2a-cli"
echo "#   Docs:     https://opena2a.org/docs"
echo "#   GitHub:   https://github.com/opena2a-org/opena2a"
echo "# -------------------------------------------------------"
sleep 5
