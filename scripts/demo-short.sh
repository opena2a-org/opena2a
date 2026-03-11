#!/bin/bash
# =============================================================================
# OpenA2A Short Demo (30 seconds -- social media clips)
#
# Record with:
#   asciinema rec demo-short.cast -c "bash scripts/demo-short.sh"
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
# Typing simulator
# ---------------------------------------------------------------------------
type_cmd() {
  local cmd="$1"
  printf '$ '
  for ((i = 0; i < ${#cmd}; i++)); do
    printf '%s' "${cmd:$i:1}"
    sleep 0.0$(( RANDOM % 4 + 4 ))
  done
  echo
  sleep 0.3
}

run_cmd() {
  type_cmd "$1"
  eval "$1"
  sleep "${2:-2}"
}

# ---------------------------------------------------------------------------
# Demo: scan -> protect -> status  (3 commands, 30 seconds)
# ---------------------------------------------------------------------------
clear
echo "# How secure is your AI agent setup?"
sleep 1.5

run_cmd "$CLI scan secure --ci --format text" 3

run_cmd "$CLI protect --dry-run --ci" 3

run_cmd "$CLI status --ci" 3

echo ""
echo "# Full AI agent security in 3 commands."
echo "# Install: npm install -g opena2a-cli"
echo "# Learn more: https://opena2a.org"
sleep 4
