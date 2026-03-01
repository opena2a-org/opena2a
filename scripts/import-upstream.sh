#!/usr/bin/env bash
# Import upstream repos as subtrees into the monorepo.
# Usage: ./scripts/import-upstream.sh
#
# This is a one-time operation for initial setup.
# After import, use mirror.yml to sync changes downstream.

set -euo pipefail

REPOS=(
  "hackmyagent:https://github.com/opena2a-org/hackmyagent.git"
  "secretless:https://github.com/opena2a-org/secretless.git"
  "arp:https://github.com/opena2a-org/arp.git"
  "oasb:https://github.com/opena2a-org/oasb.git"
  "ai-trust:https://github.com/opena2a-org/ai-trust.git"
  "trust-gate:https://github.com/opena2a-org/trust-gate.git"
)

for entry in "${REPOS[@]}"; do
  IFS=':' read -r name url <<< "$entry"
  prefix="packages/${name}"

  if [ -d "$prefix" ] && [ "$(ls -A "$prefix")" ]; then
    echo "Skipping $name -- $prefix already exists and is non-empty"
    continue
  fi

  echo "Importing $name from $url into $prefix..."
  git subtree add --prefix="$prefix" "$url" main --squash -m "Import $name as subtree"
  echo "Done: $name"
done

echo ""
echo "All imports complete. Run 'npm install' to set up workspaces."
