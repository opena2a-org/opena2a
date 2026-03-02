#!/usr/bin/env bash
# Push monorepo subtree changes back to standalone repos.
# Usage: ./scripts/mirror-downstream.sh [package-name]
#
# If no package name given, mirrors all packages.

set -euo pipefail

REPOS=(
  "hackmyagent:https://github.com/opena2a-org/hackmyagent.git"
  "secretless:https://github.com/opena2a-org/secretless.git"
  "arp:https://github.com/opena2a-org/arp.git"
  "oasb:https://github.com/opena2a-org/oasb.git"
  "ai-trust:https://github.com/opena2a-org/ai-trust.git"
  "trust-gate:https://github.com/opena2a-org/trust-gate.git"
)

TARGET="${1:-all}"

for entry in "${REPOS[@]}"; do
  IFS=':' read -r name url <<< "$entry"

  if [ "$TARGET" != "all" ] && [ "$TARGET" != "$name" ]; then
    continue
  fi

  prefix="packages/${name}"

  if [ ! -d "$prefix" ]; then
    echo "Skipping $name -- $prefix does not exist"
    continue
  fi

  echo "Pushing $prefix to $url main..."
  git subtree push --prefix="$prefix" "$url" main
  echo "Done: $name"
done
