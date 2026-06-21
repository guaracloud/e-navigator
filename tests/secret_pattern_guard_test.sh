#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

patterns=(
  "g""hp_"
  "docker""configjson"
  "docker""-password"
  "au""th""s"
  "\"""au""th""\""
  "E_NAVIGATOR""_GHCR_TOKEN"
)

excluded_paths=(
  ":(exclude)tests/secret_pattern_guard_test.sh"
)

for pattern in "${patterns[@]}"; do
  if git grep -n -F "$pattern" -- . "${excluded_paths[@]}"; then
    printf 'secret-like pattern found in tracked files: %s\n' "$pattern" >&2
    exit 1
  fi
done
