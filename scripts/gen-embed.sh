#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EMBED_DIR="$REPO_ROOT/embed"

mkdir -p "$EMBED_DIR"
cp "$REPO_ROOT/certs/ca/ca.crt" "$EMBED_DIR/ca.crt"

echo "embed/ populated"
