#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -x .venv/bin/python3 ]]; then
  echo "error: .venv not found. run: python3 -m venv .venv && .venv/bin/pip install pyyaml" >&2
  exit 1
fi

exec .venv/bin/python3 scripts/render.py "$@"
