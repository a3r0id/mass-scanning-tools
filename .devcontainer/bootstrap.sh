#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install -r requirements.txt pytest

echo "=== mst doctor ==="
mst doctor -y || true

echo "Dev container ready. Try: mst --help"
