#!/bin/bash
# Serve the Arkade Playground locally
# Usage: ./serve.sh [port]

PORT=${1:-8080}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Serving Arkade Playground at http://localhost:$PORT"
echo "Press Ctrl+C to stop"
echo ""

cd "$SCRIPT_DIR"
python3 -m http.server "$PORT"
