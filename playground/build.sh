#!/bin/bash
# Build script for Arkade Playground
# This script compiles the Rust compiler to WASM and sets up the playground

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Arkade Playground Build ==="
echo ""

# Check for wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "Error: wasm-pack is not installed."
    echo "Install it with: cargo install wasm-pack"
    echo "Or: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
    exit 1
fi

# Generate contracts.js from examples/*.ark
echo "[1/4] Generating contracts.js from examples..."
"$SCRIPT_DIR/generate_contracts.sh"

# Build WASM package
echo "[2/4] Building WASM package..."
cd "$PROJECT_DIR"
wasm-pack build --target web --out-dir playground/pkg --features wasm

# Clean up unnecessary files
echo "[3/4] Cleaning up..."
rm -f playground/pkg/.gitignore
rm -f playground/pkg/package.json
rm -f playground/pkg/README.md

# Done
echo "[4/4] Build complete!"
echo ""
echo "To serve the playground locally:"
echo "  cd playground && python3 -m http.server 8080"
echo ""
echo "Then open http://localhost:8080 in your browser."
