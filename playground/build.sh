#!/bin/bash
# Build script for Arkade Playground
# Build the compiler package and install its browser assets for the static playground.

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

echo "[1/3] Generating contracts.js from examples..."
"$SCRIPT_DIR/generate_contracts.sh"

echo "[2/3] Packing @arkade-os/compiler..."
cd "$PROJECT_DIR/npm"
npm ci
npm pack
COMPILER_VERSION="$(node -p "require('./package.json').version")"

echo "[3/3] Installing packed browser assets..."
rm -rf "$SCRIPT_DIR/pkg"
mkdir -p "$SCRIPT_DIR/pkg"
tar -xzf "arkade-os-compiler-$COMPILER_VERSION.tgz" -C "$SCRIPT_DIR/pkg" --strip-components=3 package/dist/browser
echo ""
echo "To serve the playground locally:"
echo "  cd playground && python3 -m http.server 8080"
echo ""
echo "Then open http://localhost:8080 in your browser."
