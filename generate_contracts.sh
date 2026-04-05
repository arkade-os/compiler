#!/bin/bash
# Generate contracts.js from examples/*.ark
# This creates an ES module exporting all example contracts as strings.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EXAMPLES_DIR="$PROJECT_DIR/examples"
OUTPUT="$SCRIPT_DIR/contracts.js"

echo "Generating contracts.js from examples/*.ark..."

node -e "
const fs = require('fs');
const path = require('path');
const dir = '$EXAMPLES_DIR';
const files = fs.readdirSync(dir).filter(f => f.endsWith('.ark')).sort();
let out = '// Auto-generated from examples/*.ark — do not edit\n// Regenerate: ./playground/generate_contracts.sh\n\n';
for (const f of files) {
  const name = f.replace('.ark', '');
  const code = fs.readFileSync(path.join(dir, f), 'utf-8');
  out += 'export const ' + name + ' = ' + JSON.stringify(code) + ';\n\n';
}
fs.writeFileSync('$OUTPUT', out);
console.log('  Written ' + files.length + ' contracts to contracts.js');
"
