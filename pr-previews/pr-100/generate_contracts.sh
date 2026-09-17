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
const root = '$EXAMPLES_DIR';

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.isFile() && entry.name.endsWith('.ark')) out.push(full);
  }
  return out;
}

const files = walk(root).sort();
let out = '// Auto-generated from examples/**/*.ark — do not edit\n// Regenerate: ./playground/generate_contracts.sh\n\n';
for (const full of files) {
  const name = path.basename(full, '.ark');
  const code = fs.readFileSync(full, 'utf-8');
  out += 'export const ' + name + ' = ' + JSON.stringify(code) + ';\n\n';
}
fs.writeFileSync('$OUTPUT', out);
console.log('  Written ' + files.length + ' contracts to contracts.js');
"
