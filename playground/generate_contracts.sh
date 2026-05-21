#!/bin/bash
# Generate contracts.js from examples/*.ark
# This creates an ES module exporting all example contracts as strings.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EXAMPLES_DIR="$PROJECT_DIR/examples"
OUTPUT="$SCRIPT_DIR/contracts.js"

echo "Generating contracts.js from examples/**/*.ark..."

node -e "
const fs = require('fs');
const path = require('path');
const dir = '$EXAMPLES_DIR';
const entries = [];

// Root-level .ark files
for (const f of fs.readdirSync(dir).sort()) {
  if (f.endsWith('.ark')) {
    entries.push({ name: f.replace('.ark', ''), file: path.join(dir, f) });
  }
}

// One level of subdirectories — each subdir becomes a namespace prefix
for (const d of fs.readdirSync(dir).sort()) {
  const subdir = path.join(dir, d);
  if (fs.statSync(subdir).isDirectory()) {
    for (const f of fs.readdirSync(subdir).sort()) {
      if (f.endsWith('.ark')) {
        entries.push({ name: d + '_' + f.replace('.ark', ''), file: path.join(subdir, f) });
      }
    }
  }
}

let out = '// Auto-generated from examples/**/*.ark — do not edit\n// Regenerate: ./playground/generate_contracts.sh\n\n';
for (const { name, file } of entries) {
  const code = fs.readFileSync(file, 'utf-8');
  out += 'export const ' + name + ' = ' + JSON.stringify(code) + ';\n\n';
}
fs.writeFileSync('$OUTPUT', out);
console.log('  Written ' + entries.length + ' contracts to contracts.js');
"
