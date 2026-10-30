import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const directory = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(directory);
const dist = path.join(directory, 'dist');
const manifest = JSON.parse(readFileSync(path.join(directory, 'package.json'), 'utf8'));
const metadata = JSON.parse(execFileSync('cargo', ['metadata', '--no-deps', '--format-version', '1', '--locked'], { cwd: root, encoding: 'utf8' }));
const compiler = metadata.packages.find(pkg => pkg.name === 'arkade-compiler');
assert.equal(manifest.version, compiler.version, 'npm package version must match the Rust compiler');

rmSync(dist, { recursive: true, force: true });
const wasm = path.join(dist, 'wasm');
execFileSync('wasm-pack', ['build', root, '--release', '--target', 'web', '--out-dir', wasm, '--', '--locked', '--features', 'wasm'], { stdio: 'inherit' });
for (const file of ['.gitignore', 'package.json', 'README.md', 'LICENSE']) {
    rmSync(path.join(wasm, file), { force: true });
}
// Both runtimes share the wrapper and the WASM; only the loader each wrapper imports differs.
execFileSync(process.execPath, ['node_modules/typescript/bin/tsc', 'src/index.ts', '--strict', '--target', 'ES2022', '--module', 'ES2022', '--declaration', '--outDir', path.join(dist, 'browser'), '--noEmitOnError'], { cwd: directory, stdio: 'inherit' });
mkdirSync(path.join(dist, 'node'));
copyFileSync(path.join(dist, 'browser', 'index.js'), path.join(dist, 'node', 'index.js'));
for (const runtime of ['node', 'browser']) {
    copyFileSync(path.join(directory, 'src', `${runtime}.js`), path.join(dist, runtime, 'runtime.js'));
}
copyFileSync(path.join(root, 'LICENSE'), path.join(directory, 'LICENSE'));
