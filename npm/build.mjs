import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const directory = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(directory);
const manifest = JSON.parse(readFileSync(path.join(directory, 'package.json'), 'utf8'));
const metadata = JSON.parse(execFileSync('cargo', ['metadata', '--no-deps', '--format-version', '1', '--locked'], { cwd: root, encoding: 'utf8' }));
const compiler = metadata.packages.find(pkg => pkg.name === 'arkade-compiler');
assert.equal(manifest.version, compiler.version, 'npm package version must match the Rust compiler');

rmSync(path.join(directory, 'dist'), { recursive: true, force: true });
for (const [runtime, target, module] of [['node', 'nodejs', 'CommonJS'], ['browser', 'web', 'ES2022']]) {
    const destination = path.join(directory, 'dist', runtime);
    const wasm = path.join(destination, 'wasm');
    execFileSync('wasm-pack', ['build', root, '--release', '--target', target, '--out-dir', wasm, '--', '--locked', '--features', 'wasm'], { stdio: 'inherit' });
    for (const file of ['.gitignore', 'package.json', 'README.md', 'LICENSE']) {
        rmSync(path.join(wasm, file), { force: true });
    }
    execFileSync(process.execPath, ['node_modules/typescript/bin/tsc', 'src/index.ts', '--strict', '--target', 'ES2022', '--module', module, '--declaration', '--outDir', destination, '--noEmitOnError'], { cwd: directory, stdio: 'inherit' });
    copyFileSync(path.join(directory, 'src', runtime === 'node' ? 'node.cjs' : 'browser.js'), path.join(destination, 'runtime.js'));
    writeFileSync(path.join(destination, 'package.json'), JSON.stringify({ type: runtime === 'node' ? 'commonjs' : 'module' }) + '\n');
}
copyFileSync(path.join(root, 'LICENSE'), path.join(directory, 'LICENSE'));
