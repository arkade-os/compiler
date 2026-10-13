import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { build, preview } from 'vite';

const directory = path.dirname(fileURLToPath(import.meta.url));
const temporary = mkdtempSync(path.join(tmpdir(), 'arkade-compiler-package-'));
const manifest = JSON.parse(readFileSync(path.join(directory, 'package.json'), 'utf8'));
const input = {
    entry: 'contracts/main.ark',
    files: {
        'contracts/main.ark': `import "../shared/policy.ark";
contract Vault(Policy policy, pubkey backupKey, int unused) {
    function spend(Policy next, int[2] values, signature sig) {
        Fees.check(values[0]);
        require(next.limits[1] >= policy.limits[0] + values[1]);
        require(checkSig(sig, policy.owner));
    }
    function backup(signature sig) tapscript {
        require(older(blocks(12)));
        require(checkSig(sig, tweak(backupKey, spend)));
    }
    function unilateral(signature sig) tapscript {
        require(older(serverExitDelay));
        require(checkSig(sig, policy.owner));
    }
}`,
        'shared/policy.ark': `struct Policy { pubkey owner; int[2] limits; }
library Fees { function check(int amount) { require(amount >= 1); } }`,
        'unused.ark': 'not loaded',
    },
};
const standalone = {
    entry: 'exit.ark',
    files: { 'exit.ark': 'contract Exit(pubkey owner) { function exit(signature sig) tapscript { require(older(serverExitDelay)); require(checkSig(sig, owner)); } }' },
};
const invalidSource = { entry: 'main.ark', files: { 'main.ark': 'contract Broken(' } };
function normalized(artifact) {
    const { updatedAt, ...stable } = artifact;
    return stable;
}
function run(command, args, cwd = temporary) {
    return execFileSync(command, args, { cwd, encoding: 'utf8', stdio: ['pipe', 'pipe', 'inherit'], env: { ...process.env, npm_config_cache: path.join(temporary, 'npm-cache') } });
}

let browser;
let server;
try {
    const [packed] = JSON.parse(run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', temporary], directory));
    const contents = packed.files.map(file => file.path);
    for (const runtime of ['node', 'browser']) {
        for (const file of ['index.js', 'index.d.ts', 'runtime.js', 'wasm/arkade_compiler.js', 'wasm/arkade_compiler.d.ts', 'wasm/arkade_compiler_bg.wasm']) {
            assert(contents.includes(`dist/${runtime}/${file}`), `packed package missing ${runtime}/${file}`);
        }
    }
    assert(contents.includes('LICENSE') && contents.includes('README.md'));
    assert(contents.every(file => file.startsWith('dist/') || ['package.json', 'LICENSE', 'README.md'].includes(file)));
    assert.equal(manifest.dependencies, undefined);
    for (const lifecycle of ['preinstall', 'install', 'postinstall', 'prepare']) {
        assert.equal(manifest.scripts[lifecycle], undefined);
    }
    writeFileSync(path.join(temporary, 'package.json'), '{"private":true,"type":"module"}\n');
    run('npm', ['install', '--offline', '--no-audit', '--no-fund', path.join(temporary, packed.filename)]);
    const require = createRequire(path.join(temporary, 'package.json'));
    const entry = require.resolve('@arkade-os/compiler');
    const wasmPath = path.join(path.dirname(entry), 'wasm/arkade_compiler.js');
    const commonjs = require('@arkade-os/compiler');
    const esm = await import(pathToFileURL(entry).href);
    assert.equal(esm.compile, commonjs.compile);
    assert.equal(require.cache[wasmPath], undefined, 'importing the package initializes WASM');
    const [artifact, compilerVersion, ...concurrent] = await Promise.all([
        esm.compile(input), commonjs.version(), ...Array.from({ length: 12 }, () => commonjs.compile(input)),
    ]);
    assert.equal(compilerVersion, manifest.version);
    assert.equal(artifact.compiler.version, manifest.version);
    assert.deepEqual(artifact.compiler.options, { optimize: true });
    for (const result of concurrent) assert.deepEqual(normalized(result), normalized(artifact));
    const raw = JSON.parse(require(wasmPath).compile_sources_with_diagnostics(input.entry, JSON.stringify(input.files)));
    assert.deepEqual(normalized(artifact), normalized({ ...JSON.parse(raw.artifact), warnings: raw.warnings }));
    assert.match(artifact.fingerprint, /^sha256:[0-9a-f]{64}$/);
    assert.equal(artifact.formatVersion, 1);
    assert(artifact.warnings.some(warning => warning.includes("constructor parameter 'unused'")));
    assert.deepEqual(artifact.constructorInputs, [{ name: 'policy', type: 'Policy' }, { name: 'backupKey', type: 'pubkey' }, { name: 'unused', type: 'int' }]);
    assert.deepEqual(artifact.structs, [{ name: 'Policy', fields: [{ name: 'owner', type: 'pubkey' }, { name: 'limits', type: 'int[2]' }] }]);
    assert.deepEqual(artifact.source, { entry: input.entry, files: { 'contracts/main.ark': input.files['contracts/main.ark'], 'shared/policy.ark': input.files['shared/policy.ark'] } });
    const spend = artifact.functions.find(group => group.name === 'spend');
    assert.deepEqual(spend.leaves.map(leaf => leaf.name), ['spend', 'backup']);
    assert.deepEqual(spend.arkade.inputs, [{ name: 'next', type: 'Policy' }, { name: 'values', type: 'int[2]' }, { name: 'sig', type: 'signature' }]);
    assert.deepEqual(spend.leaves[0].witness.map(field => [field.name, field.injected]), [['serverSig', true], ['emulatorSig', true]]);
    assert(spend.leaves[0].asm.includes('<EMULATOR_KEY:spend>'));
    assert(spend.leaves[1].asm.some(token => token.includes('spend')));
    const exit = await esm.compile(standalone);
    assert.equal(exit.functions.length, 1);
    assert.equal(exit.functions[0].arkade, undefined);
    assert.deepEqual(exit.functions[0].leaves[0].witness, [{ name: 'sig', type: 'signature', encoding: 'schnorr-64' }]);
    assert.deepEqual(exit.warnings, []);
    assert.deepEqual(normalized(await esm.compile(artifact.source)), normalized(artifact));
    for (const bad of [null, {}, Object.assign([], standalone), { entry: 1, files: {} }, { entry: 'main.ark', files: [] }, { entry: 'main.ark', files: { 'main.ark': 1 } }]) {
        await assert.rejects(esm.compile(bad), TypeError);
    }
    await assert.rejects(esm.compile(invalidSource), /Parse error/);
    await assert.rejects(esm.compile({ ...input, files: { 'contracts/main.ark': input.files['contracts/main.ark'] } }), /policy\.ark.*not found/);
    await assert.rejects(esm.compile({ entry: '../main.ark', files: {} }), /escapes the source root/);
    await assert.rejects(esm.compile({ entry: '/main.ark', files: {} }), /relative \.ark path/);
    await assert.rejects(esm.compile({ entry: '/main.ark', files: { '/main.ark': standalone.files['exit.ark'] } }), /relative \.ark path/);
    await assert.rejects(esm.compile({ entry: 'main.ark', files: { 'main.ark': standalone.files['exit.ark'], '/extra.ark': '' } }), /relative \.ark path/);
    await assert.rejects(esm.compile({ entry: 'main.ark', files: { 'main.ark': 'import "/extra.ark"; contract C() { function spend() { require(true); } }' } }), /relative \.ark path/);
    await assert.rejects(esm.compile({ entry: 'main.ark', files: { 'main.ark': standalone.files['exit.ark'], './main.ark': standalone.files['exit.ark'] } }), /duplicate source path/);
    const snapshot = structuredClone(standalone);
    const pending = esm.compile(snapshot);
    snapshot.entry = 'missing.ark';
    snapshot.files['exit.ark'] = 'invalid';
    assert.equal((await pending).contractName, 'Exit');
    run(process.execPath, ['--input-type=module', '-e', `
        import assert from 'node:assert/strict';
        import { compile } from '@arkade-os/compiler';
        const original = WebAssembly.Module;
        const failure = new Error('WASM initialization failed deliberately');
        WebAssembly.Module = function () { throw failure; };
        await assert.rejects(compile(${JSON.stringify(standalone)}), error => error === failure);
        WebAssembly.Module = original;
        assert.equal((await compile(${JSON.stringify(standalone)})).contractName, 'Exit');
    `]);

    const typecheck = `import { compile, version, type CompileInput, type CompilerArtifact } from '@arkade-os/compiler';
const input: CompileInput = { entry: 'main.ark', files: { 'main.ark': '' } };
const result: Promise<CompilerArtifact> = compile(input);
const compilerVersion: Promise<string> = version();
void result; void compilerVersion;
// @ts-expect-error Source content must be a string.
compile({ entry: 'main.ark', files: { 'main.ark': 42 } });
// @ts-expect-error Runtime source does not infer contract names.
const name: 'Vault' = (await compile(input)).contractName;
`;
    writeFileSync(path.join(temporary, 'consumer.mts'), typecheck);
    writeFileSync(path.join(temporary, 'consumer.cts'), typecheck.replace("(await compile(input)).contractName", "({} as CompilerArtifact).contractName"));
    const tsc = path.join(directory, 'node_modules/typescript/bin/tsc');
    run(process.execPath, [tsc, '--noEmit', '--strict', '--target', 'ES2022', '--module', 'NodeNext', 'consumer.mts', 'consumer.cts']);
    run(process.execPath, [tsc, '--noEmit', '--strict', '--target', 'ES2022', '--module', 'ESNext', '--moduleResolution', 'bundler', '--customConditions', 'browser', 'consumer.mts']);

    writeFileSync(path.join(temporary, 'index.html'), '<!doctype html><html lang="en"><title>Compiler test</title><script type="module" src="/main.js"></script></html>');
    writeFileSync(path.join(temporary, 'main.js'), "import { compile, version } from '@arkade-os/compiler'; window.compiler = { compile, version };\n");
    await build({ root: temporary, configFile: false, logLevel: 'warn', base: '/compiler-test/', build: { assetsInlineLimit: 0 } });
    assert(readdirSync(path.join(temporary, 'dist/assets')).some(file => file.endsWith('.wasm')), 'browser bundle missing WASM');
    server = await preview({ root: temporary, configFile: false, logLevel: 'warn', base: '/compiler-test/', preview: { host: '127.0.0.1', port: 0 } });
    browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL });
    const page = await browser.newPage();
    const requests = [];
    page.on('request', request => requests.push(request.url()));
    await page.goto(server.resolvedUrls.local[0]);
    await page.waitForFunction(() => window.compiler);
    assert.equal(requests.filter(url => url.endsWith('.wasm')).length, 0, 'browser import initializes WASM eagerly');
    const browserResult = await page.evaluate(async input => {
        const [compilerVersion, ...artifacts] = await Promise.all([window.compiler.version(), ...Array.from({ length: 12 }, () => window.compiler.compile(input))]);
        return { compilerVersion, artifacts };
    }, input);
    assert.equal(browserResult.compilerVersion, manifest.version);
    for (const result of browserResult.artifacts) assert.deepEqual(normalized(result), normalized(artifact));
    assert.equal(requests.filter(url => url.endsWith('.wasm')).length, 1, 'concurrent browser initialization fetched WASM more than once');
    assert(requests.every(url => url.startsWith(server.resolvedUrls.local[0])), 'bundle fetched remote compiler assets');
    assert.deepEqual(normalized(await page.evaluate(input => window.compiler.compile(input), standalone)), normalized(exit));
    const browserError = await page.evaluate(async input => {
        try { await window.compiler.compile(input); } catch (error) { return { name: error.name, message: error.message }; }
    }, invalidSource);
    assert.equal(browserError.name, 'Error');
    assert.match(browserError.message, /Parse error/);

    const failedPage = await browser.newPage();
    await failedPage.route('**/*.wasm', route => route.abort('failed'));
    await failedPage.goto(server.resolvedUrls.local[0]);
    await failedPage.waitForFunction(() => window.compiler);
    const initializationError = await failedPage.evaluate(async input => {
        try { await window.compiler.compile(input); } catch (error) { return { name: error.name, message: error.message }; }
    }, standalone);
    assert.equal(initializationError.name, 'TypeError');
    assert.match(initializationError.message, /fetch/i);
    await failedPage.unroute('**/*.wasm');
    assert.equal((await failedPage.evaluate(input => window.compiler.compile(input), standalone)).contractName, 'Exit');
    console.log(`Packed @arkade-os/compiler ${manifest.version}: Node ESM/CommonJS, declarations, and Chromium browser bundle passed.`);
} finally {
    await browser?.close();
    await new Promise(resolve => server ? server.httpServer.close(resolve) : resolve());
    rmSync(temporary, { recursive: true, force: true });
}
