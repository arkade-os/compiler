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
const diagnosticInput = {
    entry: 'main.ark',
    files: { 'main.ark': '// 🐴 café\r\ncontract Broken() { function spend() { require(missing); require(other); } }' },
};
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
    const unoptimized = await esm.compile(input, { optimize: false });
    const rawUnoptimized = JSON.parse(require(wasmPath).compile_sources_with_diagnostics(input.entry, JSON.stringify(input.files), false));
    assert.deepEqual(normalized(unoptimized), normalized({ ...JSON.parse(rawUnoptimized.artifact), warnings: rawUnoptimized.warnings }));
    assert.equal(unoptimized.compiler.options.optimize, false);
    assert.notEqual(unoptimized.fingerprint, artifact.fingerprint);
    const sourceSymbols = await esm.symbols(input);
    assert.deepEqual(sourceSymbols, JSON.parse(require(wasmPath).symbols(input.entry, JSON.stringify(input.files))));
    assert(sourceSymbols.symbols.some(symbol => symbol.name === 'Vault' && symbol.kind === 'contract'));
    assert(sourceSymbols.symbols.some(symbol => symbol.name === 'Policy' && symbol.file === 'shared/policy.ark'));
    assert(sourceSymbols.members.Fees.some(symbol => symbol.name === 'check' && symbol.type === undefined));
    const diagnostics = await esm.check(diagnosticInput);
    assert.deepEqual(diagnostics, JSON.parse(require(wasmPath).check(diagnosticInput.entry, JSON.stringify(diagnosticInput.files))));
    assert.equal(diagnostics.length, 2);
    for (const [index, diagnostic] of diagnostics.entries()) {
        assert.equal(diagnostic.severity, 'error');
        assert.equal(diagnostic.file, 'main.ark');
        assert.equal(diagnostic.code, 'validation');
        const bytes = Buffer.from(diagnosticInput.files['main.ark']);
        assert.equal(bytes.subarray(diagnostic.span.start, diagnostic.span.end).toString(), ['missing', 'other'][index]);
    }
    assert((await esm.check(input)).some(d => d.severity === 'warning' && d.message.includes('unused')));
    assert.deepEqual(await esm.check(standalone), []);
    assert.deepEqual(await esm.check({ entry: 'library.ark', files: { 'library.ark': 'library L { function yes() bool { return true; } }' } }), []);
    const importedDiagnostics = await esm.check({ entry: 'main.ark', files: {
        'main.ark': 'import "bad.ark"; contract C() { function spend() { require(true); } }',
        'bad.ark': 'library Bad { function bad() { require(missing); } }',
    } });
    assert(importedDiagnostics.some(d => d.file === 'bad.ark' && d.severity === 'error' && d.span));
    const [importedSyntax] = await esm.check({ entry: 'main.ark', files: {
        'main.ark': 'import "bad.ark"; contract C() { function spend() { require(true); } }',
        'bad.ark': '// é 🐴\nlibrary Broken(',
    } });
    assert.equal(importedSyntax.file, 'bad.ark');
    assert.equal(importedSyntax.severity, 'error');
    assert.equal(Buffer.from('// é 🐴\nlibrary Broken(').subarray(importedSyntax.span.start, importedSyntax.span.end).toString(), '(');
    for (const invalid of [invalidSource, { entry: '/main.ark', files: {} }, { entry: 'missing.ark', files: {} }]) {
        const [diagnostic] = await esm.check(invalid);
        assert.equal(diagnostic.severity, 'error');
        assert.equal(typeof diagnostic.message, 'string');
        assert(!Object.hasOwn(diagnostic, 'code'));
    }
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
        await assert.rejects(esm.symbols(bad), TypeError);
        await assert.rejects(esm.check(bad), TypeError);
    }
    for (const options of [null, true, [], { optimize: 'false' }, { optimize: 0 }]) {
        await assert.rejects(esm.compile(input, options), TypeError);
    }
    await assert.rejects(esm.compile(invalidSource), /Parse error/);
    await assert.rejects(esm.symbols(invalidSource), /Parse error/);
    await assert.rejects(esm.symbols({ entry: 'missing.ark', files: {} }), /not found/);
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
    const options = { optimize: false };
    const pendingOptions = esm.compile(input, options);
    options.optimize = true;
    assert.equal((await pendingOptions).compiler.options.optimize, false);
    for (const call of [esm.compile, esm.check, esm.symbols]) {
        let entryReads = 0, fileReads = 0, sourceReads = 0;
        const files = { get 'exit.ark'() { sourceReads++; return standalone.files['exit.ark']; } };
        await call({
            get entry() { return ++entryReads === 1 ? 'exit.ark' : 42; },
            get files() { return ++fileReads === 1 ? files : null; },
        });
        assert.deepEqual([entryReads, fileReads, sourceReads], [1, 1, 1]);
        await assert.rejects(call({ get entry() { return 42; }, files }), TypeError);
    }
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

    const typecheck = `import { compile, check, symbols, version, type CompileInput, type CompileOptions, type CompilerArtifact, type SourceSymbols, type Diagnostic } from '@arkade-os/compiler';
const input: CompileInput = { entry: 'main.ark', files: { 'main.ark': '' } };
const result: Promise<CompilerArtifact> = compile(input);
const options: CompileOptions = { optimize: false };
const detailed: Promise<CompilerArtifact> = compile(input, options);
const table: Promise<SourceSymbols> = symbols(input);
const diagnostics: Promise<Diagnostic[]> = check(input);
const compilerVersion: Promise<string> = version();
void result; void detailed; void table; void diagnostics; void compilerVersion;
// @ts-expect-error Source content must be a string.
compile({ entry: 'main.ark', files: { 'main.ark': 42 } });
// @ts-expect-error Optimization must be a boolean.
compile(input, { optimize: 'false' });
// @ts-expect-error Runtime source does not infer contract names.
const name: 'Vault' = (await compile(input)).contractName;
`;
    writeFileSync(path.join(temporary, 'consumer.mts'), typecheck);
    writeFileSync(path.join(temporary, 'consumer.cts'), typecheck.replace("(await compile(input)).contractName", "({} as CompilerArtifact).contractName"));
    const tsc = path.join(directory, 'node_modules/typescript/bin/tsc');
    run(process.execPath, [tsc, '--noEmit', '--strict', '--target', 'ES2022', '--module', 'NodeNext', 'consumer.mts', 'consumer.cts']);
    run(process.execPath, [tsc, '--noEmit', '--strict', '--target', 'ES2022', '--module', 'ESNext', '--moduleResolution', 'bundler', '--customConditions', 'browser', 'consumer.mts']);

    writeFileSync(path.join(temporary, 'index.html'), '<!doctype html><html lang="en"><title>Compiler test</title><script type="module" src="/main.js"></script></html>');
    writeFileSync(path.join(temporary, 'compiler-client.js'), readFileSync(path.join(directory, '../playground/compiler-client.js')));
    writeFileSync(path.join(temporary, 'compiler-worker.js'), readFileSync(path.join(directory, '../playground/compiler-worker.js'), 'utf8').replace("'./pkg/index.js'", "'@arkade-os/compiler'"));
    writeFileSync(path.join(temporary, 'main.js'), "import { compile, check, symbols, version } from '@arkade-os/compiler'; import * as workerCompiler from './compiler-client.js'; window.compiler = { compile, check, symbols, version }; window.workerCompiler = workerCompiler;\n");
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
        const [compilerVersion, sourceSymbols, ...artifacts] = await Promise.all([window.compiler.version(), window.compiler.symbols(input), ...Array.from({ length: 12 }, () => window.compiler.compile(input))]);
        return { compilerVersion, sourceSymbols, artifacts };
    }, input);
    assert.equal(browserResult.compilerVersion, manifest.version);
    assert.deepEqual(browserResult.sourceSymbols, sourceSymbols);
    for (const result of browserResult.artifacts) assert.deepEqual(normalized(result), normalized(artifact));
    assert.equal(requests.filter(url => url.endsWith('.wasm')).length, 1, 'concurrent browser initialization fetched WASM more than once');
    assert(requests.every(url => url.startsWith(server.resolvedUrls.local[0])), 'bundle fetched remote compiler assets');
    assert.deepEqual(normalized(await page.evaluate(input => window.compiler.compile(input), standalone)), normalized(exit));
    assert.deepEqual(normalized(await page.evaluate(input => window.compiler.compile(input, { optimize: false }), input)), normalized(unoptimized));
    const browserError = await page.evaluate(async input => {
        try { await window.compiler.compile(input); } catch (error) { return { name: error.name, message: error.message }; }
    }, invalidSource);
    assert.equal(browserError.name, 'Error');
    assert.match(browserError.message, /Parse error/);
    assert.deepEqual(await page.evaluate(input => window.compiler.check(input), diagnosticInput), diagnostics);
    const bundledWorker = await page.evaluate(async ({ input, diagnosticInput }) => ({
        artifact: await window.workerCompiler.compile(input),
        diagnostics: await window.workerCompiler.check(diagnosticInput),
        symbols: await window.workerCompiler.symbols(input),
        version: await window.workerCompiler.version(),
    }), { input, diagnosticInput });
    assert.deepEqual(normalized(bundledWorker.artifact), normalized(artifact));
    assert.deepEqual(bundledWorker.diagnostics, diagnostics);
    assert.deepEqual(bundledWorker.symbols, sourceSymbols);
    assert.equal(bundledWorker.version, manifest.version);

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

    const nativeUrl = `${server.resolvedUrls.local[0]}pr-previews/pr-1/`;
    const nativeContext = await browser.newContext();
    const nativePage = await nativeContext.newPage();
    await nativeContext.route(`${nativeUrl}**`, route => {
        const file = route.request().url().slice(nativeUrl.length);
        if (!file || file === 'worker.html') {
            const entry = file ? './compiler-client.js' : './pkg/index.js';
            return route.fulfill({ contentType: 'text/html', body: `<!doctype html><script type="module">import * as compiler from '${entry}'; window.compiler = compiler;</script>` });
        }
        if (['compiler-client.js', 'compiler-worker.js'].includes(file)) {
            return route.fulfill({ contentType: 'text/javascript', body: readFileSync(path.join(directory, '../playground', file)) });
        }
        assert(file.startsWith('pkg/'), `unexpected native browser asset: ${file}`);
        return route.fulfill({
            contentType: file.endsWith('.wasm') ? 'application/wasm' : 'text/javascript',
            body: readFileSync(path.join(temporary, 'node_modules/@arkade-os/compiler/dist/browser', file.slice(4))),
        });
    });
    await nativePage.goto(nativeUrl);
    await nativePage.waitForFunction(() => window.compiler);
    const nativeResult = await nativePage.evaluate(async input => ({
        artifact: await window.compiler.compile(input, { optimize: false }),
        symbols: await window.compiler.symbols(input),
        version: await window.compiler.version(),
    }), input);
    assert.deepEqual(normalized(nativeResult.artifact), normalized(unoptimized));
    assert.deepEqual(nativeResult.symbols, sourceSymbols);
    assert.equal(nativeResult.version, manifest.version);

    const workerPage = await nativeContext.newPage();
    await workerPage.goto(`${nativeUrl}worker.html`);
    await workerPage.waitForFunction(() => window.compiler);
    const wasmUrl = `${nativeUrl}pkg/wasm/arkade_compiler_bg.wasm`;
    await nativeContext.route(wasmUrl, route => route.abort('failed'));
    const workerFailure = await workerPage.evaluate(async () => {
        try { await window.compiler.version(); } catch (error) { return { name: error.name, message: error.message }; }
    });
    assert.equal(workerFailure.name, 'TypeError');
    assert.match(workerFailure.message, /fetch/i);
    await nativeContext.unroute(wasmUrl);
    const workerResult = await workerPage.evaluate(async ({ input, diagnosticInput }) => {
        const [artifact, symbols, diagnostics, version] = await Promise.all([
            window.compiler.compile(input, { optimize: false }), window.compiler.symbols(input),
            window.compiler.check(diagnosticInput), window.compiler.version(),
        ]);
        return { artifact, symbols, diagnostics, version };
    }, { input, diagnosticInput });
    assert.deepEqual(normalized(workerResult.artifact), normalized(unoptimized));
    assert.deepEqual(workerResult.symbols, sourceSymbols);
    assert.deepEqual(workerResult.diagnostics, diagnostics);
    assert.equal(workerResult.version, manifest.version);
    const workerSourceError = await workerPage.evaluate(async input => {
        try { await window.compiler.compile(input); } catch (error) { return { name: error.name, message: error.message }; }
    }, invalidSource);
    assert.equal(workerSourceError.name, 'Error');
    assert.match(workerSourceError.message, /Parse error/);
    const ticks = await workerPage.evaluate(async input => {
        let ticks = 0;
        const timer = setInterval(() => ticks++, 0);
        try { await Promise.all(Array.from({ length: 80 }, () => window.compiler.compile(input))); }
        finally { clearInterval(timer); }
        return ticks;
    }, input);
    assert(ticks > 0, 'compiler work blocked the browser event loop');
    const cloneFailure = await workerPage.evaluate(async () => {
        try { await window.compiler.compile(() => {}); } catch (error) { return error.name; }
    });
    assert.equal(cloneFailure, 'DataCloneError');
    assert.equal(await workerPage.evaluate(() => window.compiler.version()), manifest.version);

    // A worker script failure rejects every pending call and allows a new worker.
    const restartPage = await nativeContext.newPage();
    await nativeContext.route(`${nativeUrl}compiler-worker.js`, route => route.fulfill({ contentType: 'text/javascript', body: "throw new Error('Worker startup failed deliberately');" }));
    await restartPage.goto(`${nativeUrl}worker.html`);
    await restartPage.waitForFunction(() => window.compiler);
    const failures = await restartPage.evaluate(async () => {
        const results = await Promise.allSettled([window.compiler.version(), window.compiler.version()]);
        return results.map(result => ({ status: result.status, message: result.reason?.message }));
    });
    assert(failures.every(result => result.status === 'rejected' && result.message.includes('Worker startup failed deliberately')));
    await nativeContext.unroute(`${nativeUrl}compiler-worker.js`);
    assert.equal(await restartPage.evaluate(() => window.compiler.version()), manifest.version);
    console.log(`Packed @arkade-os/compiler ${manifest.version}: Node ESM/CommonJS, declarations, diagnostics, browser bundle, and playground worker passed.`);
} finally {
    await browser?.close();
    await new Promise(resolve => server ? server.httpServer.close(resolve) : resolve());
    rmSync(temporary, { recursive: true, force: true });
}
