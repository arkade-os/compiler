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
    const [result, compilerVersion, ...concurrent] = await Promise.all([
        esm.compile(input), commonjs.version(), ...Array.from({ length: 12 }, () => commonjs.compile(input)),
    ]);
    const { artifact } = result;
    const wasm = require(wasmPath);
    const files = JSON.stringify(input.files);
    assert.equal(compilerVersion, manifest.version);
    assert.equal(artifact.compiler.version, manifest.version);
    assert.deepEqual(artifact.compiler.options, { optimize: true });
    for (const other of concurrent) assert.deepEqual(normalized(other.artifact), normalized(artifact));
    const raw = JSON.parse(wasm.compile_sources_with_diagnostics(input.entry, files));
    assert.deepEqual(normalized(artifact), normalized(JSON.parse(raw.artifact)));
    assert.deepEqual(result.debug, JSON.parse(raw.debug));
    assert.deepEqual(result.diagnostics, raw.diagnostics);
    assert.deepEqual(Object.keys(result).sort(), ['artifact', 'debug', 'diagnostics']);
    assert.equal(result.debug.artifactFingerprint, artifact.fingerprint);
    assert(result.debug.functions.spend.sourceMap.length > 0);
    const unoptimized = (await esm.compile(input, { optimize: false })).artifact;
    const rawUnoptimized = JSON.parse(wasm.compile_sources_with_diagnostics(input.entry, files, false));
    assert.deepEqual(normalized(unoptimized), normalized(JSON.parse(rawUnoptimized.artifact)));
    assert.equal(unoptimized.compiler.options.optimize, false);
    assert.notEqual(unoptimized.fingerprint, artifact.fingerprint);
    const position = { line: 6, column: 27 };
    const symbol = await esm.symbolAt(input, position);
    assert.deepEqual(symbol, JSON.parse(wasm.symbol_at(input.entry, files, position.line, position.column)));
    assert.deepEqual([symbol.name, symbol.kind, symbol.type], ['sig', 'parameter', 'signature']);
    assert.deepEqual(symbol.definition, { file: input.entry, start: { line: 3, column: 58 }, end: { line: 3, column: 61 } });
    assert.equal(symbol.references.length, 1);
    assert.equal(await esm.symbolAt(input, { line: 1, column: 1 }), null);
    const completions = await esm.completionsAt(input, { line: 4, column: 1 });
    assert.deepEqual(completions, JSON.parse(wasm.completions_at(input.entry, files, 4, 1)));
    assert(completions.symbols.some(symbol => symbol.name === 'values' && symbol.type === 'int[2]'));
    assert.deepEqual(completions.members.Fees, [{ name: 'check', kind: 'function', type: null }]);
    assert.deepEqual(completions.structs, [{ name: 'Policy', fields: [{ name: 'owner', type: 'pubkey' }, { name: 'limits', type: 'int[2]' }] }]);
    assert.deepEqual(await esm.completionsAt({ entry: 'missing.ark', files: {} }, { line: 1, column: 1 }), { symbols: [], structs: [], members: {} });
    const diagnostics = await esm.check(diagnosticInput);
    assert.deepEqual(diagnostics, JSON.parse(wasm.check_sources(diagnosticInput.entry, JSON.stringify(diagnosticInput.files))));
    assert.equal(diagnostics.length, 2);
    const diagnosticLine = diagnosticInput.files['main.ark'].split('\r\n')[1];
    for (const [index, diagnostic] of diagnostics.entries()) {
        const name = ['missing', 'other'][index];
        assert.equal(diagnostic.severity, 'error');
        assert.equal(diagnostic.file, 'main.ark');
        assert.equal(diagnostic.code, 'validation');
        assert.deepEqual(diagnostic.start, { line: 2, column: diagnosticLine.indexOf(name) + 1 });
        assert.deepEqual(diagnostic.end, { line: 2, column: diagnosticLine.indexOf(name) + 1 + name.length });
    }
    assert((await esm.check(input)).some(d => d.severity === 'warning' && d.message.includes('unused')));
    assert.deepEqual(await esm.check(standalone), []);
    assert.deepEqual(await esm.check({ entry: 'library.ark', files: { 'library.ark': 'library L { function yes() bool { return true; } }' } }), []);
    const importedDiagnostics = await esm.check({ entry: 'main.ark', files: {
        'main.ark': 'import "bad.ark"; contract C() { function spend() { require(true); } }',
        'bad.ark': 'library Bad { function bad() { require(missing); } }',
    } });
    assert(importedDiagnostics.some(d => d.file === 'bad.ark' && d.severity === 'error' && d.start));
    const [importedSyntax] = await esm.check({ entry: 'main.ark', files: {
        'main.ark': 'import "bad.ark"; contract C() { function spend() { require(true); } }',
        'bad.ark': '// é 🐴\nlibrary Broken(',
    } });
    assert.equal(importedSyntax.file, 'bad.ark');
    assert.equal(importedSyntax.severity, 'error');
    assert.deepEqual(importedSyntax.start, { line: 2, column: 15 });
    for (const invalid of [invalidSource, { entry: '/main.ark', files: {} }, { entry: 'missing.ark', files: {} }]) {
        const [diagnostic] = await esm.check(invalid);
        assert.equal(diagnostic.severity, 'error');
        assert.equal(typeof diagnostic.message, 'string');
        assert.equal(diagnostic.code, null);
    }
    assert.match(artifact.fingerprint, /^sha256:[0-9a-f]{64}$/);
    assert.equal(artifact.formatVersion, 1);
    assert(!Object.hasOwn(artifact, 'warnings'));
    assert(result.diagnostics.some(d => d.severity === 'warning' && d.message.includes("constructor parameter 'unused'")));
    assert.deepEqual(artifact.constructorInputs, [{ name: 'policy', type: 'Policy' }, { name: 'backupKey', type: 'pubkey' }, { name: 'unused', type: 'int' }]);
    assert.deepEqual(artifact.structs, [{ name: 'Policy', fields: [{ name: 'owner', type: 'pubkey' }, { name: 'limits', type: 'int[2]' }] }]);
    assert.deepEqual(artifact.source, { entry: input.entry, files: { 'contracts/main.ark': input.files['contracts/main.ark'], 'shared/policy.ark': input.files['shared/policy.ark'] } });
    const spend = artifact.functions.find(group => group.name === 'spend');
    assert.deepEqual(spend.leaves.map(leaf => leaf.name), ['spend', 'backup']);
    assert.deepEqual(spend.arkade.inputs, [{ name: 'next', type: 'Policy' }, { name: 'values', type: 'int[2]' }, { name: 'sig', type: 'signature' }]);
    assert.deepEqual(spend.leaves[0].witness.map(field => [field.name, field.injected]), [['serverSig', true], ['emulatorSig', true]]);
    assert(spend.leaves[0].asm.includes('<EMULATOR_KEY:spend>'));
    assert(spend.leaves[1].asm.some(token => token.includes('spend')));
    const exitResult = await esm.compile(standalone);
    const exit = exitResult.artifact;
    assert.equal(exit.functions.length, 1);
    assert.equal(exit.functions[0].arkade, undefined);
    assert.deepEqual(exit.functions[0].leaves[0].witness, [{ name: 'sig', type: 'signature', encoding: 'schnorr-64' }]);
    assert.deepEqual(exitResult.diagnostics, []);
    assert.deepEqual(normalized((await esm.compile(artifact.source)).artifact), normalized(artifact));
    const at = { line: 1, column: 1 };
    const calls = [esm.compile, esm.check, input => esm.symbolAt(input, at), input => esm.completionsAt(input, at)];
    for (const bad of [null, {}, Object.assign([], standalone), { entry: 1, files: {} }, { entry: 'main.ark', files: [] }, { entry: 'main.ark', files: { 'main.ark': 1 } }]) {
        for (const call of calls) await assert.rejects(call(bad), TypeError);
    }
    for (const options of [null, true, [], { optimize: 'false' }, { optimize: 0 }]) {
        await assert.rejects(esm.compile(input, options), TypeError);
        await assert.rejects(esm.check(input, options), TypeError);
    }
    for (const bad of [undefined, null, {}, { line: 0, column: 1 }, { line: 1, column: -1 }, { line: 1.5, column: 1 }, { line: '1', column: 1 }, { line: 2 ** 32 + 3, column: 1 }, { line: 1, column: 2 ** 32 }]) {
        await assert.rejects(esm.symbolAt(input, bad), TypeError);
        await assert.rejects(esm.completionsAt(input, bad), TypeError);
    }
    // Source errors are diagnostics with a null artifact, not rejections.
    const errorOf = async input => {
        const { artifact, debug, diagnostics } = await esm.compile(input);
        assert.equal(artifact, null);
        assert.equal(debug, null);
        assert(diagnostics.some(d => d.severity === 'error'));
        return diagnostics.map(d => d.message).join('\n');
    };
    const parseFailure = await esm.compile(invalidSource);
    assert.match(await errorOf(invalidSource), /expected/);
    assert.equal(await esm.symbolAt(invalidSource, { line: 1, column: 10 }), null);
    assert.match(await errorOf({ ...input, files: { 'contracts/main.ark': input.files['contracts/main.ark'] } }), /policy\.ark.*not found/);
    assert.match(await errorOf({ entry: '../main.ark', files: {} }), /escapes the source root/);
    assert.match(await errorOf({ entry: '/main.ark', files: {} }), /relative \.ark path/);
    assert.match(await errorOf({ entry: '/main.ark', files: { '/main.ark': standalone.files['exit.ark'] } }), /relative \.ark path/);
    assert.match(await errorOf({ entry: 'main.ark', files: { 'main.ark': standalone.files['exit.ark'], '/extra.ark': '' } }), /relative \.ark path/);
    assert.match(await errorOf({ entry: 'main.ark', files: { 'main.ark': 'import "/extra.ark"; contract C() { function spend() { require(true); } }' } }), /relative \.ark path/);
    assert.match(await errorOf({ entry: 'main.ark', files: { 'main.ark': standalone.files['exit.ark'], './main.ark': standalone.files['exit.ark'] } }), /duplicate source path/);
    assert.match(await errorOf({ entry: 'library.ark', files: { 'library.ark': 'library L {}' } }), /not a library/);
    const snapshot = structuredClone(standalone);
    const pending = esm.compile(snapshot);
    snapshot.entry = 'missing.ark';
    snapshot.files['exit.ark'] = 'invalid';
    assert.equal((await pending).artifact.contractName, 'Exit');
    const options = { optimize: false };
    const pendingOptions = esm.compile(input, options);
    options.optimize = true;
    assert.equal((await pendingOptions).artifact.compiler.options.optimize, false);
    for (const call of calls) {
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
        assert.equal((await compile(${JSON.stringify(standalone)})).artifact.contractName, 'Exit');
    `]);

    const typecheck = `import { compile, check, symbolAt, completionsAt, version, type CompileInput, type CompileOptions, type CompileResult, type CompilerArtifact, type Completions, type DebugInfo, type Diagnostic, type Position, type SymbolInfo } from '@arkade-os/compiler';
const input: CompileInput = { entry: 'main.ark', files: { 'main.ark': '' } };
const result: Promise<CompileResult> = compile(input);
const options: CompileOptions = { optimize: false };
const detailed: Promise<CompileResult> = compile(input, options);
const position: Position = { line: 1, column: 1 };
const symbol: Promise<SymbolInfo | null> = symbolAt(input, position);
const table: Promise<Completions> = completionsAt(input, position);
const diagnostics: Promise<Diagnostic[]> = check(input, options);
const compilerVersion: Promise<string> = version();
void result; void detailed; void symbol; void table; void diagnostics; void compilerVersion;
// @ts-expect-error Source content must be a string.
compile({ entry: 'main.ark', files: { 'main.ark': 42 } });
// @ts-expect-error Optimization must be a boolean.
compile(input, { optimize: 'false' });
// @ts-expect-error Positions are numbers.
symbolAt(input, { line: '1', column: 1 });
// @ts-expect-error A failed compile has no artifact.
void (await compile(input)).artifact.contractName;
declare const narrowed: CompileResult;
if (narrowed.artifact !== null) {
    const map: DebugInfo = narrowed.debug;
    void map;
}
// @ts-expect-error Runtime source does not infer contract names.
const name: 'Vault' = (await compile(input)).artifact!.contractName;
`;
    writeFileSync(path.join(temporary, 'consumer.mts'), typecheck);
    writeFileSync(path.join(temporary, 'consumer.cts'), typecheck.replace("void (await compile(input)).artifact.contractName", "void ({} as CompileResult).artifact.contractName").replace("(await compile(input)).artifact!.contractName", "({} as CompilerArtifact).contractName"));
    const tsc = path.join(directory, 'node_modules/typescript/bin/tsc');
    run(process.execPath, [tsc, '--noEmit', '--strict', '--target', 'ES2022', '--module', 'NodeNext', 'consumer.mts', 'consumer.cts']);
    run(process.execPath, [tsc, '--noEmit', '--strict', '--target', 'ES2022', '--module', 'ESNext', '--moduleResolution', 'bundler', '--customConditions', 'browser', 'consumer.mts']);

    writeFileSync(path.join(temporary, 'index.html'), '<!doctype html><html lang="en"><title>Compiler test</title><script type="module" src="/main.js"></script></html>');
    writeFileSync(path.join(temporary, 'compiler-client.js'), readFileSync(path.join(directory, '../playground/compiler-client.js')));
    writeFileSync(path.join(temporary, 'compiler-worker.js'), readFileSync(path.join(directory, '../playground/compiler-worker.js'), 'utf8').replace("'./pkg/index.js'", "'@arkade-os/compiler'"));
    writeFileSync(path.join(temporary, 'main.js'), "import { compile, check, symbolAt, completionsAt, version } from '@arkade-os/compiler'; import * as workerCompiler from './compiler-client.js'; window.compiler = { compile, check, symbolAt, completionsAt, version }; window.workerCompiler = workerCompiler;\n");
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
    const browserResult = await page.evaluate(async ({ input, position }) => {
        const [compilerVersion, symbol, completions, ...results] = await Promise.all([
            window.compiler.version(), window.compiler.symbolAt(input, position), window.compiler.completionsAt(input, { line: 4, column: 1 }),
            ...Array.from({ length: 12 }, () => window.compiler.compile(input)),
        ]);
        return { compilerVersion, symbol, completions, results };
    }, { input, position });
    assert.equal(browserResult.compilerVersion, manifest.version);
    assert.deepEqual(browserResult.symbol, symbol);
    assert.deepEqual(browserResult.completions, completions);
    for (const result of browserResult.results) assert.deepEqual(normalized(result.artifact), normalized(artifact));
    assert.equal(requests.filter(url => url.endsWith('.wasm')).length, 1, 'concurrent browser initialization fetched WASM more than once');
    assert(requests.every(url => url.startsWith(server.resolvedUrls.local[0])), 'bundle fetched remote compiler assets');
    assert.deepEqual(normalized((await page.evaluate(input => window.compiler.compile(input), standalone)).artifact), normalized(exit));
    assert.deepEqual(normalized((await page.evaluate(input => window.compiler.compile(input, { optimize: false }), input)).artifact), normalized(unoptimized));
    assert.deepEqual(await page.evaluate(input => window.compiler.compile(input), invalidSource), parseFailure);
    assert.deepEqual(await page.evaluate(input => window.compiler.check(input), diagnosticInput), diagnostics);
    const bundledWorker = await page.evaluate(async ({ input, diagnosticInput, position }) => ({
        result: await window.workerCompiler.compile(input),
        diagnostics: await window.workerCompiler.check(diagnosticInput),
        symbol: await window.workerCompiler.symbolAt(input, position),
        completions: await window.workerCompiler.completionsAt(input, { line: 4, column: 1 }),
        version: await window.workerCompiler.version(),
    }), { input, diagnosticInput, position });
    assert.deepEqual(normalized(bundledWorker.result.artifact), normalized(artifact));
    assert.deepEqual(bundledWorker.result.debug, result.debug);
    assert.deepEqual(bundledWorker.diagnostics, diagnostics);
    assert.deepEqual(bundledWorker.symbol, symbol);
    assert.deepEqual(bundledWorker.completions, completions);
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
    assert.equal((await failedPage.evaluate(input => window.compiler.compile(input), standalone)).artifact.contractName, 'Exit');

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
    const nativeResult = await nativePage.evaluate(async ({ input, position }) => ({
        result: await window.compiler.compile(input, { optimize: false }),
        symbol: await window.compiler.symbolAt(input, position),
        version: await window.compiler.version(),
    }), { input, position });
    assert.deepEqual(normalized(nativeResult.result.artifact), normalized(unoptimized));
    assert.deepEqual(nativeResult.symbol, symbol);
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
    const workerResult = await workerPage.evaluate(async ({ input, diagnosticInput, position }) => {
        const [result, symbol, completions, diagnostics, version] = await Promise.all([
            window.compiler.compile(input, { optimize: false }), window.compiler.symbolAt(input, position),
            window.compiler.completionsAt(input, { line: 4, column: 1 }), window.compiler.check(diagnosticInput), window.compiler.version(),
        ]);
        return { result, symbol, completions, diagnostics, version };
    }, { input, diagnosticInput, position });
    assert.deepEqual(normalized(workerResult.result.artifact), normalized(unoptimized));
    assert.deepEqual(workerResult.symbol, symbol);
    assert.deepEqual(workerResult.completions, completions);
    assert.deepEqual(workerResult.diagnostics, diagnostics);
    assert.equal(workerResult.version, manifest.version);
    assert.deepEqual(await workerPage.evaluate(input => window.compiler.compile(input), invalidSource), parseFailure);
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
