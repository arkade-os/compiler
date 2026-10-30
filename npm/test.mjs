import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from 'playwright';

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
}`,
        'shared/policy.ark': `struct Policy { pubkey owner; int[2] limits; }
library Fees { function check(int amount) { require(amount >= 1); } }`,
    },
};
const invalidSource = { entry: 'main.ark', files: { 'main.ark': 'contract Broken(' } };
// Nesting deep enough to overflow the stack, which traps the WASM instance.
const nested = { entry: 'main.ark', files: { 'main.ark': `contract C() { function f() { require(${'('.repeat(10000)}1${')'.repeat(10000)} == 1); } }` } };
const position = { line: 6, column: 27 };
const completionPosition = { line: 4, column: 1 };
function normalized(artifact) {
    const { updatedAt, ...stable } = artifact;
    return stable;
}
function run(command, args, cwd = temporary) {
    return execFileSync(command, args, { cwd, encoding: 'utf8', stdio: ['pipe', 'pipe', 'inherit'], env: { ...process.env, npm_config_cache: path.join(temporary, 'npm-cache') } });
}

let browser;
try {
    const [packed] = JSON.parse(run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', temporary], directory));
    const contents = packed.files.map(file => file.path);
    for (const file of ['browser/index.js', 'browser/index.d.ts', 'browser/runtime.js', 'node/index.js', 'node/runtime.js', 'wasm/arkade_compiler.js', 'wasm/arkade_compiler_bg.wasm']) {
        assert(contents.includes(`dist/${file}`), `packed package missing ${file}`);
    }
    assert(contents.every(file => file.startsWith('dist/') || ['package.json', 'LICENSE', 'README.md'].includes(file)));
    assert.equal(manifest.dependencies, undefined);
    for (const lifecycle of ['preinstall', 'install', 'postinstall', 'prepare']) {
        assert.equal(manifest.scripts[lifecycle], undefined);
    }
    writeFileSync(path.join(temporary, 'package.json'), '{"private":true,"type":"module"}\n');
    run('npm', ['install', '--offline', '--no-audit', '--no-fund', path.join(temporary, packed.filename)]);
    const installed = path.join(temporary, 'node_modules/@arkade-os/compiler/dist');
    const require = createRequire(path.join(temporary, 'package.json'));
    const esm = await import(pathToFileURL(require.resolve('@arkade-os/compiler')).href);
    assert.equal(require('@arkade-os/compiler').compile, esm.compile, 'require() loads the ESM package');

    const wasm = await import(`${pathToFileURL(path.join(installed, 'wasm/arkade_compiler.js')).href}?raw`);
    wasm.initSync({ module: readFileSync(path.join(installed, 'wasm/arkade_compiler_bg.wasm')) });
    const files = JSON.stringify(input.files);
    const [result, compilerVersion, ...concurrent] = await Promise.all([
        esm.compile(input), esm.version(), ...Array.from({ length: 12 }, () => esm.compile(input)),
    ]);
    const { artifact } = result;
    assert.equal(compilerVersion, manifest.version);
    assert.deepEqual(artifact.compiler.options, { optimize: true });
    for (const other of concurrent) assert.deepEqual(normalized(other.artifact), normalized(artifact));
    const raw = JSON.parse(wasm.compile_sources_with_diagnostics(input.entry, files));
    assert.deepEqual(Object.keys(result).sort(), ['artifact', 'debug', 'diagnostics']);
    assert.deepEqual(normalized(artifact), normalized(JSON.parse(raw.artifact)));
    assert.deepEqual(result.debug, JSON.parse(raw.debug));
    assert.deepEqual(result.diagnostics, raw.diagnostics);
    const unoptimized = (await esm.compile(input, { optimize: false })).artifact;
    assert.deepEqual(normalized(unoptimized), normalized(JSON.parse(JSON.parse(wasm.compile_sources_with_diagnostics(input.entry, files, false)).artifact)));
    const symbol = await esm.symbolAt(input, position);
    assert.deepEqual(symbol, JSON.parse(wasm.symbol_at(input.entry, files, position.line, position.column)));
    assert.equal(symbol.name, 'sig');
    const completions = await esm.completionsAt(input, completionPosition);
    assert.deepEqual(completions, JSON.parse(wasm.completions_at(input.entry, files, completionPosition.line, completionPosition.column)));
    const diagnostics = await esm.check(invalidSource);
    assert.deepEqual(diagnostics, JSON.parse(wasm.check_sources(invalidSource.entry, JSON.stringify(invalidSource.files))));
    // Source errors are diagnostics with a null artifact, not rejections.
    const parseFailure = await esm.compile(invalidSource);
    assert.equal(parseFailure.artifact, null);
    assert.equal(parseFailure.debug, null);
    assert(parseFailure.diagnostics.some(d => d.severity === 'error'));
    for (const bad of [undefined, {}, { line: 0, column: 1 }, { line: 1.5, column: 1 }, { line: '1', column: 1 }, { line: 2 ** 32 + 3, column: 1 }]) {
        await assert.rejects(esm.symbolAt(input, bad), TypeError);
        await assert.rejects(esm.completionsAt(input, bad), TypeError);
    }
    // A trap leaves the instance unusable; the next call loads a fresh one.
    await assert.rejects(esm.symbolAt(nested, { line: 1, column: 1 }), error => !(error instanceof TypeError));
    assert.deepEqual(await esm.symbolAt(input, position), symbol);

    const typecheck = `import { compile, check, symbolAt, completionsAt, version, type CompileInput, type CompileOptions, type CompileResult, type Completions, type DebugInfo, type Diagnostic, type Position, type SymbolInfo } from '@arkade-os/compiler';
const input: CompileInput = { entry: 'main.ark', files: { 'main.ark': '' } };
const options: CompileOptions = { optimize: false };
const result: Promise<CompileResult> = compile(input, options);
const position: Position = { line: 1, column: 1 };
const symbol: Promise<SymbolInfo | null> = symbolAt(input, position);
const table: Promise<Completions> = completionsAt(input, position);
const diagnostics: Promise<Diagnostic[]> = check(input, options);
const compilerVersion: Promise<string> = version();
void result; void symbol; void table; void diagnostics; void compilerVersion;
// @ts-expect-error Source content must be a string.
compile({ entry: 'main.ark', files: { 'main.ark': 42 } });
// @ts-expect-error A failed compile has no artifact.
void (await compile(input)).artifact.contractName;
declare const narrowed: CompileResult;
if (narrowed.artifact !== null) {
    const map: DebugInfo = narrowed.debug;
    void map;
}
`;
    writeFileSync(path.join(temporary, 'consumer.mts'), typecheck);
    const tsc = path.join(directory, 'node_modules/typescript/bin/tsc');
    run(process.execPath, [tsc, '--noEmit', '--strict', '--target', 'ES2022', '--module', 'NodeNext', 'consumer.mts']);
    run(process.execPath, [tsc, '--noEmit', '--strict', '--target', 'ES2022', '--module', 'ESNext', '--moduleResolution', 'bundler', '--customConditions', 'browser', 'consumer.mts']);

    // The browser entrypoint served unbundled under a URL prefix, as the playground serves it.
    const base = 'http://compiler.test/pr-previews/pr-1/';
    browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL });
    const context = await browser.newContext();
    const served = [];
    await context.route(`${base}**`, route => {
        const file = route.request().url().slice(base.length);
        served.push(file);
        if (!file) {
            return route.fulfill({ contentType: 'text/html', body: `<!doctype html><script type="module">import * as compiler from './pkg/browser/index.js'; window.compiler = compiler;</script>` });
        }
        assert(file.startsWith('pkg/'), `unexpected browser asset: ${file}`);
        return route.fulfill({
            contentType: file.endsWith('.wasm') ? 'application/wasm' : 'text/javascript',
            body: readFileSync(path.join(installed, file.slice(4))),
        });
    });
    const page = await context.newPage();
    await page.goto(base);
    await page.waitForFunction(() => window.compiler);
    // A failed dynamic import stays cached, so only the WASM fetch is lazy.
    assert(served.includes('pkg/wasm/arkade_compiler.js') && !served.some(file => file.endsWith('.wasm')));
    const wasmUrl = `${base}pkg/wasm/arkade_compiler_bg.wasm`;
    await context.route(wasmUrl, route => route.abort('failed'));
    const failure = await page.evaluate(async () => {
        try { await window.compiler.version(); } catch (error) { return { name: error.name, message: error.message }; }
    });
    assert.equal(failure.name, 'TypeError');
    assert.match(failure.message, /fetch/i);
    await context.unroute(wasmUrl);
    const browserResult = await page.evaluate(async ({ input, invalidSource, position, completionPosition }) => {
        const [compilerVersion, symbol, completions, parseFailure, ...results] = await Promise.all([
            window.compiler.version(), window.compiler.symbolAt(input, position), window.compiler.completionsAt(input, completionPosition),
            window.compiler.compile(invalidSource), ...Array.from({ length: 12 }, () => window.compiler.compile(input)),
        ]);
        return { compilerVersion, symbol, completions, parseFailure, results };
    }, { input, invalidSource, position, completionPosition });
    assert.equal(browserResult.compilerVersion, manifest.version);
    assert.deepEqual(browserResult.symbol, symbol);
    assert.deepEqual(browserResult.completions, completions);
    assert.deepEqual(browserResult.parseFailure, parseFailure);
    for (const result of browserResult.results) assert.deepEqual(normalized(result.artifact), normalized(artifact));
    assert.equal(served.filter(file => file.endsWith('.wasm')).length, 1, 'concurrent browser initialization fetched WASM more than once');
    console.log(`Packed @arkade-os/compiler ${manifest.version}: Node ESM and require(), declarations, trap recovery, and browser loading passed.`);
} finally {
    await browser?.close();
    rmSync(temporary, { recursive: true, force: true });
}
