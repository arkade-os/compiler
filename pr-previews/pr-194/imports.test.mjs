// Run after ./playground/build.sh with node playground/imports.test.mjs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { deflateRawSync } from 'node:zlib';
import * as contracts from './contracts.js';
import { initSync, compile_sources, compile_sources_with_diagnostics, symbol_at } from './pkg/arkade_compiler.js';

initSync({ module: fs.readFileSync(new URL('./pkg/arkade_compiler_bg.wasm', import.meta.url)) });
const context = vm.createContext({
    contracts, compile_sources, compile_sources_with_diagnostics, symbol_at,
    document: { addEventListener() {} },
    localStorage: { setItem() {} },
    location: { hash: '' },
    Blob, CompressionStream, DecompressionStream, TextEncoder, TextDecoder, btoa, atob,
    console: { warn() {} },
});
const source = fs.readFileSync(new URL('./main.js', import.meta.url), 'utf8');
vm.runInContext(source.replace(/^import .*;$/gm, ''), context);

const warningSource = 'contract HasWarnings(int value) { function spend() { require(true); } }';
const detailed = JSON.parse(compile_sources_with_diagnostics('main.ark', JSON.stringify({ 'main.ark': warningSource }), false));
const warningArtifact = JSON.parse(detailed.artifact);
assert(detailed.warnings.some(warning => warning.startsWith('warning[unused-parameter]')));
assert(!Object.hasOwn(warningArtifact, 'warnings'));
assert.equal(warningArtifact.compiler.options.optimize, false);
assert.equal(warningArtifact.formatVersion, 1);
assert.match(warningArtifact.fingerprint, /^sha256:[0-9a-f]{64}$/);

const selections = vm.runInContext(`[
    ...Object.entries(projects).flatMap(([id, project]) => Object.keys(project.files).map(file => [id, file])),
    ...Object.keys(examples).map(id => [null, id]),
]`, context);
for (const [project, file] of selections) {
    context.selection = [project, file];
    const input = vm.runInContext(`
        [currentProject, currentFile] = selection;
        editor = { getValue: () => currentProject ? projects[currentProject].files[currentFile] : examples[currentFile].code };
        compilationSources();
    `, context);
    const output = JSON.parse(compile_sources(input.entry, JSON.stringify(input.files)));
    const bundle = output.source;
    const rebuilt = JSON.parse(compile_sources(bundle.entry, JSON.stringify(bundle.files)));
    rebuilt.updatedAt = output.updatedAt;
    assert.deepEqual(rebuilt, output);
}

vm.runInContext('delete examples.single_sig; delete examplePaths.single_sig;', context);
for (const [project, file] of selections.filter(([, file]) => file !== 'single_sig')) {
    context.selection = [project, file];
    const input = vm.runInContext(`
        [currentProject, currentFile] = selection;
        editor = { getValue: () => currentProject ? projects[currentProject].files[currentFile] : examples[currentFile].code };
        compilationSources();
    `, context);
    compile_sources(input.entry, JSON.stringify(input.files));
}

context.bundle = {
    entry: 'vault/main.ark',
    files: {
        'vault/main.ark': 'import "../shared/fees.ark"; contract Vault() { function spend() { require(Fees.value() == 7); } }',
        'shared/fees.ark': 'library Fees { const int VALUE = 7; function value() int { return hidden(); } private function hidden() int { return VALUE; } }',
    },
};
await vm.runInContext(`
    compressCode(JSON.stringify(bundle)).then(encoded => { location.hash = '#project=' + encoded; });
`, context);
const shared = await vm.runInContext('loadFromUrl()', context);
assert.deepEqual(JSON.parse(JSON.stringify(shared)), context.bundle);
context.shared = shared;
const sharedInput = vm.runInContext(`
    projects.shared = { name: 'Shared', files: shared.files };
    currentProject = 'shared';
    currentFile = shared.entry;
    editor = { getValue: () => projects.shared.files[currentFile] };
    compilationSources();
`, context);
assert.equal(JSON.parse(compile_sources(sharedInput.entry, JSON.stringify(sharedInput.files))).contractName, 'Vault');

// Compilation reads edits in dependencies, including files that are not selected.
vm.runInContext(`projects.shared.files['shared/fees.ark'] = projects.shared.files['shared/fees.ark'].replace('VALUE = 7', 'VALUE = 8');`, context);
const edited = vm.runInContext('compilationSources()', context);
assert.match(JSON.parse(compile_sources(edited.entry, JSON.stringify(edited.files))).source.files['shared/shared/fees.ark'], /VALUE = 8/);

context.bundle = { entry: '<img>.ark', files: { '<img>.ark': 'contract Invalid() {}' } };
await vm.runInContext(`compressCode(JSON.stringify(bundle)).then(encoded => { location.hash = '#project=' + encoded; });`, context);
assert.equal(await vm.runInContext('loadFromUrl()', context), null);
const encodedLimit = vm.runInContext('MAX_SHARED_ENCODED_CHARS', context);
const decodedLimit = vm.runInContext('MAX_SHARED_DECODED_BYTES', context);
context.encoded = 'A'.repeat(encodedLimit + 1);
await assert.rejects(vm.runInContext('decompressCode(encoded)', context), /Encoded share link exceeds/);
for (const size of [decodedLimit, decodedLimit + 1]) {
    context.encoded = deflateRawSync(Buffer.alloc(size, 'a')).toString('base64url');
    const decoded = vm.runInContext('decompressCode(encoded)', context);
    if (size === decodedLimit) assert.equal((await decoded).length, size);
    else await assert.rejects(decoded, /Shared source exceeds/);
}
context.encoded = 'AA';
await assert.rejects(vm.runInContext('decompressCode(encoded)', context));
for (const prefix of ['#code=', '#project=']) {
    context.location.hash = prefix + deflateRawSync(Buffer.alloc(decodedLimit + 1, 'a')).toString('base64url');
    assert.equal(await vm.runInContext('loadFromUrl()', context), null);
}
await assert.rejects(vm.runInContext("compressCode('a'.repeat(MAX_SHARED_DECODED_BYTES + 1))", context), /Shared source exceeds/);

const sharedFolderCount = () => vm.runInContext(
    `Object.keys(projects).filter(id => id === 'shared' || id.startsWith('shared_')).length`,
    context);
const foldersBefore = sharedFolderCount();

context.bundle = { entry: 'escrow/escrow.ark', files: { 'escrow/escrow.ark': contracts.escrow } };
let opened = vm.runInContext('resolveSharedBundle(bundle)', context);
assert.equal(opened.example, 'escrow');
assert.equal(opened.created, undefined);
opened = vm.runInContext('resolveSharedBundle(bundle)', context);
assert.equal(opened.example, 'escrow');
assert.equal(sharedFolderCount(), foldersBefore);

context.bundle = {
    entry: 'shared/escrow/escrow.ark',
    files: { 'shared/escrow/escrow.ark': contracts.escrow },
};
opened = vm.runInContext('resolveSharedBundle(bundle)', context);
assert.equal(opened.example, 'escrow');
assert.equal(vm.runInContext('canonicalShareBundle(bundle).entry', context), 'escrow/escrow.ark');
assert.equal(sharedFolderCount(), foldersBefore);

context.bundle = {
    entry: 'escrow/escrow.ark',
    files: { 'escrow/escrow.ark': `${contracts.escrow}\n// edited\n` },
};
const imported = vm.runInContext('resolveSharedBundle(bundle)', context);
assert.equal(imported.created, true);
assert.equal(sharedFolderCount(), foldersBefore + 1);
const reopened = vm.runInContext('resolveSharedBundle(bundle)', context);
assert.equal(reopened.project, imported.project);
assert.equal(reopened.file, imported.file);
assert.equal(reopened.created, undefined);
assert.equal(sharedFolderCount(), foldersBefore + 1);

context.selection = [imported.project, imported.file];
const resharedInput = vm.runInContext(`
    [currentProject, currentFile] = selection;
    editor = { getValue: () => projects[currentProject].files[currentFile] };
    compilationSources();
`, context);
context.bundle = JSON.parse(compile_sources(resharedInput.entry, JSON.stringify(resharedInput.files))).source;
assert.equal(context.bundle.entry, `${imported.project}/escrow/escrow.ark`);
assert.equal(vm.runInContext('canonicalShareBundle(bundle).entry', context), 'escrow/escrow.ark');
const fromReshare = vm.runInContext('resolveSharedBundle(bundle)', context);
assert.equal(fromReshare.project, imported.project);
assert.equal(fromReshare.created, undefined);
assert.equal(sharedFolderCount(), foldersBefore + 1);

const nestedAgain = {
    entry: `${imported.project}/escrow/escrow.ark`,
    files: { [`${imported.project}/escrow/escrow.ark`]: `${contracts.escrow}\n// edited\n` },
};
context.bundle = {
    entry: `shared_9/${nestedAgain.entry}`,
    files: { [`shared_9/${nestedAgain.entry}`]: nestedAgain.files[nestedAgain.entry] },
};
const unwrappedTwice = vm.runInContext('resolveSharedBundle(bundle)', context);
assert.equal(unwrappedTwice.project, imported.project);
assert.equal(sharedFolderCount(), foldersBefore + 1);

context.bundle = vm.runInContext(`({ entry: 'vault/main.ark', files: { ...projects.shared.files } })`, context);
assert.equal(vm.runInContext('canonicalShareBundle(bundle).entry', context), 'vault/main.ark');
assert.equal(vm.runInContext("'shared/fees.ark' in canonicalShareBundle(bundle).files", context), true);
const vaultAgain = vm.runInContext('resolveSharedBundle(bundle)', context);
assert.equal(vaultAgain.project, 'shared');
assert.equal(vaultAgain.file, 'vault/main.ark');
assert.equal(sharedFolderCount(), foldersBefore + 1);

const elements = Object.fromEntries(['errors-output', 'error-count', 'compile-status'].map(id => {
    const classes = new Set();
    return [id, {
        textContent: '',
        innerHTML: '',
        dataset: {},
        classList: {
            add: (...names) => names.forEach(name => classes.add(name)),
            remove: (...names) => names.forEach(name => classes.delete(name)),
            toggle: (name, on) => (on ? classes.add(name) : classes.delete(name)),
            contains: name => classes.has(name),
        },
    }];
}));
elements['optimize-toggle'] = { checked: false };
context.document.getElementById = id => elements[id];
context.warningSource = warningSource;
context.renderedArtifact = null;
vm.runInContext(`
    wasmReady = true;
    editor = { getValue: () => warningSource };
    compilationSources = () => ({ entry: 'main.ark', files: { 'main.ark': warningSource } });
    displayJson = json => { renderedArtifact = JSON.parse(json); };
    displayAsm = () => {};
    displayBindings = () => {};
    markCompiled = () => {};
    doCompile();
`, context);
assert.equal(context.renderedArtifact.fingerprint, warningArtifact.fingerprint);
const warningDiagnostics = detailed.diagnostics.filter(d => d.severity === 'warning');
assert.equal(warningDiagnostics.length, detailed.warnings.length);
for (const warning of warningDiagnostics) {
    assert.ok(elements['errors-output'].innerHTML.includes('class="diagnostic warning"'));
    assert.ok(elements['errors-output'].innerHTML.includes(warning.message), warning.message);
}
assert(elements['error-count'].classList.contains('warning'));
assert.equal(elements['error-count'].textContent, String(detailed.warnings.length));
assert.equal(elements['compile-status'].className, 'compile-status warning');
context.warningSource = 'contract Clean(pubkey k) { function spend(signature s) { require(checkSig(s, k)); } }';
vm.runInContext('doCompile()', context);
assert.equal(elements['errors-output'].innerHTML, '');
assert(!elements['error-count'].classList.contains('visible'));
assert.equal(elements['compile-status'].className, 'compile-status success');

// Every error is reported with its position, columns in UTF-16 units; nothing is thrown.
const failingSource = 'contract Failing() {\n    function spend(int x) { require("é" == x); require(y == 1); }\n}';
const failed = JSON.parse(compile_sources_with_diagnostics('main.ark', JSON.stringify({ './main.ark': failingSource })));
assert.equal(failed.artifact, null);
const errors = failed.diagnostics.filter(d => d.severity === 'error');
assert(errors.length >= 2);
for (const error of errors) {
    assert.equal(error.file, 'main.ark');
    assert.equal(error.start.line, 2);
}
const undefinedName = errors.find(d => d.message.includes("'y'"));
assert.equal(undefinedName.start.column, failingSource.split('\n')[1].indexOf('y == 1') + 1);
context.document.querySelectorAll = () => [];
context.warningSource = failingSource;
context.selected = null;
vm.runInContext(`
    editor = { getValue: () => warningSource, revealLineInCenter() {}, setSelection: range => { selected = range; } };
    doCompile();
`, context);
assert.equal(context.selected.startColumn, errors[0].start.column);
assert.equal(elements['error-count'].textContent, String(errors.length));
assert.equal(elements['compile-status'].className, 'compile-status error');
assert.match(elements['errors-output'].innerHTML, /data-line="2" data-column="\d+">error\[/);
assert.match(elements['errors-output'].innerHTML, /\(main\.ark:2:\d+\)/);

// Assembly tokens link to the statement each comes from.
const mapped = JSON.parse(compile_sources_with_diagnostics('main.ark', JSON.stringify({
    'main.ark': 'contract M(pubkey k) {\n  function f(signature s, int n) {\n    require(n > 0);\n    if (n > 1) {\n      require(checkSig(s, k));\n    }\n  }\n}',
})));
const covenant = JSON.parse(mapped.artifact).functions[0].arkade;
context.covenant = covenant;
const html = vm.runInContext('asmRuns = []; covenantListing(covenant.asm, covenant.sourceMap)', context);
assert.equal((html.match(/class="asm-line asm-run"/g) || []).length, covenant.sourceMap.length);
assert.equal((html.match(/class="asm-line"/g) || []).length > 0, true);
for (const token of covenant.asm) assert.ok(html.includes(token.replace(/</g, '&lt;').replace(/>/g, '&gt;')), token);
const runs = vm.runInContext('asmRuns', context);
const innermost = line => [...vm.runInContext(`innermostRuns(asmRuns, ${line}, 9)`, context)].map(run => runs[run].start[0]);
assert.deepEqual(innermost(3), [3]);
assert.deepEqual(innermost(5), [5]);
assert.ok(innermost(4).every(line => line === 4) && innermost(4).length > 0);
// An `if` maps to its condition alone, so its tokens are not chosen inside its body.
assert.ok(runs.filter(range => range.start[0] === 4).every(range => range.end[0] === 4));
assert.deepEqual(innermost(8), []);

// Hover and go to definition read the compiler's symbol table.
const symbolFiles = JSON.stringify({
    'main.ark': 'import "fees.ark";\ncontract V(pubkey owner) {\n  function spend(signature sig, int amount) {\n    require(checkSig(sig, owner));\n    require(Fees.fee(amount) > amount);\n  }\n}',
    'fees.ark': 'library Fees {\n  function fee(int amount) int { return amount + 1; }\n}',
});
const symbolAtPosition = (line, column) => JSON.parse(symbol_at('main.ark', symbolFiles, line, column));
const owner = symbolAtPosition(4, 28);
assert.deepEqual([owner.name, owner.kind, owner.type], ['owner', 'parameter', 'pubkey']);
assert.deepEqual(owner.definition.start, { line: 2, column: 19 });
assert.deepEqual(owner.at.start, { line: 4, column: 27 });
assert.equal(owner.references.length, 1);
context.symbol = owner;
assert.deepEqual([...vm.runInContext('describeSymbol(symbol)', context)], ['parameter owner: pubkey', 'Defined at line 2 · 1 reference']);
const fee = symbolAtPosition(5, 18);
assert.deepEqual([fee.name, fee.kind, fee.type, fee.definition.file], ['fee', 'function', 'int', 'fees.ark']);
context.symbol = fee;
assert.equal(vm.runInContext('describeSymbol(symbol)[1]', context), 'Defined at fees.ark:2 · 1 reference');
const amount = symbolAtPosition(3, 37);
assert.deepEqual([amount.name, amount.references.length], ['amount', 2]);
assert.equal(symbolAtPosition(4, 1), null);

function loadStored(saved) {
    const store = { 'arkade-playground': JSON.stringify(saved) };
    const storageContext = vm.createContext({
        contracts, document: { addEventListener() {} }, location: { hash: '' }, console: { warn() {} },
        localStorage: { getItem: key => store[key] ?? null, setItem: (key, value) => { store[key] = value; } },
    });
    vm.runInContext(source.replace(/^import .*;$/gm, ''), storageContext);
    vm.runInContext('loadFromStorage()', storageContext);
    return { store, read: expr => vm.runInContext(expr, storageContext) };
}

const legacy = loadStored({
    projects: {
        bonds: { name: 'Bonds', description: '', files: { 'bond_mint.ark': 'stale', 'mine.ark': 'own' } },
        mine: { name: 'Mine', description: '', files: { 'a.ark': 'own' } },
    },
    examples: { htlc: { name: 'HTLC', code: 'stale' }, own: { name: 'Own', code: 'own' } },
});
assert.equal(legacy.read("projects.bonds.files['bond_mint.ark']"), contracts.bond_mint);
assert.equal(legacy.read("projects.bonds.files['repayment_pool.ark']"), contracts.repayment_pool);
assert.equal(legacy.read("projects.bonds.files['mine.ark']"), 'own');
assert.equal(legacy.read("projects.mine.files['a.ark']"), 'own');
assert.equal(legacy.read('examples.htlc.code'), contracts.htlc);
assert.equal(legacy.read('examples.own.code'), 'own');
assert.equal(JSON.parse(legacy.store['arkade-playground-legacy']).examples.htlc.code, 'stale');

legacy.read('saveToStorage()');
const saved = JSON.parse(legacy.store['arkade-playground']);
saved.defaults.examples.htlc.code = saved.examples.htlc.code = 'previous release';
saved.defaults.examples.escrow.code = 'previous release';
saved.examples.escrow.code = 'edited';
delete saved.projects.bonds.files['bond_mint.ark'];
saved.defaults.projects.bonds.files['retired.ark'] = saved.projects.bonds.files['retired.ark'] = 'retired';
saved.defaults.projects.bonds.files['kept.ark'] = 'retired';
saved.projects.bonds.files['kept.ark'] = 'edited';
saved.defaults.examples.retired = saved.examples.retired = { name: 'Retired', code: 'retired' };
saved.defaults.examples.kept = { name: 'Kept', code: 'retired' };
saved.examples.kept = { name: 'Kept', code: 'edited' };
delete saved.projects.option;
delete saved.examples.single_sig;
delete saved.defaults.examples.swap;
delete saved.examples.swap;
const upgraded = loadStored(saved);
assert(!upgraded.read("Object.hasOwn(projects, 'option')"));
assert(!upgraded.read("Object.hasOwn(examples, 'single_sig')"));
assert.equal(upgraded.read('examples.swap.code'), contracts.non_interactive_swap);
assert.equal(upgraded.read('examples.htlc.code'), contracts.htlc);
assert.equal(upgraded.read('examples.escrow.code'), 'edited');
assert(!upgraded.read("Object.hasOwn(projects.bonds.files, 'bond_mint.ark')"));
assert(!upgraded.read("Object.hasOwn(projects.bonds.files, 'retired.ark')"));
assert.equal(upgraded.read("projects.bonds.files['kept.ark']"), 'edited');
assert(!upgraded.read("Object.hasOwn(examples, 'retired')"));
assert.equal(upgraded.read('examples.kept.code'), 'edited');
assert(!Object.hasOwn(upgraded.store, 'arkade-playground-legacy'));

console.log(`Verified ${selections.length} playground entries, source round trips, shared projects, dependency edits, removed shared examples, idempotent share links, and stored edits over bundled updates.`);
