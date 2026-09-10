// Run after ./playground/build.sh with node playground/imports.test.mjs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import * as contracts from './contracts.js';
import { initSync, compile_sources } from './pkg/arkade_compiler.js';

initSync({ module: fs.readFileSync(new URL('./pkg/arkade_compiler_bg.wasm', import.meta.url)) });
const context = vm.createContext({
    contracts, compile_sources,
    document: { addEventListener() {} },
    localStorage: { setItem() {} },
    location: { hash: '' },
    CompressionStream, DecompressionStream, TextEncoder, TextDecoder, btoa, atob,
    console: { warn() {} },
});
const source = fs.readFileSync(new URL('./main.js', import.meta.url), 'utf8');
vm.runInContext(source.replace(/^import .*;$/gm, ''), context);

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

context.bundle = {
    entry: 'vault/main.ark',
    files: {
        'vault/main.ark': 'import "../shared/fees.ark"; contract Vault() { function spend() { require(Fees.VALUE == 7); } }',
        'shared/fees.ark': 'contract Fees() { const int VALUE = 7; }',
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
vm.runInContext(`projects.shared.files['shared/fees.ark'] = 'contract Fees() { const int VALUE = 8; }';`, context);
const edited = vm.runInContext('compilationSources()', context);
assert.match(JSON.parse(compile_sources(edited.entry, JSON.stringify(edited.files))).source.files['shared/shared/fees.ark'], /VALUE = 8/);

context.bundle = { entry: '<img>.ark', files: { '<img>.ark': 'contract Invalid() {}' } };
await vm.runInContext(`compressCode(JSON.stringify(bundle)).then(encoded => { location.hash = '#project=' + encoded; });`, context);
assert.equal(await vm.runInContext('loadFromUrl()', context), null);
console.log(`Verified ${selections.length} playground entries, source round trips, shared projects, and dependency edits.`);
