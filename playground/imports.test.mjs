// Run after ./playground/build.sh with node playground/imports.test.mjs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { deflateRawSync } from 'node:zlib';
import * as contracts from './contracts.js';
import { initSync, compile_sources } from './pkg/arkade_compiler.js';

initSync({ module: fs.readFileSync(new URL('./pkg/arkade_compiler_bg.wasm', import.meta.url)) });
const context = vm.createContext({
    contracts, compile_sources,
    document: { addEventListener() {} },
    localStorage: { setItem() {} },
    location: { hash: '' },
    Blob, CompressionStream, DecompressionStream, TextEncoder, TextDecoder, btoa, atob,
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

console.log(`Verified ${selections.length} playground entries, source round trips, shared projects, dependency edits, removed shared examples, and idempotent share links.`);
