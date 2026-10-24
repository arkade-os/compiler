// Run with node playground/completions.test.mjs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({ window: {} });
vm.runInContext(fs.readFileSync(new URL('./arkade-language.js', import.meta.url), 'utf8'), context);
context.window.arkadeUseDocs(JSON.parse(fs.readFileSync(new URL('../src/builtins.json', import.meta.url), 'utf8')));
const complete = context.window.arkadeComplete;
const labels = (before, table = null) => [...complete(before, table)].map(item => item.label);

// Shape returned by the WASM `completions_at` export: the names visible at the cursor.
const table = {
    symbols: [
        { name: 'Point', kind: 'struct' },
        { name: 'Demo', kind: 'contract' },
        { name: 'owner', kind: 'parameter', type: 'pubkey' },
        { name: 'points', kind: 'parameter', type: 'Point[2]' },
        { name: 'amounts', kind: 'parameter', type: 'int[3]' },
        { name: 'spend', kind: 'function' },
        { name: 'sig', kind: 'parameter', type: 'signature' },
        { name: 'group', kind: 'variable', type: 'AssetGroup' },
        { name: 'point', kind: 'variable', type: 'Point' },
        { name: 'segment', kind: 'variable', type: 'Segment' },
        { name: 'segments', kind: 'parameter', type: 'Segment[2]' },
        { name: 'Shadowed', kind: 'parameter', type: 'Point' },
        { name: 'Fees', kind: 'library' },
        { name: 'destination', kind: 'parameter', type: 'ScriptPubKey' },
        { name: 'destinations', kind: 'parameter', type: 'ScriptPubKey[2]' },
    ],
    structs: [
        { name: 'Point', fields: [{ name: 'x', type: 'int' }, { name: 'y', type: 'bytes32' }] },
        { name: 'Segment', fields: [{ name: 'from', type: 'Point' }, { name: 'ends', type: 'Point[2]' }, { name: 'script', type: 'ScriptPubKey' }] },
    ],
    members: {
        Fees: [{ name: 'DELAY', kind: 'constant', type: 'int' }, { name: 'calculate', kind: 'function', type: 'int' }],
        Shadowed: [{ name: 'hidden', kind: 'constant', type: 'int' }],
    },
};

const top = labels('    require(', table);
for (const label of ['checkSig', 'substr', 'tx', 'owner', 'sig', 'group', 'spend', 'Point', 'Demo', 'Fees']) assert(top.includes(label), label);
assert.deepEqual(labels('constructor.', table), []);
assert.deepEqual(labels('toString.', { members: {} }), []);
assert(!top.some(label => label.includes('.')));
assert.equal(top.length, new Set(top).size);
assert(labels('').includes('checkSig'));

assert(labels('tx.').includes('inputs'));
assert(labels('require(tx . ').includes('assetGroups'));
assert.deepEqual(labels('tx.outputs[0].'), ['value', 'script', 'witnessVersion', 'assets']);
assert(labels('tx.inputs[this.activeInputIndex].').includes('arkadeScriptHash'));
assert.deepEqual(labels('tx.outputs[idx[0]].'), ['value', 'script', 'witnessVersion', 'assets']);
assert(!top.includes('older'));
assert(labels('tx.inputs[i].assets.').includes('lookup'));
assert.deepEqual(labels('tx.outputs[o].assets[0].'), ['assetId', 'amount']);
assert(labels('tx.assetGroups[k].').includes('sumOutputs'));
assert(labels('tx.input.current.').includes('value'));
assert(labels('this.').includes('activeInputIndex'));
assert(labels('group.', table).includes('controlIs'));
assert.deepEqual(labels('group.inputs[j].', table), ['amount', 'type', 'index', 'txid']);
assert.deepEqual(labels('tx.assetGroups[k].outputs[0].'), ['amount', 'type', 'index']);
assert.deepEqual(labels('group[0].', table), []);
assert.deepEqual(labels('points[1].', table), ['x', 'y']);
assert.deepEqual(labels('point.', table), ['x', 'y']);
assert.deepEqual(labels('amounts.', table), ['length']);
assert.deepEqual(labels('segment.from.', table), ['x', 'y']);
assert.deepEqual(labels('segment.ends.', table), ['length']);
assert.deepEqual(labels('segment.ends[1].', table), ['x', 'y']);
assert.deepEqual(labels('segment.missing.', table), []);
assert.deepEqual(labels('segments.from.', table), []);
assert.deepEqual(labels('segments[0].from.', table), ['x', 'y']);
assert.deepEqual(labels('Shadowed.', table), ['x', 'y']);
assert.deepEqual(labels('Fees.', table), ['DELAY', 'calculate']);
assert.deepEqual(labels('unknown.', table), []);
assert(complete('tx.', null).find(item => item.label === 'inputs').snippet);

for (const prefix of ['tx.inputs[0].', 'tx.input.current.', 'tx.outputs[0].']) {
    assert(labels(prefix).includes('script'));
    assert(!labels(prefix).includes('scriptPubKey'));
}
assert(labels('').includes('ScriptPubKey'));
for (const path of ['destination', 'destinations[0]', 'segment.script', 'tx.outputs[0].script', 'tx.inputs[0].script', 'tx.input.current.script', 'this.activeBytecode']) {
    assert.deepEqual(labels(`${path}.`, table), ['program', 'version']);
}
assert.deepEqual(labels('destinations.', table), ['length']);
assert.deepEqual(labels('destination.program.', table), []);
assert.equal(complete('', null).find(item => item.label === 'checkMultisig').insertText, 'checkMultisig([${1:pubkeys}], [${2:sigs}])');
assert.deepEqual(labels('tx.input.current.'), ['value', 'script', 'witnessVersion', 'sequence', 'outpoint', 'arkadeScriptHash', 'arkadeWitnessHash']);

const describe = context.window.arkadeDescribe;
assert.equal(describe('require(', 'sha256', null).declaration, 'function sha256(bytes data) bytes32');
assert.equal(describe('tx.outputs[o].assets.', 'lookup', null).key, 'tx.inputs[].assets.lookup');
assert.equal(describe('tx.input.current.', 'value', null).key, 'tx.inputs[].value');
assert.equal(describe('group.inputs[j].', 'txid', table).declaration, 'bytes32 tx.assetGroups[].inputs[].txid');
assert.equal(describe('', 'constructor', null), null);
assert.equal(describe('point.', 'x', table), null);

const { text, lines } = context.window.arkadeDeclarations();
const declared = text.split('\n');
assert.equal(declared[lines.sha256 - 1], 'function sha256(bytes data) bytes32;');
assert.equal(declared[lines['tx.version'] - 2], '// Transaction version.');
