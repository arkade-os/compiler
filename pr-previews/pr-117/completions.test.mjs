// Run with node playground/completions.test.mjs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({ window: {} });
vm.runInContext(fs.readFileSync(new URL('./arkade-language.js', import.meta.url), 'utf8'), context);
const complete = context.window.arkadeComplete;
const labels = (before, table = null, line = 1) => [...complete(before, table, line)].map(item => item.label);

// Shape returned by the WASM `symbols` export.
const table = {
    symbols: [
        { name: 'Point', kind: 'struct' },
        { name: 'Demo', kind: 'contract' },
        { name: 'owner', kind: 'parameter', type: 'pubkey' },
        { name: 'points', kind: 'parameter', type: 'Point[2]' },
        { name: 'amounts', kind: 'parameter', type: 'int[3]' },
        { name: 'spend', kind: 'function' },
        { name: 'sig', kind: 'parameter', type: 'signature', position: [4, 20], scope: [4, 9] },
        { name: 'group', kind: 'variable', type: 'assetGroup', position: [5, 9], scope: [4, 9] },
        { name: 'point', kind: 'variable', type: 'Point', position: [5, 20], scope: [4, 9] },
        { name: 'later', kind: 'variable', position: [7, 9], scope: [4, 9] },
        { name: 'other', kind: 'variable', position: [11, 9], scope: [10, 12] },
        { name: 'Fees', kind: 'library' },
    ],
    structs: [{ name: 'Point', fields: [{ name: 'x', type: 'int' }, { name: 'y', type: 'bytes32' }] }],
    members: { Fees: [{ name: 'DELAY', kind: 'constant', type: 'int' }, { name: 'calculate', kind: 'function', type: 'int' }] },
};

const top = labels('    require(', table, 5);
for (const label of ['checkSig', 'substr', 'tx', 'owner', 'sig', 'group', 'spend', 'Point', 'Demo', 'Fees']) assert(top.includes(label), label);
assert(!top.includes('other'));
assert(!top.includes('later'));
assert(labels('', table, 8).includes('later'));
assert.deepEqual(labels('constructor.', table, 5), []);
assert.deepEqual(labels('toString.', { members: {} }, 5), []);
assert(labels('', table, 11).includes('other'));
assert(!labels('', table, 11).includes('sig'));
assert(!top.some(label => label.includes('.')));
assert.equal(top.length, new Set(top).size);
assert(labels('').includes('checkSig'));

assert(labels('tx.').includes('inputs'));
assert(labels('require(tx . ').includes('assetGroups'));
assert.deepEqual(labels('tx.outputs[0].'), ['value', 'scriptPubKey', 'assets']);
assert(labels('tx.inputs[this.activeInputIndex].').includes('arkadeScriptHash'));
assert.deepEqual(labels('tx.outputs[idx[0]].'), ['value', 'scriptPubKey', 'assets']);
assert(!top.includes('older'));
assert(labels('tx.inputs[i].assets.').includes('lookup'));
assert.deepEqual(labels('tx.outputs[o].assets[0].'), ['assetId', 'amount']);
assert(labels('tx.assetGroups[k].').includes('sumOutputs'));
assert(labels('tx.input.current.').includes('value'));
assert(labels('this.').includes('activeInputIndex'));
assert(labels('group.', table, 5).includes('controlIs'));
assert.deepEqual(labels('points[1].', table, 5), ['x', 'y']);
assert.deepEqual(labels('point.', table, 5), ['x', 'y']);
assert.deepEqual(labels('amounts.', table, 5), ['length']);
assert.deepEqual(labels('Fees.', table, 5), ['DELAY', 'calculate']);
assert.deepEqual(labels('unknown.', table, 5), []);
assert(complete('tx.', null, 1).find(item => item.label === 'inputs').snippet);
