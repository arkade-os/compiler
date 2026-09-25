// Run with node playground/completions.test.mjs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({ window: {} });
vm.runInContext(fs.readFileSync(new URL('./arkade-language.js', import.meta.url), 'utf8'), context);
const complete = context.window.arkadeComplete;
const labels = (before, text = '') => [...complete(before, text)].map(item => item.label);

const source = `
struct Point { int x; bytes32 y; }
contract Demo(pubkey owner, Point[2] points, int[3] amounts) {
    function spend(signature sig, bytes32 txid) {
        let group = tx.assetGroups.find(txid, 0);
        let total = 0;
        require(checkSig(sig, owner));
    }
}`;

const top = labels('    require(', source);
for (const label of ['checkSig', 'substr', 'tx', 'owner', 'sig', 'group', 'total', 'spend', 'Point', 'Demo']) assert(top.includes(label), label);
assert(!top.some(label => label.includes('.')));
assert.equal(top.length, new Set(top).size);

assert(labels('tx.').includes('inputs'));
assert(labels('require(tx . ').includes('assetGroups'));
assert.deepEqual(labels('tx.outputs[0].'), ['value', 'scriptPubKey', 'assets']);
assert(labels('tx.inputs[this.activeInputIndex].').includes('arkadeScriptHash'));
assert(labels('tx.inputs[i].assets.').includes('lookup'));
assert.deepEqual(labels('tx.outputs[o].assets[0].'), ['assetId', 'amount']);
assert(labels('tx.assetGroups[k].').includes('sumOutputs'));
assert(labels('tx.input.current.').includes('value'));
assert(labels('this.').includes('activeInputIndex'));
assert(labels('group.', source).includes('controlIs'));
assert.deepEqual(labels('points[1].', source), ['x', 'y']);
assert.deepEqual(labels('amounts.', source), ['length']);
assert.deepEqual(labels('unknown.', source), []);
assert(complete('tx.', '').find(item => item.label === 'inputs').snippet);
