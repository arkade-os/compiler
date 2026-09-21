import assert from 'node:assert/strict';
import {
    escrowFlowMarkup,
    escrowTechnicalDetailsMarkup,
    supportsEscrowFlow,
} from './escrow-flow.js';

const artifact = {
    contractName: 'Escrow',
    constructorInputs: [
        'partyAPk',
        'partyBPk',
        'oraclePk',
        'oracleMessageHash',
        'partyAScript',
        'partyBScript',
        'amount',
        'timeoutHeight',
        'exit',
    ].map(name => ({ name })),
    functions: ['complete', 'cancel', 'unilateral'].map(name => ({ name })),
};

assert.equal(supportsEscrowFlow(artifact), true);
assert.equal(supportsEscrowFlow({ ...artifact, contractName: 'Other' }), false);
assert.equal(
    supportsEscrowFlow({
        ...artifact,
        functions: artifact.functions.filter(group => group.name !== 'unilateral'),
    }),
    false,
);

const highLevel = escrowFlowMarkup();
for (const copy of [
    'One deposit. Three safe outcomes.',
    'Party B gets paid',
    'Party A gets a full refund',
    'Both parties decide together',
]) {
    assert.match(highLevel, new RegExp(copy.replace(/[.]/g, '\\.')));
}
assert.doesNotMatch(highLevel, /partyBScript|timeoutHeight|Output 0/);
assert.equal((highLevel.match(/Technical details/g) || []).length, 3);

const completeDetails = escrowTechnicalDetailsMarkup('complete');
assert.match(completeDetails, /Output 0/);
assert.match(completeDetails, /partyBScript/);
assert.match(completeDetails, /Raw script parameter/);

const unilateralDetails = escrowTechnicalDetailsMarkup('unilateral');
assert.match(unilateralDetails, /older\(exit\)/);
assert.match(unilateralDetails, /Unconstrained/);

const modified = escrowFlowMarkup({ modified: true });
assert.match(modified, /Bespoke view—verify after edits/);

console.log('Verified Escrow flow summary, technical disclosure, and artifact guard.');
