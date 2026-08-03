package e2e

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
)

func TestSymbolicStackStress(t *testing.T) {
	contract := compileArtifact(t, "contracts/symbolic_stack.ark")
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	ownerKey := fixedPrivateKey(4)
	attestorKey := fixedPrivateKey(5)
	stress := instantiateGroup(
		t,
		contract,
		"spend",
		map[string][]byte{
			"multiplier": scriptInt(t, 2),
			"bias":       scriptInt(t, 3),
			"boundary":   scriptInt(t, 20),
			"owner":      schnorr.SerializePubKey(ownerKey.PubKey()),
		},
		serverKey.PubKey(),
		emulatorKey.PubKey(),
	)
	attestation := bytes.Repeat([]byte{0x42}, 32)
	attestSig := signBIP340(t, attestorKey, attestation)

	testCases := []struct {
		name     string
		left     int64
		right    int64
		carry    int64
		selector int64
		values   [3]int64
		expected int64
	}{
		{
			name:     "high branches",
			left:     4,
			right:    5,
			carry:    6,
			selector: 30,
			values:   [3]int64{7, 8, 9},
			expected: 1_685_251,
		},
		{
			name:     "low branches",
			left:     4,
			right:    5,
			carry:    6,
			selector: 10,
			values:   [3]int64{1, 2, 3},
			expected: 58_178,
		},
		{
			name:     "mixed branches",
			left:     0,
			right:    0,
			carry:    10,
			selector: 10,
			values:   [3]int64{7, 8, 9},
			expected: -38_753,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			witness := wire.TxWitness{
				attestation,
				attestSig,
				schnorr.SerializePubKey(attestorKey.PubKey()),
				nil,
				scriptInt(t, testCase.values[2]),
				scriptInt(t, testCase.values[1]),
				scriptInt(t, testCase.values[0]),
				scriptInt(t, testCase.expected),
				scriptInt(t, testCase.selector),
				scriptInt(t, testCase.carry),
				scriptInt(t, testCase.right),
				scriptInt(t, testCase.left),
			}
			deployment := fundingTx(stress.pkScript, 10_000)
			unsigned := spendingPSBTWithWitness(
				t, deployment, stress, 10_000, stress.pkScript, witness,
			)
			witness[3] = signArkadeSighash(t, unsigned, 0, ownerKey)
			signed := spendingPSBTWithWitness(
				t, deployment, stress, 10_000, stress.pkScript, witness,
			)

			requireVMResult(t, signed, emulatorKey.PubKey(), "")
		})
	}
}
