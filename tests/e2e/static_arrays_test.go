package e2e

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Mirrors contracts/static_arrays.ark, computed independently of the compiler.
// scale is [1, 2, 3] with element 1 reassigned to 10.
func expectedTotal(weights [4]int64, samples [5]int64, index, scaleIndex int64) int64 {
	scale := [3]int64{1, 10, 3}
	total := samples[index]*scale[scaleIndex] + scale[0]
	for i, weight := range weights {
		total += weight * int64(i+1)
	}
	for j, sample := range samples {
		if sample > 0 {
			total += sample * int64(j+1)
		} else {
			total -= 3
		}
	}
	return total
}

func TestStaticArrays(t *testing.T) {
	contract := compileArtifact(t, "contracts/static_arrays.ark")
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	ownerKey := fixedPrivateKey(4)

	// The ABI keeps one entry per source parameter, sized.
	if got := contract.ConstructorInputs[0]; got.Name != "weights" || got.Type != "int[4]" {
		t.Fatalf("constructor input 0 = %+v, want weights int[4]", got)
	}
	group := covenantGroup(t, contract, "spend")
	if got := group.Arkade.Inputs[3]; got.Name != "samples" || got.Type != "int[5]" {
		t.Fatalf("covenant input 3 = %+v, want samples int[5]", got)
	}

	weights := [4]int64{2, 3, 5, 7}
	// Constructor arrays expand into one placeholder per element.
	constructorValues := map[string][]byte{
		"owner": schnorr.SerializePubKey(ownerKey.PubKey()),
	}
	for i, weight := range weights {
		constructorValues[fmt.Sprintf("weights_%d", i)] = scriptInt(t, weight)
	}
	arrays := instantiateGroup(
		t, contract, "spend", constructorValues, serverKey.PubKey(), emulatorKey.PubKey(),
	)

	testCases := []struct {
		name       string
		index      int64
		scaleIndex int64
		samples    [5]int64
		total      int64
		wantErr    string
	}{
		// scaleIndex indexes the local array at runtime, so these also pin the
		// order its elements are pushed in.
		{name: "first element", index: 0, scaleIndex: 0, samples: [5]int64{4, 6, 8, 1, 2}},
		{name: "middle element", index: 2, scaleIndex: 1, samples: [5]int64{5, -1, 7, 0, 9}},
		{name: "last element", index: 4, scaleIndex: 2, samples: [5]int64{1, 2, 3, 4, 5}},
		{
			name:    "index past the declared size is rejected",
			index:   5,
			samples: [5]int64{1, 2, 3, 4, 5},
			wantErr: "OP_VERIFY failed",
		},
		{
			// A negative index isolates the lower bound check: without it,
			// OP_PICK would fail on the negative depth rather than OP_VERIFY.
			name:    "negative index fails the bound check",
			index:   -1,
			samples: [5]int64{1, 2, 3, 4, 5},
			wantErr: "OP_VERIFY failed",
		},
		{
			name:       "local array index past its declared size is rejected",
			index:      1,
			scaleIndex: 3,
			samples:    [5]int64{1, 2, 3, 4, 5},
			wantErr:    "OP_VERIFY failed",
		},
		{
			name:    "wrong total is rejected",
			index:   1,
			samples: [5]int64{1, 2, 3, 4, 5},
			total:   1,
			wantErr: "OP_VERIFY failed",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			total := testCase.total
			if total == 0 {
				index := testCase.index
				if index < 0 || index >= int64(len(testCase.samples)) {
					index = 0
				}
				scaleIndex := testCase.scaleIndex
				if scaleIndex < 0 || scaleIndex > 2 {
					scaleIndex = 0
				}
				total = expectedTotal(weights, testCase.samples, index, scaleIndex)
			}

			values := map[string][]byte{
				"index":      scriptInt(t, testCase.index),
				"scaleIndex": scriptInt(t, testCase.scaleIndex),
				"expected":   scriptInt(t, total),
				"ownerSig":   nil,
			}
			for i, sample := range testCase.samples {
				values[fmt.Sprintf("samples_%d", i)] = scriptInt(t, sample)
			}

			deployment := fundingTx(arrays.pkScript, 10_000)
			unsigned := spendingPSBTWithWitness(
				t, deployment, arrays, 10_000, arrays.pkScript,
				covenantWitness(t, group, values),
			)
			values["ownerSig"] = signArkadeSighash(t, unsigned, 0, ownerKey)
			signed := spendingPSBTWithWitness(
				t, deployment, arrays, 10_000, arrays.pkScript,
				covenantWitness(t, group, values),
			)

			requireVMResult(t, signed, emulatorKey.PubKey(), testCase.wantErr)
		})
	}
}
