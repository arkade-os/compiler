package e2e

import (
	"fmt"
	"testing"
)

func TestPrivateFunctions(t *testing.T) {
	contract := compileArtifact(t, "contracts/private_functions.ark")
	if len(contract.Functions) != 1 || contract.Functions[0].Name != "spend" {
		t.Fatalf("private functions leaked into ABI: %+v", contract.Functions)
	}
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	point := fixedPrivateKey(9).PubKey().SerializeUncompressed()
	group := covenantGroup(t, contract, "spend")
	instantiated := instantiateGroup(t, contract, "spend", map[string][]byte{
		"config.minimum":   scriptInt(t, 5),
		"config.offsets.0": scriptInt(t, 2),
		"config.offsets.1": scriptInt(t, 3),
	}, serverKey.PubKey(), emulatorKey.PubKey())

	for _, tc := range []struct {
		name        string
		values      [3]int64
		pass        bool
		wrongResult bool
	}{
		{name: "return in first iteration", values: [3]int64{8, 9, 10}, pass: true},
		{name: "return in middle iteration", values: [3]int64{1, 7, 9}, pass: true},
		{name: "return in last iteration", values: [3]int64{1, 2, 6}, pass: true},
		{name: "fallthrough return", values: [3]int64{1, 2, 3}, pass: true},
		{name: "helper requirement fails", values: [3]int64{8, 9, 10}},
		{name: "caller resumes and checks result", values: [3]int64{1, 7, 9}, pass: true, wrongResult: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected, nested := int64(5), int64(5)
			for i, value := range tc.values {
				if value >= 5 {
					selected = value + 5 + int64(i)
					nested = value + int64(i)
					break
				}
			}
			expected := 100 + (selected+5)*2 + selected + nested
			wantErr := ""
			if !tc.pass || tc.wrongResult {
				wantErr = "OP_VERIFY failed"
			}
			if tc.wrongResult {
				expected++
			}
			pass := int64(0)
			if tc.pass {
				pass = 1
			}
			inputs := map[string][]byte{
				"expected": scriptInt(t, expected),
				"pass":     scriptInt(t, pass),
				"x":        scriptPositiveBigInt(t, point[1:33]),
				"y":        scriptPositiveBigInt(t, point[33:]),
			}
			for i, value := range tc.values {
				inputs[fmt.Sprintf("values.%d", i)] = scriptInt(t, value)
			}
			deployment := fundingTx(instantiated.pkScript, 10_000)
			spending := spendingPSBTWithWitness(t, deployment, instantiated, 10_000, instantiated.pkScript, covenantWitness(t, contract, group, inputs))
			requireVMResult(t, spending, emulatorKey.PubKey(), wantErr)
		})
	}
}
