package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCompositeComparisonExpressions(t *testing.T) {
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	for _, width := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("width%d", width), func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "compare.ark")
			code := fmt.Sprintf(`
struct Item { int[%d] values; }
struct Wrapped { Item item; }
contract C() {
    private function same(Wrapped a, Wrapped b) bool { return a == b; }
    private function checked(Wrapped value) Wrapped {
        require(tx.outputs[0].value > 0);
        return value;
    }
    private function fail(Wrapped value) Wrapped { require(false); return value; }
    function spend(Wrapped left, Wrapped right, bool expected, int index, bool selectedMatches) {
        bool equal = left == right;
        require(equal == expected);
        equal = left != right;
        require(equal == !expected);
        require(same(left, right) == expected);
        require((checked(left) == checked(right)) == expected);
        require((left.item.values == right.item.values) == expected);
        require((left.item.values != right.item.values) == !expected);
        Wrapped[2] choices = [left, right];
        require((choices[index] == left) == selectedMatches);
        if (left == right) { require(expected); } else { require(!expected); }
        require(left == right || left != right);
        require(!(left == right && left != right));
        bool skip = expected || !expected;
        require(skip || fail(left) == right);
        require(!(!skip && fail(left) == right));
    }
    function guarded(bool skip, Wrapped value) {
        require(skip || fail(value) == value);
    }
}`, width)
			if err := os.WriteFile(source, []byte(code), 0600); err != nil {
				t.Fatal(err)
			}
			contract := compileArtifact(t, source)
			group := covenantGroup(t, contract, "spend")
			inspections := 0
			for _, token := range group.Arkade.ASM {
				if token == "OP_INSPECTOUTPUTVALUE" {
					inspections++
				}
			}
			if inspections != 2 {
				t.Fatalf("comparison operands evaluated %d times, want 2", inspections)
			}
			instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10_000)
			for different := -1; different < width; different++ {
				for index := 0; index < 2; index++ {
					for _, wrongExpectation := range []bool{false, true} {
						t.Run(fmt.Sprintf("different%d/index%d/wrong%v", different, index, wrongExpectation), func(t *testing.T) {
							expected := int64(0)
							if (different == -1) != wrongExpectation {
								expected = 1
							}
							selectedMatches := int64(0)
							if index == 0 || different == -1 {
								selectedMatches = 1
							}
							values := map[string][]byte{
								"expected": scriptInt(t, expected), "index": scriptInt(t, int64(index)),
								"selectedMatches": scriptInt(t, selectedMatches),
							}
							for i := 0; i < width; i++ {
								left, right := int64(i+1), int64(i+1)
								if i == different {
									right = 99
								}
								values[fmt.Sprintf("left.item.values.%d", i)] = scriptInt(t, left)
								values[fmt.Sprintf("right.item.values.%d", i)] = scriptInt(t, right)
							}
							wantErr := ""
							if wrongExpectation {
								wantErr = "OP_EQUALVERIFY failed"
							}
							spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
							requireVMResult(t, spend, emulatorKey.PubKey(), wantErr)
						})
					}
				}
			}
			guarded := instantiateGroup(t, contract, "guarded", nil, serverKey.PubKey(), emulatorKey.PubKey())
			for _, skip := range []int64{0, 1} {
				values := map[string][]byte{"skip": scriptInt(t, skip)}
				for i := 0; i < width; i++ {
					values[fmt.Sprintf("value.item.values.%d", i)] = scriptInt(t, int64(i))
				}
				wantErr := ""
				if skip == 0 {
					wantErr = "OP_VERIFY failed"
				}
				spend := spendingPSBTWithWitness(t, fundingTx(guarded.pkScript, 10_000), guarded, 10_000, guarded.pkScript, covenantWitness(t, contract, covenantGroup(t, contract, "guarded"), values))
				requireVMResult(t, spend, emulatorKey.PubKey(), wantErr)
			}
		})
	}
}

func TestNativeScriptComparisonExpressions(t *testing.T) {
	source := filepath.Join(t.TempDir(), "script.ark")
	if err := os.WriteFile(source, []byte(`
contract C() {
    function spend(bool expected) {
        require((tx.outputs[0].script == tx.input.current.script) == expected);
        require((tx.outputs[0].script != tx.input.current.script) == !expected);
    }
}`), 0600); err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	otherVersion := slices.Clone(instance.pkScript)
	otherVersion[0] = 0
	otherProgram := slices.Clone(instance.pkScript)
	otherProgram[len(otherProgram)-1] ^= 1
	for _, tc := range []struct {
		name     string
		pkScript []byte
		expected int64
	}{
		{"matching", instance.pkScript, 1},
		{"wrong version", otherVersion, 0},
		{"wrong program", otherProgram, 0},
		{"non-witness", []byte{0x51}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			witness := covenantWitness(t, contract, covenantGroup(t, contract, "spend"), map[string][]byte{"expected": scriptInt(t, tc.expected)})
			spend := spendingPSBTWithWitness(t, fundingTx(instance.pkScript, 10_000), instance, 10_000, tc.pkScript, witness)
			requireVMResult(t, spend, emulatorKey.PubKey(), "")
		})
	}
}
