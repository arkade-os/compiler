package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNumericEqualityRejectsNonMinimalNumbers(t *testing.T) {
	source := filepath.Join(t.TempDir(), "numeric_equality.ark")
	err := os.WriteFile(source, []byte(`
contract NumericEquality() {
    function differs(int x) {
        require(x != 5);
    }
    function branches(int x, bool flag) {
        if (x == 5) {
            require(false);
        }
        require(flag != false);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	for _, tc := range []struct {
		name, function string
		values         map[string][]byte
		wantErr        string
	}{
		{"different number", "differs", map[string][]byte{"x": {0x06}}, ""},
		{"equal number", "differs", map[string][]byte{"x": {0x05}}, "false stack entry"},
		{"non-minimal equal number", "differs", map[string][]byte{"x": {0x05, 0x00}}, "minimally encoded"},
		{"other branch", "branches", map[string][]byte{"x": {0x06}, "flag": {0x01}}, ""},
		{"non-minimal number in a branch", "branches", map[string][]byte{"x": {0x05, 0x00}, "flag": {0x01}}, "minimally encoded"},
		{"negative zero bool", "branches", map[string][]byte{"x": {0x06}, "flag": {0x80}}, "minimally encoded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := covenantGroup(t, contract, tc.function)
			instance := instantiateGroup(t, contract, tc.function, nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10_000)
			witness := covenantWitness(t, contract, group, tc.values)
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, witness)
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
