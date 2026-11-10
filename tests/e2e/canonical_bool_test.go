package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBoolWitnessesMustBeCanonical(t *testing.T) {
	source := filepath.Join(t.TempDir(), "canonical_bool.ark")
	err := os.WriteFile(source, []byte(`
struct Flag { bool value; }
contract CanonicalBool() {
    function truthy(bool flag) {
        require(flag);
    }
    function notTrue(bool flag) {
        require(flag != true);
    }
    function field(Flag flag) {
        require(flag.value != true);
    }
    function element(bool[2] flags) {
        require(flags[1] != true);
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
		{"true", "truthy", map[string][]byte{"flag": {0x01}}, ""},
		{"false", "truthy", map[string][]byte{"flag": {}}, "false stack entry"},
		{"two", "truthy", map[string][]byte{"flag": {0x02}}, "OP_EQUALVERIFY failed"},
		{"negative one", "truthy", map[string][]byte{"flag": {0x81}}, "OP_EQUALVERIFY failed"},
		{"non-minimal zero", "truthy", map[string][]byte{"flag": {0x00}}, "minimally encoded"},
		{"non-minimal one", "truthy", map[string][]byte{"flag": {0x01, 0x00}}, "minimally encoded"},
		{"false is not true", "notTrue", map[string][]byte{"flag": {}}, ""},
		{"two is not a bool", "notTrue", map[string][]byte{"flag": {0x02}}, "OP_EQUALVERIFY failed"},
		{"false field", "field", map[string][]byte{"flag.value": {}}, ""},
		{"two in a field", "field", map[string][]byte{"flag.value": {0x02}}, "OP_EQUALVERIFY failed"},
		{"false element", "element", map[string][]byte{"flags.0": {0x01}, "flags.1": {}}, ""},
		{"two in an element", "element", map[string][]byte{"flags.0": {0x01}, "flags.1": {0x02}}, "OP_EQUALVERIFY failed"},
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
