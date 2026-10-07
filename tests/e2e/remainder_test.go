package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemainderOperator(t *testing.T) {
	source := filepath.Join(t.TempDir(), "remainder.ark")
	err := os.WriteFile(source, []byte(`
contract Remainder() {
    function spend(int n, int m, int r) {
        require(n % m == r);
        require(7 % 3 == 1);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := covenantGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(instance.pkScript, 10_000)
	for _, tc := range []struct {
		name    string
		n, m, r int64
		wantErr string
	}{
		{"positive operands", 17, 5, 2, ""},
		{"sign of the dividend", -7, 2, -1, ""},
		{"negative divisor", 7, -2, 1, ""},
		{"wrong remainder", 17, 5, 3, "OP_EQUALVERIFY failed"},
		{"modulo by zero", 17, 0, 0, "modulo by zero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string][]byte{"n": scriptInt(t, tc.n), "m": scriptInt(t, tc.m), "r": scriptInt(t, tc.r)}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
