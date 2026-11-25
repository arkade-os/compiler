package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
)

func TestRuntimeProofPaths(t *testing.T) {
	source := filepath.Join(t.TempDir(), "proof.ark")
	err := os.WriteFile(source, []byte(`
contract ProofPath() {
    function spend(bytes path, bytes expected, int present) {
        require(tx.proof.has(path) == (present == 1));
        if (present == 1) {
            require(tx.proof.field(path) == expected);
        }
    }
    function read(bytes path, bytes expected) {
        require(tx.proof.field(path) == expected);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	message := arkade.WithIntentMessage(`{"type":"register","owner":{"name":"alice"}}`)
	for _, tc := range []struct {
		name, function, path, expected string
		present                        int64
		wantErr                        string
	}{
		{"top-level field", "spend", "type", "register", 1, ""},
		{"nested field", "spend", "owner.name", "alice", 1, ""},
		{"missing field", "spend", "fee", "", 0, ""},
		{"wrong value", "spend", "type", "redeem", 1, "OP_EQUALVERIFY failed"},
		{"invalid path", "spend", "Type", "", 0, "invalid intent message path"},
		{"invalid field path", "read", "Type", "", 0, "invalid intent message path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := arkadeScriptGroup(t, contract, tc.function)
			instance := instantiateGroup(t, contract, tc.function, nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10_000)
			values := map[string][]byte{"path": []byte(tc.path), "expected": []byte(tc.expected), "present": scriptInt(t, tc.present)}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, arkadeScriptWitness(t, contract, group, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr, message)
		})
	}
}
