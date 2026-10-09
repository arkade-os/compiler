package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
)

func TestRuntimeIntentPaths(t *testing.T) {
	source := filepath.Join(t.TempDir(), "intent.ark")
	err := os.WriteFile(source, []byte(`
contract IntentPath() {
    function spend(bytes path, bytes expected, int present) {
        require(tx.intent.has(path) == (present == 1));
        if (present == 1) {
            require(tx.intent.field(path) == expected);
        }
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := covenantGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	message := arkade.WithIntentMessage(`{"type":"register","owner":{"name":"alice"}}`)
	for _, tc := range []struct {
		name, path, expected string
		present              int64
		wantErr              string
	}{
		{"top-level field", "type", "register", 1, ""},
		{"nested field", "owner.name", "alice", 1, ""},
		{"missing field", "fee", "", 0, ""},
		{"wrong value", "type", "redeem", 1, "OP_EQUALVERIFY failed"},
		{"invalid path", "Type", "", 0, "invalid intent message path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deployment := fundingTx(instance.pkScript, 10_000)
			values := map[string][]byte{"path": []byte(tc.path), "expected": []byte(tc.expected), "present": scriptInt(t, tc.present)}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr, message)
		})
	}
}
