package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/wire"
)

func TestCheckedCasts(t *testing.T) {
	source := filepath.Join(t.TempDir(), "casts.ark")
	err := os.WriteFile(source, []byte(`
contract Casts() {
    function spend(bytes raw) {
        bytes32 id = bytes32(raw);
        require(id != 0x00);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(group.pkScript, 10_000)
	for _, tc := range []struct {
		name    string
		value   []byte
		wantErr string
	}{
		{"exact length", bytes.Repeat([]byte{7}, 32), ""},
		{"short", bytes.Repeat([]byte{7}, 31), "OP_EQUALVERIFY failed"},
		{"long", bytes.Repeat([]byte{7}, 33), "OP_EQUALVERIFY failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spend := spendingPSBTWithWitness(t, deployment, group, 10_000, group.pkScript, wire.TxWitness{tc.value})
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
