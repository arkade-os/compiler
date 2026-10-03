package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/wire"
)

func TestWitnessVersion(t *testing.T) {
	source := filepath.Join(t.TempDir(), "witness_version.ark")
	err := os.WriteFile(source, []byte(`
contract WitnessVersion() {
    function spend(int version) {
        require(tx.input.current.witnessVersion == 1);
        require(tx.inputs[0].witnessVersion == 1);
        require(tx.inputs[1].witnessVersion == -1);
        require(tx.outputs[0].witnessVersion == version);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(group.pkScript, 10_000)
	p2wpkh := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{7}, 20)...)
	p2pkh := append(append([]byte{0x76, 0xa9, 0x14}, bytes.Repeat([]byte{7}, 20)...), 0x88, 0xac)
	for _, tc := range []struct {
		name     string
		pkScript []byte
		version  int64
		wantErr  string
	}{
		{"taproot output", group.pkScript, 1, ""},
		{"segwit v0 output", p2wpkh, 0, ""},
		{"non-witness output", p2pkh, -1, ""},
		{"wrong version", group.pkScript, 0, "false stack entry"},
		{"non-witness is not v0", p2pkh, 0, "false stack entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spend := spendingPSBTWithWitness(t, deployment, group, 10_000, tc.pkScript, wire.TxWitness{scriptInt(t, tc.version)})
			spend = withExtraInput(t, spend, fundingTx(p2pkh, 10_000))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
