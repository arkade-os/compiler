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
        require(tx.inputs[1].witnessVersion == 0);
        require(tx.outputs[0].witnessVersion == version);
        let input = tx.inputs[1].script;
        require(input.version == 0);
        require(input.program == tx.inputs[1].scriptPubKey);
        let output = tx.outputs[0].script;
        require(output.version == version);
        require(output.program == tx.outputs[0].scriptPubKey);
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
	for _, tc := range []struct {
		name     string
		pkScript []byte
		version  int64
		wantErr  string
	}{
		{"taproot output", group.pkScript, 1, ""},
		{"segwit v0 output", p2wpkh, 0, ""},
		{"wrong version", group.pkScript, 0, "OP_EQUALVERIFY failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spend := spendingPSBTWithWitness(t, deployment, group, 10_000, tc.pkScript, wire.TxWitness{scriptInt(t, tc.version)})
			spend = withExtraInput(t, spend, fundingTx(p2wpkh, 10_000))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
