package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func TestGroupInputAndOutputRecords(t *testing.T) {
	source := filepath.Join(t.TempDir(), "group_records.ark")
	err := os.WriteFile(source, []byte(`
contract GroupRecords() {
    function spend(AssetGroup g, int j, int amount, int kind, int index) {
        require(g.inputs[j].amount == amount);
        require(g.inputs[j].type == kind);
        require(g.inputs[j].index == index);
        require(g.outputs[0].index == 1);
        require(g.outputs[0].amount == amount);
    }
    function source(AssetGroup g, bytes32 txid) {
        require(g.inputs[0].txid == txid);
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

	local, intent := asset.AssetId{Txid: chainhash.Hash{4}, Index: 3}, asset.AssetId{Txid: chainhash.Hash{5}, Index: 0}
	// A group's inputs share one type, so each kind gets its own group.
	packet := asset.Packet{
		{
			AssetId: &local,
			Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 7}},
			Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 7}},
		},
		{
			AssetId: &intent,
			Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeIntent, Txid: chainhash.Hash{8}, Vin: 3, Amount: 11}},
			Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 11}},
		},
	}
	sourceGroup := covenantGroup(t, contract, "source")
	sourceInstance := instantiateGroup(t, contract, "source", nil, serverKey.PubKey(), emulatorKey.PubKey())
	sourceDeployment := fundingTx(sourceInstance.pkScript, 10_000)
	for _, tc := range []struct {
		name    string
		g       int64
		txid    chainhash.Hash
		wantErr string
	}{
		{"intent txid", 1, chainhash.Hash{8}, ""},
		{"wrong txid", 1, chainhash.Hash{9}, "false stack entry"},
		{"local input has no txid", 0, chainhash.Hash{8}, "OP_EQUALVERIFY failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string][]byte{"g": scriptInt(t, tc.g), "txid": tc.txid[:]}
			spend := spendingPSBTWithWitness(t, sourceDeployment, sourceInstance, 10_000, sourceInstance.pkScript,
				covenantWitness(t, contract, sourceGroup, values), extension.Packet(packet))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
	for _, tc := range []struct {
		name                      string
		g, j, amount, kind, index int64
		wantErr                   string
	}{
		{"local input", 0, 0, 7, 1, 0, ""},
		{"intent input", 1, 0, 11, 2, 3, ""},
		{"wrong amount", 1, 0, 7, 2, 3, "OP_EQUALVERIFY failed"},
		{"wrong type", 0, 0, 7, 2, 0, "OP_EQUALVERIFY failed"},
		{"wrong index", 1, 0, 11, 2, 0, "OP_EQUALVERIFY failed"},
		{"input out of range", 0, 1, 7, 1, 0, "input index out of range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string][]byte{
				"g": scriptInt(t, tc.g), "j": scriptInt(t, tc.j), "amount": scriptInt(t, tc.amount),
				"kind": scriptInt(t, tc.kind), "index": scriptInt(t, tc.index),
			}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript,
				covenantWitness(t, contract, group, values), extension.Packet(packet))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
