package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func TestGroupControlAssetId(t *testing.T) {
	source := filepath.Join(t.TempDir(), "group_control.ark")
	err := os.WriteFile(source, []byte(`
contract GroupControl() {
    function spend(bytes32 ctrlTxid, int ctrlGidx) {
        let g = 0;
        AssetId control = g.controlAssetId;
        require(control.txid == ctrlTxid);
        require(control.gidx == ctrlGidx);
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

	controlId := asset.AssetId{Txid: chainhash.Hash{9}, Index: 2}
	otherId := asset.AssetId{Txid: chainhash.Hash{4}, Index: 3}
	byId, err := asset.NewAssetRefFromId(controlId)
	if err != nil {
		t.Fatal(err)
	}
	byGroup, err := asset.NewAssetRefFromGroupIndex(1)
	if err != nil {
		t.Fatal(err)
	}
	issuance := func(control *asset.AssetRef) asset.AssetGroup {
		return asset.AssetGroup{
			ControlAsset: control,
			Outputs:      []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 5}},
		}
	}
	transfer := asset.AssetGroup{
		AssetId: &otherId,
		Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 7}},
		Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 7}},
	}
	for _, tc := range []struct {
		name    string
		packet  asset.Packet
		want    asset.AssetId
		wantErr string
	}{
		{"control by id", asset.Packet{issuance(byId)}, controlId, ""},
		{"control by group", asset.Packet{issuance(byGroup), transfer}, otherId, ""},
		{"wrong control", asset.Packet{issuance(byId)}, otherId, "OP_EQUALVERIFY failed"},
		{"no control", asset.Packet{issuance(nil)}, controlId, "OP_VERIFY failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string][]byte{
				"ctrlTxid": tc.want.Txid[:],
				"ctrlGidx": scriptInt(t, int64(tc.want.Index)),
			}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript,
				covenantWitness(t, contract, group, values), extension.Packet(tc.packet))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
