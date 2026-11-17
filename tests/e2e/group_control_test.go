package e2e

import (
	"crypto/sha256"
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
    function spend(AssetGroup g, AssetId ctrl) {
        AssetId control = g.controlAssetId;
        require(control.txid == ctrl.txid);
        require(control.gidx == ctrl.gidx);
        require(g.delta == 5);
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
				"g":         scriptInt(t, 0),
				"ctrl.txid": tc.want.Txid[:],
				"ctrl.gidx": scriptInt(t, int64(tc.want.Index)),
			}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript,
				covenantWitness(t, contract, group, values), extension.Packet(tc.packet))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}

func TestComputedAssetIdTxid(t *testing.T) {
	source := filepath.Join(t.TempDir(), "computed_txid.ark")
	err := os.WriteFile(source, []byte(`
contract ComputedTxid() {
    function spend(bytes d, bytes e, int g) {
        require(tx.outputs[0].assets.has({ txid: sha256(d), gidx: 3 }));
        require(tx.outputs[0].assets.lookup(tx.inputs[0].assets[0].assetId) == 7);
        require(tx.assetGroups[0].controlIs(AssetId { txid: id(d), gidx: 2 }));
        require(tx.assetGroups[0].controlIs(make(e, g)));
    }
    private function id(bytes d) bytes32 { return sha256(d); }
    private function make(bytes e, int g) AssetId { return AssetId { txid: sha256(e), gidx: g }; }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := covenantGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(instance.pkScript, 10_000)

	preimage := []byte("computed asset id")
	txid := chainhash.Hash(sha256.Sum256(preimage))
	transferId := asset.AssetId{Txid: txid, Index: 3}
	transfer := asset.AssetGroup{
		AssetId: &transferId,
		Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 7}},
		Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 7}},
	}
	control := asset.AssetId{Txid: txid, Index: 2}
	other := []byte("other")
	// The literal check reads the control id field by field; the helper's id is compared whole.
	for _, tc := range []struct {
		name     string
		preimage []byte
		helper   []byte
		gidx     int64
		control  asset.AssetId
		wantErr  string
	}{
		{"computed ids", preimage, preimage, 2, control, ""},
		{"wrong preimage", other, preimage, 2, control, "OP_VERIFY failed"},
		{"wrong control txid", preimage, preimage, 2, asset.AssetId{Txid: chainhash.Hash{9}, Index: 2}, "OP_VERIFY failed"},
		{"wrong control gidx", preimage, preimage, 2, asset.AssetId{Txid: txid, Index: 1}, "OP_VERIFY failed"},
		{"wrong helper txid", preimage, other, 2, control, "false stack entry"},
		{"wrong helper gidx", preimage, preimage, 1, control, "false stack entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			control, err := asset.NewAssetRefFromId(tc.control)
			if err != nil {
				t.Fatal(err)
			}
			issuance := asset.AssetGroup{
				ControlAsset: control,
				Outputs:      []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 5}},
			}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript,
				covenantWitness(t, contract, group, map[string][]byte{
					"d": tc.preimage, "e": tc.helper, "g": scriptInt(t, tc.gidx),
				}),
				extension.Packet(asset.Packet{issuance, transfer}))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}

func TestControlIsSeesOneEncodingPerGidx(t *testing.T) {
	source := filepath.Join(t.TempDir(), "control_gate.ark")
	err := os.WriteFile(source, []byte(`
contract ControlGate(AssetId banned) {
    function byWitness(AssetId id) {
        require(id.txid == 0x0900000000000000000000000000000000000000000000000000000000000000);
        require(bytes(id.gidx) == 0x02);
        require(!tx.assetGroups[0].controlIs(id));
    }
    function byConstructor() {
        require(!tx.assetGroups[0].controlIs(banned));
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	txid := chainhash.Hash{9}
	control, err := asset.NewAssetRefFromId(asset.AssetId{Txid: txid, Index: 2})
	if err != nil {
		t.Fatal(err)
	}
	issuance := asset.AssetGroup{
		ControlAsset: control,
		Outputs:      []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 5}},
	}
	// 0x0200 pads 2: bytes() accepts it, and byte equality with the control gidx would not.
	for _, tc := range []struct {
		name, function string
		gidx           []byte
		wantErr        string
	}{
		{"witness", "byWitness", []byte{0x02}, "false stack entry"},
		{"padded witness", "byWitness", []byte{0x02, 0x00}, "minimally encoded"},
		{"constructor", "byConstructor", []byte{0x02}, "false stack entry"},
		{"padded constructor", "byConstructor", []byte{0x02, 0x00}, "minimally encoded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string][]byte{"banned.txid": txid[:], "banned.gidx": tc.gidx, "id.txid": txid[:], "id.gidx": tc.gidx}
			group := covenantGroup(t, contract, tc.function)
			instance := instantiateGroup(t, contract, tc.function, values, serverKey.PubKey(), emulatorKey.PubKey())
			spend := spendingPSBTWithWitness(t, fundingTx(instance.pkScript, 10_000), instance, 10_000, instance.pkScript,
				covenantWitness(t, contract, group, values), extension.Packet(asset.Packet{issuance}))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
