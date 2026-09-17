package e2e

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func TestTunnel(t *testing.T) {
	contract := compileArtifact(t, "contracts/new_opcodes.ark")
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	id := asset.AssetId{Txid: chainhash.Hash{4}, Index: 3}
	for _, test := range []struct {
		name         string
		function     string
		amount       int64
		assets       uint64
		gidx         int64
		outputIndex  int64
		changeScript bool
		wantErr      string
	}{
		{name: "all preserved", function: "all", amount: 10000, assets: 7},
		{name: "value mismatch", function: "all", amount: 9999, assets: 7, wantErr: "does not preserve source value"},
		{name: "asset mismatch", function: "all", amount: 10000, assets: 6, wantErr: "does not preserve source assets"},
		{name: "script mismatch", function: "all", amount: 10000, assets: 7, changeScript: true, wantErr: "does not preserve source script"},
		{name: "negative index", function: "all", amount: 10000, assets: 7, outputIndex: -1, wantErr: "output index out of range"},
		{name: "bound and helper exceptions", function: "except", amount: 10000, assets: 6, gidx: 3},
		{name: "wrong exception", function: "except", amount: 10000, assets: 6, gidx: 2, wantErr: "does not preserve source assets"},
		{name: "native exception", function: "native", amount: 10000, assets: 6},
	} {
		t.Run(test.name, func(t *testing.T) {
			group := covenantGroup(t, contract, test.function)
			instance := instantiateGroup(t, contract, test.function, nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10000)
			packet := asset.Packet{{
				AssetId: &id,
				Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 7}},
				Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: test.assets}},
			}}
			values := map[string][]byte{
				"outputIndex":    scriptInt(t, test.outputIndex),
				"exception.txid": id.Txid[:],
				"exception.gidx": scriptInt(t, test.gidx),
			}
			outputScript := instance.pkScript
			if test.changeScript {
				outputScript = p2trScript(t, []byte{0x51})
			}
			ptx := spendingPSBTWithWitness(t, deployment, instance, test.amount, outputScript,
				covenantWitness(t, contract, group, values), packet)
			requireVMResult(t, ptx, emulatorKey.PubKey(), test.wantErr)
		})
	}
}
