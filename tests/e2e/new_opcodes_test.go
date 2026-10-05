package e2e

import (
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
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

func TestOpcodeExecutionContext(t *testing.T) {
	contract := compileArtifact(t, "contracts/new_opcodes.ark")
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	message := arkade.WithIntentMessage(`{"type":"register","expire_at":0,"enabled":false,"empty":"","items":[7]}`)
	for _, test := range []struct {
		name     string
		function string
		inputs   map[string][]byte
		options  []arkade.ExecuteOption
		wantErr  string
	}{
		{name: "expiry", function: "expiry", inputs: map[string][]byte{"expected": scriptInt(t, 123456)}, options: []arkade.ExecuteOption{arkade.WithExpiry(123456)}},
		{name: "missing expiry", function: "expiry", inputs: map[string][]byte{"expected": scriptInt(t, 123456)}, wantErr: "expiry not set"},
		{name: "past clock", function: "clock", inputs: map[string][]byte{"deadline": scriptInt(t, 0)}},
		{name: "future clock", function: "clock", inputs: map[string][]byte{"deadline": scriptInt(t, 9223372036854775807)}, wantErr: "OP_VERIFY failed"},
		{name: "negative clock", function: "clock", inputs: map[string][]byte{"deadline": scriptInt(t, -1)}, wantErr: "negative timestamp"},
		{name: "intent fields including false zero and empty", function: "intent", options: []arkade.ExecuteOption{message}},
		{name: "missing intent", function: "intent", wantErr: "OP_VERIFY failed"},
		{name: "missing field", function: "intent", options: []arkade.ExecuteOption{arkade.WithIntentMessage(`{"type":"register"}`)}, wantErr: "OP_VERIFY failed"},
		{name: "fractional field", function: "intent", options: []arkade.ExecuteOption{arkade.WithIntentMessage(`{"type":"register","expire_at":0.5}`)}, wantErr: "OP_VERIFY failed"},
		{name: "null field", function: "intent", options: []arkade.ExecuteOption{arkade.WithIntentMessage(`{"type":"register","expire_at":null}`)}, wantErr: "OP_VERIFY failed"},
		{name: "has without context", function: "noIntent"},
		{name: "has with context", function: "noIntent", options: []arkade.ExecuteOption{message}, wantErr: "false stack entry"},
	} {
		t.Run(test.name, func(t *testing.T) {
			group := covenantGroup(t, contract, test.function)
			instance := instantiateGroup(t, contract, test.function, nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10000)
			ptx := spendingPSBTWithWitness(t, deployment, instance, 10000, instance.pkScript,
				covenantWitness(t, contract, group, test.inputs))
			requireVMResult(t, ptx, emulatorKey.PubKey(), test.wantErr, test.options...)
		})
	}
}

func TestECPairing(t *testing.T) {
	contract := compileArtifact(t, "contracts/new_opcodes.ark")
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	_, _, g1, g2 := bn254.Generators()
	var negG1 bn254.G1Affine
	negG1.Neg(&g1)
	coordinate := func(element fp.Element) []byte {
		bytes := element.Bytes()
		return scriptPositiveBigInt(t, bytes[:])
	}
	// e(first, G2) * e(second, G2) == 1 exactly when second == -first.
	pairs := func(prefix string, first, second bn254.G1Affine) map[string][]byte {
		inputs := map[string][]byte{}
		for i, point := range []bn254.G1Affine{first, second} {
			inputs[fmt.Sprintf("%sg1.%d.x", prefix, i)] = coordinate(point.X)
			inputs[fmt.Sprintf("%sg1.%d.y", prefix, i)] = coordinate(point.Y)
			inputs[fmt.Sprintf("%sg2.%d.xC1", prefix, i)] = coordinate(g2.X.A1)
			inputs[fmt.Sprintf("%sg2.%d.xC0", prefix, i)] = coordinate(g2.X.A0)
			inputs[fmt.Sprintf("%sg2.%d.yC1", prefix, i)] = coordinate(g2.Y.A1)
			inputs[fmt.Sprintf("%sg2.%d.yC0", prefix, i)] = coordinate(g2.Y.A0)
		}
		return inputs
	}
	proofs := func(selected bn254.G1Affine) map[string][]byte {
		inputs := pairs("proofs.0.", g1, g1)
		for name, value := range pairs("proofs.1.", g1, selected) {
			inputs[name] = value
		}
		inputs["index"] = scriptInt(t, 1)
		return inputs
	}
	for _, test := range []struct {
		name     string
		function string
		inputs   map[string][]byte
		wantErr  string
	}{
		{name: "balanced pairs", function: "pairing", inputs: pairs("", g1, negG1)},
		{name: "unbalanced pairs", function: "pairing", inputs: pairs("", g1, g1), wantErr: "false stack entry"},
		{name: "selected balanced proof", function: "pairingProof", inputs: proofs(negG1)},
		{name: "selected unbalanced proof", function: "pairingProof", inputs: proofs(g1), wantErr: "false stack entry"},
	} {
		t.Run(test.name, func(t *testing.T) {
			group := covenantGroup(t, contract, test.function)
			instance := instantiateGroup(t, contract, test.function, nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10000)
			ptx := spendingPSBTWithWitness(t, deployment, instance, 10000, instance.pkScript,
				covenantWitness(t, contract, group, test.inputs))
			requireVMResult(t, ptx, emulatorKey.PubKey(), test.wantErr)
		})
	}
}
