package e2e

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"slices"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

func TestCompiledVHTLC(t *testing.T) {
	contract := compileArtifact(t, filepath.Join("..", "..", "examples", "htlc", "vhtlc.ark"))
	// Native emulation: one operator key signs every leaf, tweaked by the covenant in covenant leaves.
	operatorKey := fixedPrivateKey(1)
	receiverScript := p2trScript(t, []byte{0x51})
	senderScript := p2trScript(t, []byte{0x52})
	const maxFee = 500
	values := map[string][]byte{
		"sender":                               schnorr.SerializePubKey(fixedPublicKey(4)),
		"receiver":                             schnorr.SerializePubKey(fixedPublicKey(5)),
		"preimageHash":                         address.Hash160(bytes.Repeat([]byte{0x42}, 32)),
		"refundLocktime":                       scriptInt(t, 500_000_001),
		"unilateralClaimDelay":                 scriptInt(t, 144),
		"unilateralRefundDelay":                scriptInt(t, 288),
		"unilateralRefundWithoutReceiverDelay": scriptInt(t, 432),
		"receiverScript":                       receiverScript[2:],
		"senderScript":                         senderScript[2:],
		"maxFee":                               scriptInt(t, maxFee),
		"OPERATOR_KEY":                         schnorr.SerializePubKey(operatorKey.PubKey()),
	}
	covenants := map[string][]byte{}
	tweakedKeys := [][]byte{values["OPERATOR_KEY"]}
	for _, name := range []string{"payReceiver", "paySender"} {
		covenants[name] = assemble(t, arkadeScriptGroup(t, contract, name).Arkade.ASM, values)
		values["OPERATOR_KEY:"+name] = schnorr.SerializePubKey(arkade.ComputeArkadeScriptPublicKey(
			operatorKey.PubKey(), arkade.ArkadeScriptHash(covenants[name]),
		))
		tweakedKeys = append(tweakedKeys, values["OPERATOR_KEY:"+name])
	}

	// Native arkd accepts a non-CSV leaf naming the operator key or that key tweaked by a covenant
	// hash the spend reveals; ark-lib's Validate here predates tweaked keys, so this mirrors it.
	t.Run("arkd accepts the taptree", func(t *testing.T) {
		var leaves []string
		for _, group := range contract.Functions {
			for _, leaf := range group.Leaves {
				leaves = append(leaves, hex.EncodeToString(assemble(t, leaf.ASM, values)))
			}
		}
		if len(leaves) != 9 {
			t.Fatalf("got %d leaves, want 9", len(leaves))
		}
		tree := &script.TapscriptsVtxoScript{}
		if err := tree.Decode(leaves); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(tree.ForfeitClosures()) != 6 || len(tree.ExitClosures()) != 3 {
			t.Fatalf("got %d non-CSV and %d CSV leaves, want 6 and 3",
				len(tree.ForfeitClosures()), len(tree.ExitClosures()))
		}
		for i, closure := range tree.ForfeitClosures() {
			var keys []*btcec.PublicKey
			switch c := closure.(type) {
			case *script.MultisigClosure:
				keys = c.PubKeys
			case *script.CLTVMultisigClosure:
				keys = c.PubKeys
			case *script.ConditionMultisigClosure:
				keys = c.PubKeys
			default:
				t.Fatalf("non-CSV leaf %d decodes as %T", i, closure)
			}
			if !slices.ContainsFunc(keys, func(k *btcec.PublicKey) bool {
				return slices.ContainsFunc(tweakedKeys, func(o []byte) bool {
					return bytes.Equal(o, schnorr.SerializePubKey(k))
				})
			}) {
				t.Fatalf("non-CSV leaf %d names no operator key", i)
			}
		}
		exitDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
		if smallest, err := tree.SmallestExitDelay(); err != nil || smallest.LessThan(exitDelay) {
			t.Fatalf("smallest exit delay %v below %v: %v", smallest, exitDelay, err)
		}
	})

	for _, tc := range []struct {
		covenant, leaf string
		payout, other  []byte
	}{
		{"payReceiver", "nonInteractiveClaim", receiverScript, senderScript},
		{"paySender", "nonInteractiveRefundWithoutReceiver", senderScript, receiverScript},
	} {
		var leafASM []string
		for _, leaf := range arkadeScriptGroup(t, contract, tc.covenant).Leaves {
			if leaf.Name == tc.leaf {
				leafASM = leaf.ASM
			}
		}
		pkScript, tapLeaf := taprootLeaf(t, assemble(t, leafASM, values))
		htlc := instantiatedGroup{covenants[tc.covenant], pkScript, tapLeaf}
		prevTx := fundingTx(htlc.pkScript, 10_000)
		id := asset.AssetId{Txid: chainhash.Hash{4}, Index: 0}
		assets := func(vin, vout uint16) extension.Packet {
			return extension.Packet(asset.Packet{{
				AssetId: &id,
				Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: vin, Amount: 5}},
				Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: vout, Amount: 5}},
			}})
		}

		t.Run(tc.covenant+"/virtual", func(t *testing.T) {
			for _, c := range []struct {
				name    string
				outputs []*wire.TxOut
				packets []extension.Packet
				wantErr string
			}{
				{"whole value", []*wire.TxOut{{Value: 10_000, PkScript: tc.payout}}, nil, ""},
				{"maxFee", []*wire.TxOut{{Value: 10_000 - maxFee, PkScript: tc.payout}}, nil, ""},
				{"above maxFee", []*wire.TxOut{{Value: 10_000 - maxFee - 1, PkScript: tc.payout}}, nil, "OP_VERIFY failed"},
				{"other program", []*wire.TxOut{{Value: 10_000, PkScript: tc.other}}, nil, "OP_EQUALVERIFY failed"},
				{"payout not at input index", []*wire.TxOut{
					{Value: 10_000, PkScript: tc.other}, {Value: 10_000, PkScript: tc.payout},
				}, nil, "OP_EQUALVERIFY failed"},
				{"assets kept", []*wire.TxOut{
					{Value: 10_000, PkScript: tc.payout}, {Value: 330, PkScript: tc.other},
				}, []extension.Packet{assets(0, 0)}, ""},
				{"assets moved away", []*wire.TxOut{
					{Value: 10_000, PkScript: tc.payout}, {Value: 330, PkScript: tc.other},
				}, []extension.Packet{assets(0, 1)}, "does not preserve source assets"},
			} {
				t.Run(c.name, func(t *testing.T) {
					spend := spendingPSBTOutputs(t, prevTx, htlc, 0, c.outputs, nil, c.packets...)
					requireVMResult(t, spend, operatorKey.PubKey(), c.wantErr)
				})
			}
		})

		t.Run(tc.covenant+"/proof", func(t *testing.T) {
			register := arkade.WithIntentMessage(`{"type":"register"}`)
			for _, c := range []struct {
				name    string
				outputs []*wire.TxOut
				packets []extension.Packet
				wantErr string
			}{
				{"payout at input index - 1", []*wire.TxOut{{Value: 10_000 - maxFee, PkScript: tc.payout}}, nil, ""},
				{"payout at input index", []*wire.TxOut{
					{Value: 10_000, PkScript: tc.other}, {Value: 10_000, PkScript: tc.payout},
				}, nil, "OP_EQUALVERIFY failed"},
				{"above maxFee", []*wire.TxOut{{Value: 10_000 - maxFee - 1, PkScript: tc.payout}}, nil, "OP_VERIFY failed"},
				{"assets kept", []*wire.TxOut{
					{Value: 10_000, PkScript: tc.payout}, {Value: 330, PkScript: tc.other},
				}, []extension.Packet{assets(1, 0)}, ""},
				{"assets moved away", []*wire.TxOut{
					{Value: 10_000, PkScript: tc.payout}, {Value: 330, PkScript: tc.other},
				}, []extension.Packet{assets(1, 1)}, "does not preserve source assets"},
			} {
				t.Run(c.name, func(t *testing.T) {
					spend := proofPSBT(t, prevTx, htlc, c.outputs, c.packets...)
					requireVMResult(t, spend, operatorKey.PubKey(), c.wantErr, register)
				})
			}
		})
	}

	t.Run("attacks", func(t *testing.T) {
		htlc := instantiatedGroup{covenants["payReceiver"], nil, nil}
		for _, leaf := range arkadeScriptGroup(t, contract, "payReceiver").Leaves {
			if leaf.Name == "nonInteractiveClaim" {
				htlc.pkScript, htlc.tapLeafScript = taprootLeaf(t, assemble(t, leaf.ASM, values))
			}
		}
		prev := fundingTx(htlc.pkScript, 10_000)
		other := fundingTx(senderScript, 5_000)
		message := fundingTx([]byte{0x51}, 0)
		attacker := p2trScript(t, []byte{0x53})
		payout := &wire.TxOut{Value: 10_000 - maxFee, PkScript: receiverScript}
		asset1, asset2 := asset.AssetId{Txid: chainhash.Hash{4}}, asset.AssetId{Txid: chainhash.Hash{5}}
		moves := func(id *asset.AssetId, vin, vout uint16) asset.AssetGroup {
			return asset.AssetGroup{
				AssetId: id,
				Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: vin, Amount: 100}},
				Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: vout, Amount: 100}},
			}
		}
		for _, c := range []struct {
			name    string
			prevs   []*wire.MsgTx
			vin     uint16
			outputs []*wire.TxOut
			extAt   int
			packet  asset.Packet
			message string
			wantErr string
		}{
			// arkd drops the extension from the batch leaf but keeps the packet's vouts
			{"extension before the payout", []*wire.MsgTx{message, other, prev}, 2,
				[]*wire.TxOut{payout, {Value: 5_000, PkScript: attacker}}, 0,
				asset.Packet{moves(&asset1, 2, 1)}, `{"type":"register"}`, "OP_NUMEQUALVERIFY failed"},
			{"payout listed as an onchain output", []*wire.MsgTx{message, prev}, 1,
				[]*wire.TxOut{payout, {Value: 400, PkScript: attacker}}, -1,
				asset.Packet{moves(&asset1, 1, 0)}, `{"type":"register","onchain_output_indexes":[0]}`,
				"OP_VERIFY failed"},
			{"a delete proof", []*wire.MsgTx{message, prev}, 1, []*wire.TxOut{payout}, -1,
				nil, `{"type":"delete","expire_at":1}`, "OP_EQUALVERIFY failed"},
			// the tunnelled control asset would let the spender reissue the asset it controls
			{"another asset group", []*wire.MsgTx{prev}, 0,
				[]*wire.TxOut{payout, {Value: 500, PkScript: attacker}}, -1,
				asset.Packet{moves(&asset1, 0, 0), {
					AssetId: &asset2,
					Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 1_000_000}},
				}}, "", "OP_NUMEQUALVERIFY failed"},
		} {
			t.Run(c.name, func(t *testing.T) {
				var packets []extension.Packet
				if c.packet != nil {
					packets = append(packets, extension.Packet(c.packet))
				}
				spend := attackPSBT(t, c.prevs, htlc, c.vin, c.outputs, c.extAt, packets...)
				var options []arkade.ExecuteOption
				if c.message != "" {
					options = append(options, arkade.WithIntentMessage(c.message))
				}
				requireVMResult(t, spend, operatorKey.PubKey(), c.wantErr, options...)
			})
		}
	})

	t.Run("tapscripts", func(t *testing.T) {
		claim := instantiatedGroup{covenants["payReceiver"], nil, nil}
		claim.pkScript, claim.tapLeafScript = taprootLeaf(t, assemble(t,
			arkadeScriptGroup(t, contract, "payReceiver").Leaves[0].ASM, values))
		refund := instantiatedGroup{covenants["paySender"], nil, nil}
		for _, leaf := range arkadeScriptGroup(t, contract, "paySender").Leaves {
			if leaf.Name == "nonInteractiveRefundWithoutReceiver" {
				refund.pkScript, refund.tapLeafScript = taprootLeaf(t, assemble(t, leaf.ASM, values))
			}
		}
		operatorKeys := func(covenant []byte) []*btcec.PrivateKey {
			return []*btcec.PrivateKey{arkade.ComputeArkadeScriptPrivateKey(
				operatorKey, arkade.ArkadeScriptHash(covenant),
			)}
		}
		final := wire.MaxTxInSequenceNum - 1
		preimage := wire.TxWitness{bytes.Repeat([]byte{0x42}, 32)}

		claimTx := fundingTx(claim.pkScript, 10_000)
		requireTapscriptResult(t, claimTx, claim, 0, final, operatorKeys(claim.arkadeScript), preimage, "")
		requireTapscriptResult(t, claimTx, claim, 0, final, operatorKeys(claim.arkadeScript),
			wire.TxWitness{bytes.Repeat([]byte{0x43}, 32)}, "OP_VERIFY failed")
		requireTapscriptResult(t, claimTx, claim, 0, final, operatorKeys(refund.arkadeScript), preimage,
			"signature not empty on failed checksig")

		refundTx := fundingTx(refund.pkScript, 10_000)
		requireTapscriptResult(t, refundTx, refund, 500_000_001, final, operatorKeys(refund.arkadeScript), nil, "")
		requireTapscriptResult(t, refundTx, refund, 500_000_000, final, operatorKeys(refund.arkadeScript), nil,
			"locktime requirement not satisfied")
	})
}

// proofPSBT spends htlc as input 1 behind a stand-in for the proof's own input 0.
func proofPSBT(
	t *testing.T,
	prevTx *wire.MsgTx,
	htlc instantiatedGroup,
	outputs []*wire.TxOut,
	packets ...extension.Packet,
) *psbt.Packet {
	t.Helper()

	toSpend := fundingTx([]byte{0x51}, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: toSpend.TxHash()}})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prevTx.TxHash()}})
	for _, output := range outputs {
		tx.AddTxOut(output)
	}
	emulatorPacket, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 1, Script: htlc.arkadeScript})
	if err != nil {
		t.Fatalf("emulator packet: %v", err)
	}
	extensionOutput, err := extension.Extension(append(packets, emulatorPacket)).TxOut()
	if err != nil {
		t.Fatalf("extension output: %v", err)
	}
	tx.AddTxOut(extensionOutput)

	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatalf("PSBT: %v", err)
	}
	ptx.Inputs[0].WitnessUtxo = toSpend.TxOut[0]
	ptx.Inputs[1].WitnessUtxo = prevTx.TxOut[0]
	ptx.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{htlc.tapLeafScript}
	for i, prev := range []*wire.MsgTx{toSpend, prevTx} {
		if err := txutils.SetArkPsbtField(ptx, i, arkade.PrevArkTxField, *prev); err != nil {
			t.Fatalf("previous Ark transaction: %v", err)
		}
	}
	return ptx
}

// attackPSBT spends prevs, the input vin running htlc, with the extension inserted before
// outputs[extAt], or last when extAt is out of range.
func attackPSBT(
	t *testing.T,
	prevs []*wire.MsgTx,
	htlc instantiatedGroup,
	vin uint16,
	outputs []*wire.TxOut,
	extAt int,
	packets ...extension.Packet,
) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	for _, prev := range prevs {
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prev.TxHash()}})
	}
	emulatorPacket, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: vin, Script: htlc.arkadeScript})
	if err != nil {
		t.Fatalf("emulator packet: %v", err)
	}
	extensionOutput, err := extension.Extension(append(packets, emulatorPacket)).TxOut()
	if err != nil {
		t.Fatalf("extension output: %v", err)
	}
	for i, output := range outputs {
		if i == extAt {
			tx.AddTxOut(extensionOutput)
		}
		tx.AddTxOut(output)
	}
	if extAt < 0 || extAt >= len(outputs) {
		tx.AddTxOut(extensionOutput)
	}
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatalf("PSBT: %v", err)
	}
	for i, prev := range prevs {
		ptx.Inputs[i].WitnessUtxo = prev.TxOut[0]
		if err := txutils.SetArkPsbtField(ptx, i, arkade.PrevArkTxField, *prev); err != nil {
			t.Fatalf("previous Ark transaction: %v", err)
		}
	}
	ptx.Inputs[vin].TaprootLeafScript = []*psbt.TaprootTapLeafScript{htlc.tapLeafScript}
	return ptx
}
