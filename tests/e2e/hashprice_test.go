package e2e

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	hashpriceBeaconValue = int64(10_000)
	hashpriceCollateral  = int64(50_000)
	hashpriceStrike      = int64(100)
	hashpriceDust        = int64(330)
)

// One beacon, one note. The beacon's update and passthrough leaves share a
// taproot output, which is the program the note is instantiated against.
func TestHashprice(t *testing.T) {
	beaconContract := compileArtifact(t, filepath.Join("..", "..", "examples", "hashprice", "hashprice_beacon.ark"))
	optionContract := compileArtifact(t, filepath.Join("..", "..", "examples", "hashprice", "hashprice_option.ark"))

	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	holderKey := fixedPrivateKey(4)
	writerKey := fixedPrivateKey(5)
	oracleKey := fixedPrivateKey(6)

	hashpriceAsset := asset.AssetId{Txid: chainhash.Hash{0x44}, Index: 1}
	heightAsset := asset.AssetId{Txid: chainhash.Hash{0x45}, Index: 2}
	holderProgram := bytes.Repeat([]byte{0x11}, 32)
	writerProgram := bytes.Repeat([]byte{0x22}, 32)

	assetValues := map[string][]byte{
		"oraclePk":             schnorr.SerializePubKey(oracleKey.PubKey()),
		"hashpriceAsset.txid":  hashpriceAsset.Txid[:],
		"hashpriceAsset.gidx":  scriptInt(t, int64(hashpriceAsset.Index)),
		"heightAsset.txid":     heightAsset.Txid[:],
		"heightAsset.gidx":     scriptInt(t, int64(heightAsset.Index)),
		"holderPk":             schnorr.SerializePubKey(holderKey.PubKey()),
		"writerPk":             schnorr.SerializePubKey(writerKey.PubKey()),
		"holderScript.program": holderProgram,
		"holderScript.version": scriptInt(t, 1),
		"writerScript.program": writerProgram,
		"writerScript.version": scriptInt(t, 1),
		"strike":               scriptInt(t, hashpriceStrike),
		"collateral":           scriptInt(t, hashpriceCollateral),
		"SERVER_EXIT_DELAY":    scriptInt(t, 144),
	}
	beacon := instantiateSharedTree(
		t, beaconContract, []string{"update", "passthrough"}, assetValues,
		serverKey.PubKey(), emulatorKey.PubKey(),
	)
	noteValues := map[string][]byte{}
	for key, value := range assetValues {
		noteValues[key] = value
	}
	noteValues["CONTRACT:HashpriceBeacon(<oraclePk>,<hashpriceAsset.txid>,<hashpriceAsset.gidx>,<heightAsset.txid>,<heightAsset.gidx>)"] = beacon.pkScript[2:]

	assets := func(inHashprice, outHashprice, inHeight, outHeight uint64) asset.Packet {
		hashpriceID, heightID := hashpriceAsset, heightAsset
		return asset.Packet{
			{
				AssetId: &hashpriceID,
				Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: inHashprice}},
				Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: outHashprice}},
			},
			{
				AssetId: &heightID,
				Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: inHeight}},
				Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: outHeight}},
			},
		}
	}
	beaconOut := func(value int64, script []byte) *wire.TxOut {
		return &wire.TxOut{Value: value, PkScript: script}
	}
	pay := func(value int64, program []byte) *wire.TxOut {
		return &wire.TxOut{Value: value, PkScript: p2trTo(program)}
	}

	t.Run("update", func(t *testing.T) {
		group := covenantGroup(t, beaconContract, "update")
		deployment := fundingTx(beacon.pkScript, hashpriceBeaconValue)
		spend := func(hashprice, height int64, signer *btcec.PrivateKey, output *wire.TxOut, packet asset.Packet) *psbt.Packet {
			witness := covenantWitness(t, beaconContract, group, map[string][]byte{
				"newHashprice": scriptInt(t, hashprice),
				"newHeight":    scriptInt(t, height),
				"oracleSig": signBIP340(t, signer, hashpriceMessage(
					t, deployment, 0, hashprice, height,
				)),
			})
			return hashpriceTx(t, []covenantInput{{
				prev: deployment, path: beacon.update, witness: witness,
			}}, []*wire.TxOut{output}, packet)
		}
		continued := beaconOut(hashpriceBeaconValue, beacon.pkScript)
		published := assets(100, 150, 100, 101)

		t.Run("oracle advances the published hashprice", func(t *testing.T) {
			requireVMResult(t, spend(150, 101, oracleKey, continued, published), emulatorKey.PubKey(), "")
		})
		t.Run("an old height is a replay", func(t *testing.T) {
			requireVMResult(
				t, spend(150, 100, oracleKey, continued, assets(100, 150, 100, 100)),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})
		t.Run("the oracle signed a different hashprice than the output", func(t *testing.T) {
			requireVMResult(
				t, spend(150, 101, oracleKey, continued, assets(100, 149, 100, 101)),
				emulatorKey.PubKey(), "OP_NUMEQUALVERIFY failed",
			)
		})
		t.Run("another key cannot publish", func(t *testing.T) {
			requireVMResult(
				t, spend(150, 101, holderKey, continued, published),
				emulatorKey.PubKey(), "signature verification failed",
			)
		})
		t.Run("the beacon value cannot be skimmed", func(t *testing.T) {
			requireVMResult(
				t, spend(150, 101, oracleKey, beaconOut(hashpriceBeaconValue-1, beacon.pkScript), published),
				emulatorKey.PubKey(), "does not preserve source value",
			)
		})
	})

	t.Run("settle", func(t *testing.T) {
		deployment := fundingTx(beacon.pkScript, hashpriceBeaconValue)
		passthrough := covenantInput{prev: deployment, path: beacon.passthrough}
		optionOf := func(collateral, strike int64) instantiatedGroup {
			values := map[string][]byte{}
			for key, value := range noteValues {
				values[key] = value
			}
			values["collateral"] = scriptInt(t, collateral)
			values["strike"] = scriptInt(t, strike)
			return instantiateGroup(
				t, optionContract, "settle", values, serverKey.PubKey(), emulatorKey.PubKey(),
			)
		}
		standard := optionOf(hashpriceCollateral, hashpriceStrike)
		settle := func(
			beacon covenantInput, option instantiatedGroup, locked, hashprice, height int64,
			outputs []*wire.TxOut,
		) *psbt.Packet {
			return hashpriceTx(t, []covenantInput{
				beacon,
				{prev: fundingTx(option.pkScript, locked), path: scriptPath{covenant: option.covenant, leaf: option.tapLeafScript}},
			}, outputs, assets(uint64(hashprice), uint64(hashprice), uint64(height), uint64(height)))
		}
		holderAmt := hashpriceCollateral * (150 - hashpriceStrike) / 150
		writerAmt := hashpriceCollateral - holderAmt

		t.Run("an in-the-money note pays the holder and the writer", func(t *testing.T) {
			requireVMResult(t, settle(
				passthrough, standard, hashpriceCollateral, 150, 101,
				[]*wire.TxOut{
					beaconOut(hashpriceBeaconValue, beacon.pkScript),
					pay(holderAmt, holderProgram),
					pay(writerAmt, writerProgram),
				},
			), emulatorKey.PubKey(), "")
		})
		t.Run("the published value survives an update and then settles", func(t *testing.T) {
			update := covenantGroup(t, beaconContract, "update")
			witness := covenantWitness(t, beaconContract, update, map[string][]byte{
				"newHashprice": scriptInt(t, 150),
				"newHeight":    scriptInt(t, 101),
				"oracleSig": signBIP340(t, oracleKey, hashpriceMessage(
					t, deployment, 0, 150, 101,
				)),
			})
			updated := hashpriceTx(t, []covenantInput{{
				prev: deployment, path: beacon.update, witness: witness,
			}}, []*wire.TxOut{beaconOut(hashpriceBeaconValue, beacon.pkScript)}, assets(100, 150, 100, 101))
			requireVMResult(t, updated, emulatorKey.PubKey(), "")

			requireVMResult(t, settle(
				covenantInput{prev: updated.UnsignedTx, path: beacon.passthrough},
				standard, hashpriceCollateral, 150, 101,
				[]*wire.TxOut{
					beaconOut(hashpriceBeaconValue, beacon.pkScript),
					pay(holderAmt, holderProgram),
					pay(writerAmt, writerProgram),
				},
			), emulatorKey.PubKey(), "")
		})
		t.Run("out of the money the writer keeps the collateral", func(t *testing.T) {
			requireVMResult(t, settle(
				passthrough, standard, hashpriceCollateral, 80, 101,
				[]*wire.TxOut{
					beaconOut(hashpriceBeaconValue, beacon.pkScript),
					pay(hashpriceCollateral, writerProgram),
				},
			), emulatorKey.PubKey(), "")
		})
		t.Run("a dust leg folds into the writer", func(t *testing.T) {
			const collateral = hashpriceDust + 70
			holder := collateral * (101 - hashpriceStrike) / 101
			if holder > hashpriceDust {
				t.Fatalf("dust fixture holder payout %d is above dust", holder)
			}
			requireVMResult(t, settle(
				passthrough, optionOf(collateral, hashpriceStrike), collateral, 101, 102,
				[]*wire.TxOut{
					beaconOut(hashpriceBeaconValue, beacon.pkScript),
					pay(collateral, writerProgram),
				},
			), emulatorKey.PubKey(), "")
		})
		t.Run("a different beacon program does not settle", func(t *testing.T) {
			other := fundingTx(p2trScript(t, []byte{0x51}), hashpriceBeaconValue)
			requireVMResult(t, settle(
				covenantInput{prev: other, path: beacon.passthrough},
				standard, hashpriceCollateral, 150, 101,
				[]*wire.TxOut{
					beaconOut(hashpriceBeaconValue, other.TxOut[0].PkScript),
					pay(holderAmt, holderProgram),
					pay(writerAmt, writerProgram),
				},
			), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
		t.Run("settlement cannot move the published hashprice", func(t *testing.T) {
			moved := hashpriceTx(t, []covenantInput{
				passthrough,
				{prev: fundingTx(standard.pkScript, hashpriceCollateral), path: scriptPath{covenant: standard.covenant, leaf: standard.tapLeafScript}},
			}, []*wire.TxOut{
				beaconOut(hashpriceBeaconValue, beacon.pkScript),
				pay(holderAmt, holderProgram),
				pay(writerAmt, writerProgram),
			}, assets(150, 151, 101, 101))
			requireVMResult(t, moved, emulatorKey.PubKey(), "does not preserve source assets")
		})
		t.Run("the holder cannot be shorted", func(t *testing.T) {
			requireVMResult(t, settle(
				passthrough, standard, hashpriceCollateral, 150, 101,
				[]*wire.TxOut{
					beaconOut(hashpriceBeaconValue, beacon.pkScript),
					pay(holderAmt-1, holderProgram),
					pay(writerAmt+1, writerProgram),
				},
			), emulatorKey.PubKey(), "OP_VERIFY failed")
		})
		t.Run("the holder payout cannot be redirected", func(t *testing.T) {
			requireVMResult(t, settle(
				passthrough, standard, hashpriceCollateral, 150, 101,
				[]*wire.TxOut{
					beaconOut(hashpriceBeaconValue, beacon.pkScript),
					pay(holderAmt, writerProgram),
					pay(writerAmt, writerProgram),
				},
			), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
	})
}

type scriptPath struct {
	covenant []byte
	leaf     *psbt.TaprootTapLeafScript
}

type sharedTree struct {
	pkScript    []byte
	update      scriptPath
	passthrough scriptPath
}

type covenantInput struct {
	prev    *wire.MsgTx
	path    scriptPath
	witness wire.TxWitness
}

func instantiateSharedTree(
	t *testing.T,
	contract artifact,
	names []string,
	values map[string][]byte,
	serverKey, emulatorKey *btcec.PublicKey,
) sharedTree {
	t.Helper()

	paths := make([]scriptPath, len(names))
	leaves := make([][]byte, len(names))
	for i, name := range names {
		group := covenantGroup(t, contract, name)
		covenant := assemble(t, group.Arkade.ASM, values)
		var leafASM []string
		for _, leaf := range group.Leaves {
			if leaf.Name == name {
				leafASM = leaf.ASM
				break
			}
		}
		if leafASM == nil {
			t.Fatalf("%s.%s leaf not found", contract.Name, name)
		}
		leafValues := map[string][]byte{
			"SERVER_KEY": schnorr.SerializePubKey(serverKey),
			"EMULATOR_KEY:" + name: schnorr.SerializePubKey(arkade.ComputeArkadeScriptPublicKey(
				emulatorKey, arkade.ArkadeScriptHash(covenant),
			)),
		}
		leaves[i] = assemble(t, leafASM, leafValues)
		paths[i] = scriptPath{covenant: covenant}
	}

	internalKey := fixedPublicKey(3)
	tapLeaves := make([]txscript.TapLeaf, len(leaves))
	for i, leaf := range leaves {
		tapLeaves[i] = txscript.NewBaseTapLeaf(leaf)
	}
	tree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	root := tree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, root[:])
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.LeafMerkleProofs) != len(leaves) {
		t.Fatalf("%d proofs for %d leaves", len(tree.LeafMerkleProofs), len(leaves))
	}
	for i, leaf := range leaves {
		controlBlock := tree.LeafMerkleProofs[i].ToControlBlock(internalKey)
		control, err := controlBlock.ToBytes()
		if err != nil {
			t.Fatal(err)
		}
		if err := txscript.VerifyTaprootLeafCommitment(&controlBlock, pkScript[2:], leaf); err != nil {
			t.Fatalf("leaf %d is not committed: %v", i, err)
		}
		paths[i].leaf = &psbt.TaprootTapLeafScript{
			ControlBlock: control,
			Script:       leaf,
			LeafVersion:  txscript.BaseLeafVersion,
		}
	}
	byName := make(map[string]scriptPath, len(names))
	for i, name := range names {
		byName[name] = paths[i]
	}
	update, okUpdate := byName["update"]
	passthrough, okPassthrough := byName["passthrough"]
	if !okUpdate || !okPassthrough {
		t.Fatalf("beacon tree is missing update or passthrough: %v", names)
	}
	return sharedTree{pkScript: pkScript, update: update, passthrough: passthrough}
}

func hashpriceTx(
	t *testing.T,
	inputs []covenantInput,
	outputs []*wire.TxOut,
	assets asset.Packet,
) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	entries := make([]arkade.EmulatorEntry, len(inputs))
	for i, input := range inputs {
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: input.prev.TxHash(), Index: 0},
		})
		entries[i] = arkade.EmulatorEntry{
			Vin:     uint16(i),
			Script:  input.path.covenant,
			Witness: input.witness,
		}
	}
	for _, output := range outputs {
		tx.AddTxOut(output)
	}
	packet, err := arkade.NewPacket(entries...)
	if err != nil {
		t.Fatal(err)
	}
	extensionOutput, err := extension.Extension{extension.Packet(assets), packet}.TxOut()
	if err != nil {
		t.Fatal(err)
	}
	tx.AddTxOut(extensionOutput)

	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	for i, input := range inputs {
		ptx.Inputs[i].WitnessUtxo = input.prev.TxOut[0]
		ptx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{input.path.leaf}
		if err := txutils.SetArkPsbtField(ptx, i, arkade.PrevArkTxField, *input.prev); err != nil {
			t.Fatal(err)
		}
	}
	return ptx
}

func hashpriceMessage(t *testing.T, prev *wire.MsgTx, vout uint32, hashprice, height int64) []byte {
	t.Helper()

	var body bytes.Buffer
	txid := prev.TxHash()
	body.Write(txid[:])
	body.Write(num2bin(t, int64(vout), 4))
	body.Write(num2bin(t, hashprice, 8))
	body.Write(num2bin(t, height, 8))
	sum := sha256.Sum256(body.Bytes())
	return sum[:]
}

func num2bin(t *testing.T, value int64, size int) []byte {
	t.Helper()

	encoded, err := arkade.BigNumFromInt64(value).FixedBytes(size)
	if err != nil {
		t.Fatalf("num2bin(%d, %d): %v", value, size, err)
	}
	return encoded
}
