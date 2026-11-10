package e2e

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type headerFixture struct {
	Height                         int64
	ParentHeader, EpochStartHeader string
	Headers                        []string
	Coinbase                       string
	Merkle                         []string
	Source                         string
}

func headerFixtures(t *testing.T) []headerFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/hashprice_blocks.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []headerFixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func beaconHex(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func beaconNum(t *testing.T, n *big.Int, length int) []byte {
	t.Helper()
	data := scriptPositiveBigInt(t, n.Bytes())
	if n.Sign() < 0 || len(data) > length {
		t.Fatal("state integer out of range")
	}
	return append(data, make([]byte, length-len(data))...)
}

func beaconState(t *testing.T, kind byte, height int64, fields ...[]byte) []byte {
	t.Helper()
	state := append([]byte{1, kind}, beaconNum(t, big.NewInt(height), 8)...)
	for _, field := range fields {
		state = append(state, field...)
	}
	return state
}

// Build both issuer leaves into the same Taproot tree, as a deployment does.
func beaconInstances(t *testing.T, contract artifact, values map[string][]byte) map[string]instantiatedGroup {
	t.Helper()
	instances := make(map[string]instantiatedGroup)
	leaves := make([]txscript.TapLeaf, 0, len(contract.Functions))
	for _, function := range contract.Functions {
		instance := instantiateGroup(t, contract, function.Name, values, fixedPublicKey(1), fixedPublicKey(2))
		instances[function.Name] = instance
		leaves = append(leaves, txscript.NewBaseTapLeaf(instance.tapLeafScript.Script))
		t.Logf("%s.%s: %d covenant bytes", contract.Name, function.Name, len(instance.covenant))
	}
	tree := txscript.AssembleTaprootScriptTree(leaves...)
	root := tree.RootNode.TapHash()
	program, err := txscript.PayToTaprootScript(txscript.ComputeTaprootOutputKey(fixedPublicKey(3), root[:]))
	if err != nil {
		t.Fatal(err)
	}
	for i, function := range contract.Functions {
		instance := instances[function.Name]
		control := tree.LeafMerkleProofs[i].ToControlBlock(fixedPublicKey(3))
		data, err := control.ToBytes()
		if err != nil {
			t.Fatal(err)
		}
		instance.pkScript = program
		instance.tapLeafScript.ControlBlock = data
		instances[function.Name] = instance
	}
	return instances
}

func beaconGroup(id asset.AssetId, inputs, outputs []uint16) asset.AssetGroup {
	group := asset.AssetGroup{AssetId: &id}
	for _, vin := range inputs {
		group.Inputs = append(group.Inputs, asset.AssetInput{Type: asset.AssetInputTypeLocal, Vin: vin, Amount: 1})
	}
	for _, vout := range outputs {
		group.Outputs = append(group.Outputs, asset.AssetOutput{Type: asset.AssetOutputTypeLocal, Vout: vout, Amount: 1})
	}
	return group
}

type beaconCoin struct {
	instance instantiatedGroup
	state    []byte
	witness  wire.TxWitness
	id       asset.AssetId
}

// Previous state deliberately lives at vout 3, independent of the current vin.
// Previous asset allocations are independent of the spending packet so arkd's
// validator can reject forged inputs as well as unauthorized supply increases.
func beaconSpend(t *testing.T, coins []beaconCoin, outputs []*wire.TxOut, states [][]byte, assets asset.Packet) *psbt.Packet {
	t.Helper()
	tx := wire.NewMsgTx(2)
	previous := make([]*wire.MsgTx, len(coins))
	entries := make([]arkade.EmulatorEntry, len(coins))
	for i, coin := range coins {
		prev := fundingTx([]byte{txscript.OP_TRUE}, 10000)
		prev.AddTxOut(&wire.TxOut{PkScript: []byte{txscript.OP_TRUE}})
		prev.AddTxOut(&wire.TxOut{PkScript: []byte{txscript.OP_TRUE}})
		prev.AddTxOut(&wire.TxOut{Value: 10000, PkScript: coin.instance.pkScript})
		out, err := (extension.Extension{
			asset.Packet{beaconGroup(coin.id, nil, []uint16{3})},
			extension.UnknownPacket{PacketType: 35, Data: coin.state},
		}).TxOut()
		if err != nil {
			t.Fatal(err)
		}
		prev.AddTxOut(out)
		previous[i] = prev
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prev.TxHash(), Index: 3}})
		entries[i] = arkade.EmulatorEntry{Vin: uint16(i), Script: coin.instance.covenant, Witness: coin.witness}
	}
	for _, out := range outputs {
		tx.AddTxOut(out)
	}
	em, err := arkade.NewPacket(entries...)
	if err != nil {
		t.Fatal(err)
	}
	packets := extension.Extension{assets, em}
	for i, state := range states {
		packets = append(packets, extension.UnknownPacket{PacketType: uint8(32 + i), Data: state})
	}
	ext, err := packets.TxOut()
	if err != nil {
		t.Fatal(err)
	}
	tx.AddTxOut(ext)
	tx.AddTxOut(txutils.AnchorOutput())
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	for i, coin := range coins {
		ptx.Inputs[i].WitnessUtxo = previous[i].TxOut[3]
		ptx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{coin.instance.tapLeafScript}
		if err := txutils.SetArkPsbtField(ptx, i, arkade.PrevArkTxField, *previous[i]); err != nil {
			t.Fatal(err)
		}
	}
	return ptx
}

func beaconOut(instance instantiatedGroup) *wire.TxOut {
	return &wire.TxOut{Value: 10000, PkScript: bytes.Clone(instance.pkScript)}
}

func beaconResult(t *testing.T, ptx *psbt.Packet, valid bool) {
	t.Helper()
	err := executeArkadeScripts(ptx, fixedPublicKey(2))
	if err == nil {
		err = validateBeaconAssets(ptx)
	}
	if valid && err != nil {
		t.Fatalf("valid beacon spend failed: %v", err)
	}
	if !valid && err == nil {
		t.Fatal("invalid beacon spend accepted")
	}
}

var (
	blockControlID     = asset.AssetId{Txid: chainhash.Hash{4}, Index: 0}
	blockCoinID        = asset.AssetId{Txid: chainhash.Hash{4}, Index: 1}
	hashPriceControlID = asset.AssetId{Txid: chainhash.Hash{4}, Index: 2}
	hashPriceCoinID    = asset.AssetId{Txid: chainhash.Hash{4}, Index: 3}
)

// The authenticated initialization registry: singleton control assets have no
// control asset themselves, so their supply cannot increase.
type beaconAssetSource map[string]string

func (s beaconAssetSource) GetControlAsset(_ context.Context, id string) (string, error) {
	control, ok := s[id]
	if !ok {
		return "", fmt.Errorf("unknown asset %s", id)
	}
	return control, nil
}

func (s beaconAssetSource) AssetExists(_ context.Context, id string) bool {
	_, ok := s[id]
	return ok
}

func validateBeaconAssets(ptx *psbt.Packet) error {
	ext, err := extension.NewExtensionFromTx(ptx.UnsignedTx)
	if err != nil {
		return err
	}
	prevouts := make(map[int][]asset.Asset)
	for vin := range ptx.Inputs {
		previous, err := txutils.GetArkPsbtFields(ptx, vin, arkade.PrevArkTxField)
		if err != nil || len(previous) != 1 {
			return fmt.Errorf("previous transaction for input %d: %v", vin, err)
		}
		previousExtension, err := extension.NewExtensionFromTx(&previous[0])
		if errors.Is(err, extension.ErrExtensionNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		for _, group := range previousExtension.GetAssetPacket() {
			for _, out := range group.Outputs {
				if uint32(out.Vout) == ptx.UnsignedTx.TxIn[vin].PreviousOutPoint.Index {
					prevouts[vin] = append(prevouts[vin], asset.Asset{AssetId: group.AssetId.String(), Amount: out.Amount})
				}
			}
		}
	}
	source := beaconAssetSource{
		blockControlID.String(): "", blockCoinID.String(): blockControlID.String(),
		hashPriceControlID.String(): "", hashPriceCoinID.String(): hashPriceControlID.String(),
	}
	return asset.ValidateAssetTransaction(context.Background(), ptx.UnsignedTx, ext.GetAssetPacket(), prevouts, source)
}

func beaconObservation(t *testing.T, kind byte) instantiatedGroup {
	t.Helper()
	length := int64(99)
	if kind == 4 {
		length = 138
	}
	return beaconInstances(t, compileArtifact(t, "../../examples/hashprice/beacon_coin.ark"), map[string][]byte{
		"stateTag": {1, kind}, "stateLength": scriptInt(t, length),
	})["continue"]
}

func fixtureReward(t *testing.T, f headerFixture) *big.Int {
	t.Helper()
	var tx wire.MsgTx
	if err := tx.DeserializeNoWitness(bytes.NewReader(beaconHex(t, f.Coinbase))); err != nil {
		t.Fatal(err)
	}
	reward := new(big.Int)
	for _, out := range tx.TxOut {
		reward.Add(reward, big.NewInt(out.Value))
	}
	return reward
}

func TestHashpriceHeaders(t *testing.T) {
	coin := beaconObservation(t, 2)
	verifier := compileArtifact(t, "../../examples/hashprice/block_header_beacon.ark")
	issuer := beaconInstances(t, verifier, map[string][]byte{"coinGidx": scriptInt(t, 1), "blockCoinScript": coin.pkScript[2:]})["mint"]
	for _, f := range headerFixtures(t) {
		t.Run(fmt.Sprint(f.Height), func(t *testing.T) {
			parent := beaconHex(t, f.ParentHeader)
			epoch := beaconHex(t, f.EpochStartHeader)
			first := beaconHex(t, f.Headers[0])
			second := beaconHex(t, f.Headers[1])
			parentHash := chainhash.DoubleHashB(parent)
			before := beaconState(t, 1, f.Height-1, parentHash, first[72:76], epoch[68:72])
			epochTime := epoch[68:72]
			if f.Height%2016 == 0 {
				epochTime = first[68:72]
			}
			after := beaconState(t, 1, f.Height, chainhash.DoubleHashB(first), second[72:76], epochTime)
			observation := beaconState(t, 2, f.Height, first, beaconNum(t, fixtureReward(t, f), 9))
			for _, mutation := range []string{"valid", "link", "pow", "difficulty", "reward", "height", "state hash", "state target", "state epoch", "coinbase", "proof", "short proof", "output script", "supply", "missing header"} {
				t.Run(mutation, func(t *testing.T) {
					values := map[string][]byte{"coinbase": beaconHex(t, f.Coinbase), "merkleDepth": scriptInt(t, int64(len(f.Merkle)))}
					for i := range 30 {
						values[fmt.Sprintf("headers.%d", i)] = nil
						if i < len(f.Headers) {
							values[fmt.Sprintf("headers.%d", i)] = beaconHex(t, f.Headers[i])
						}
					}
					for i := range 20 {
						values[fmt.Sprintf("siblings.%d", i)] = make([]byte, 32)
						if i < len(f.Merkle) {
							values[fmt.Sprintf("siblings.%d", i)] = beaconHex(t, f.Merkle[i])
						}
					}
					states := [][]byte{bytes.Clone(after), bytes.Clone(observation)}
					outs := []*wire.TxOut{beaconOut(issuer), beaconOut(coin)}
					assets := asset.Packet{beaconGroup(blockControlID, []uint16{0}, []uint16{0}), beaconGroup(blockCoinID, nil, []uint16{1})}
					switch mutation {
					case "link":
						values["headers.0"][4] ^= 1
					case "pow":
						values["headers.0"][79] ^= 1
					case "difficulty":
						values["headers.1"][72] ^= 1
					case "reward":
						states[1][90] ^= 1
					case "height":
						states[0][2] ^= 1
					case "state hash":
						states[0][10] ^= 1
					case "state target":
						states[0][42] ^= 1
					case "state epoch":
						states[0][46] ^= 1
					case "coinbase":
						values["coinbase"][50] ^= 1
					case "proof":
						values["siblings.0"][0] ^= 1
					case "short proof":
						values["siblings.0"] = nil
					case "output script":
						outs[1].PkScript[2] ^= 1
					case "supply":
						assets[1].Outputs[0].Amount = 2
					case "missing header":
						values[fmt.Sprintf("headers.%d", len(f.Headers)-1)] = nil
					}
					witness := covenantWitness(t, verifier, covenantGroup(t, verifier, "mint"), values)
					ptx := beaconSpend(t, []beaconCoin{{issuer, before, witness, blockControlID}}, outs, states, assets)
					beaconResult(t, ptx, mutation == "valid")
				})
			}
		})
	}
}

func TestHashpriceBeacon(t *testing.T) {
	f := headerFixtures(t)[2]
	header := beaconHex(t, f.Headers[0])
	reward := fixtureReward(t, f)
	source := beaconObservation(t, 2)
	hpc := beaconObservation(t, 4)
	contract := compileArtifact(t, "../../examples/hashprice/hashprice_beacon.ark")
	issuer := beaconInstances(t, contract, map[string][]byte{"coinGidx": scriptInt(t, 3), "sourceGidx": scriptInt(t, 1), "blockCoinScript": source.pkScript[2:], "hashPriceCoinScript": hpc.pkScript[2:]})["mint"]
	target := blockchain.CompactToBig(binary.LittleEndian.Uint32(header[72:76]))
	q := new(big.Int).Mul(reward, target)
	previous := new(big.Int).Lsh(big.NewInt(1), 300)
	next := new(big.Int).Add(previous, q)
	before := beaconState(t, 3, f.Height-1, beaconNum(t, previous, 64))
	block := beaconState(t, 2, f.Height, header, beaconNum(t, reward, 9))
	after := beaconState(t, 3, f.Height, beaconNum(t, next, 64))
	observation := beaconState(t, 4, f.Height, beaconNum(t, q, 64), beaconNum(t, next, 64))
	for _, mutation := range []string{"valid", "skip", "accumulator", "numerator", "source state", "source identity", "source script", "extra supply", "burn source"} {
		t.Run(mutation, func(t *testing.T) {
			states := [][]byte{bytes.Clone(after), bytes.Clone(block), bytes.Clone(observation)}
			outs := []*wire.TxOut{beaconOut(issuer), beaconOut(source), beaconOut(hpc)}
			assets := asset.Packet{beaconGroup(hashPriceControlID, []uint16{0}, []uint16{0}), beaconGroup(blockCoinID, []uint16{1}, []uint16{1}), beaconGroup(hashPriceCoinID, nil, []uint16{2})}
			switch mutation {
			case "skip":
				states[0][2]++
			case "accumulator":
				states[0][10]++
			case "numerator":
				states[2][10]++
			case "source state":
				states[1][90]++
			case "source identity":
				assets[1].AssetId = &asset.AssetId{Txid: chainhash.Hash{5}, Index: 0}
			case "source script":
				outs[1].PkScript[2] ^= 1
			case "extra supply":
				assets[2].Outputs[0].Amount++
			case "burn source":
				assets[1].Outputs = nil
			}
			ptx := beaconSpend(t, []beaconCoin{{issuer, before, nil, hashPriceControlID}, {source, block, nil, blockCoinID}}, outs, states, assets)
			beaconResult(t, ptx, mutation == "valid")
		})
	}
}

func TestHashpriceCloning(t *testing.T) {
	for _, kind := range []string{"block", "hashprice"} {
		t.Run(kind, func(t *testing.T) {
			controlID, id := blockControlID, blockCoinID
			issuerFile := "block_header_beacon"
			state := beaconState(t, 2, 2017, make([]byte, 80), beaconNum(t, big.NewInt(5000000000), 9))
			issuerState := beaconState(t, 1, 2017, make([]byte, 40))
			if kind == "hashprice" {
				controlID, id = hashPriceControlID, hashPriceCoinID
				issuerFile = "hashprice_beacon"
				state = beaconState(t, 4, 2017, make([]byte, 128))
				issuerState = beaconState(t, 3, 2017, make([]byte, 64))
			}
			coin := beaconObservation(t, state[1])
			values := map[string][]byte{"coinGidx": scriptInt(t, int64(id.Index)), "blockCoinScript": coin.pkScript[2:], "hashPriceCoinScript": coin.pkScript[2:], "sourceGidx": scriptInt(t, 1)}
			issuer := beaconInstances(t, compileArtifact(t, "../../examples/hashprice/"+issuerFile+".ark"), values)["clone"]
			for _, copies := range []int{1, 8} {
				for _, mutation := range []string{"valid", "state", "issuer state", "script", "value", "amount", "wrong control", "forged control", "control supply", "control burn", "control script"} {
					t.Run(fmt.Sprintf("%d/%s", copies, mutation), func(t *testing.T) {
						outs := []*wire.TxOut{beaconOut(issuer), beaconOut(coin)}
						states := [][]byte{bytes.Clone(issuerState), bytes.Clone(state)}
						indices := []uint16{1}
						for i := range copies {
							outs = append(outs, beaconOut(coin))
							states = append(states, bytes.Clone(state))
							indices = append(indices, uint16(i+2))
						}
						assets := asset.Packet{beaconGroup(controlID, []uint16{0}, []uint16{0}), beaconGroup(id, []uint16{1}, indices)}
						inputControl := controlID
						switch mutation {
						case "state":
							states[2][2]++
						case "issuer state":
							states[0][2]++
						case "script":
							outs[2].PkScript[2] ^= 1
						case "value":
							outs[2].Value--
						case "amount":
							assets[1].Outputs[1].Amount++
						case "wrong control", "forged control":
							inputControl = blockControlID
							if controlID == blockControlID {
								inputControl = hashPriceControlID
							}
							if mutation == "wrong control" {
								assets[0].AssetId = &inputControl
							}
						case "control supply":
							assets[0].Outputs[0].Amount++
						case "control burn":
							assets[0].Outputs = nil
						case "control script":
							outs[0].PkScript[2] ^= 1
						}
						ptx := beaconSpend(t, []beaconCoin{{issuer, issuerState, nil, inputControl}, {coin, state, nil, id}}, outs, states, assets)
						if mutation == "wrong control" || mutation == "forged control" {
							if err := executeArkadeScripts(ptx, fixedPublicKey(2)); err != nil {
								t.Fatalf("expected arkd to enforce control ownership: %v", err)
							}
						}
						if mutation == "control supply" && validateBeaconAssets(ptx) == nil {
							t.Fatal("arkd accepted reissuance of a fixed-supply control asset")
						}
						beaconResult(t, ptx, mutation == "valid")
					})
				}
			}
			for _, mutation := range []string{"continue", "state", "burn", "unauthorized clone"} {
				t.Run(mutation, func(t *testing.T) {
					outs := []*wire.TxOut{beaconOut(coin)}
					states := [][]byte{bytes.Clone(state)}
					assets := asset.Packet{beaconGroup(id, []uint16{0}, []uint16{0})}
					switch mutation {
					case "state":
						states[0][2]++
					case "burn":
						assets[0].Outputs = nil
					case "unauthorized clone":
						outs = append(outs, beaconOut(coin))
						states = append(states, bytes.Clone(state))
						assets[0].Outputs = append(assets[0].Outputs, asset.AssetOutput{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 1})
					}
					ptx := beaconSpend(t, []beaconCoin{{coin, state, nil, id}}, outs, states, assets)
					if mutation == "unauthorized clone" {
						// Continuation deliberately leaves issuance authority to arkd.
						if err := executeArkadeScripts(ptx, fixedPublicKey(2)); err != nil {
							t.Fatalf("continuation must not check the issuer: %v", err)
						}
					}
					beaconResult(t, ptx, mutation == "continue")
				})
			}
		})
	}
}

func TestHashpriceCoinContinuations(t *testing.T) {
	coin := beaconObservation(t, 4)
	first := beaconState(t, 4, 2017, make([]byte, 128))
	second := beaconState(t, 4, 2027, make([]byte, 128))
	for _, mutation := range []string{"valid", "swapped states", "merged outputs"} {
		t.Run(mutation, func(t *testing.T) {
			outs := []*wire.TxOut{beaconOut(coin), beaconOut(coin)}
			states := [][]byte{first, second}
			assets := asset.Packet{beaconGroup(hashPriceCoinID, []uint16{0, 1}, []uint16{0, 1})}
			if mutation == "swapped states" {
				states = [][]byte{second, first}
			}
			if mutation == "merged outputs" {
				outs, states = outs[:1], states[:1]
				assets[0].Outputs = assets[0].Outputs[:1]
				assets[0].Outputs[0].Amount = 2
			}
			ptx := beaconSpend(t, []beaconCoin{
				{coin, first, nil, hashPriceCoinID}, {coin, second, nil, hashPriceCoinID},
			}, outs, states, assets)
			beaconResult(t, ptx, mutation == "valid")
		})
	}
}

func TestHashpriceMath(t *testing.T) {
	contract := compileArtifact(t, "contracts/hashprice_math.ark")
	instances := beaconInstances(t, contract, nil)
	run := func(name, function string, values map[string][]byte, valid bool) {
		t.Run(name, func(t *testing.T) {
			if function == "reward" {
				values["expectedTxid"] = chainhash.DoubleHashB(values["transaction"])
			}
			instance := instances[function]
			witness := covenantWitness(t, contract, covenantGroup(t, contract, function), values)
			ptx := spendingPSBTWithWitness(t, fundingTx(instance.pkScript, 10000), instance, 10000, instance.pkScript, witness)
			beaconResult(t, ptx, valid)
		})
	}
	old := new(big.Int).Lsh(big.NewInt(1), 200)
	for _, c := range []struct{ num, den, want int64 }{{1, 2, 6}, {1, 1, 6}, {9, 8, 7}, {5, 4, 8}, {2, 1, 14}, {3, 1, 22}, {4, 1, 30}, {17, 4, 32}} {
		next := new(big.Int).Quo(new(big.Int).Mul(old, big.NewInt(c.num)), big.NewInt(c.den))
		run(fmt.Sprintf("confirmations %d/%d", c.num, c.den), "confirmations", map[string][]byte{"oldTarget": scriptPositiveBigInt(t, old.Bytes()), "newTarget": scriptPositiveBigInt(t, next.Bytes()), "expected": scriptInt(t, c.want)}, c.num <= 4*c.den)
	}
	next := new(big.Int).Add(old, big.NewInt(1))
	run("one target unit rounds up", "confirmations", map[string][]byte{"oldTarget": scriptPositiveBigInt(t, old.Bytes()), "newTarget": scriptPositiveBigInt(t, next.Bytes()), "expected": scriptInt(t, 7)}, true)
	for step := int64(1); step <= 24; step++ {
		threshold := new(big.Int).Mul(new(big.Int).Rsh(new(big.Int).Set(old), 3), big.NewInt(8+step))
		for _, offset := range []int64{-1, 0, 1} {
			target := new(big.Int).Add(threshold, big.NewInt(offset))
			want := 6 + step
			if offset > 0 {
				want++
			}
			run(fmt.Sprintf("confirmation threshold %d offset %d", step, offset), "confirmations", map[string][]byte{
				"oldTarget": scriptPositiveBigInt(t, old.Bytes()), "newTarget": scriptPositiveBigInt(t, target.Bytes()), "expected": scriptInt(t, want),
			}, want <= 30)
		}
	}
	for _, n := range []*big.Int{big.NewInt(1), big.NewInt(127), big.NewInt(128), big.NewInt(255), big.NewInt(256), big.NewInt(32767), big.NewInt(32768), big.NewInt(8388607), big.NewInt(8388608), old, blockchain.CompactToBig(0x1d00ffff)} {
		bits := make([]byte, 4)
		binary.LittleEndian.PutUint32(bits, blockchain.BigToCompact(n))
		run("compact "+n.String(), "compact", map[string][]byte{"target": scriptPositiveBigInt(t, n.Bytes()), "bits": bits}, true)
		decoded := blockchain.CompactToBig(binary.LittleEndian.Uint32(bits))
		run("target "+n.String(), "target", map[string][]byte{"bits": bits, "expected": scriptPositiveBigInt(t, decoded.Bytes())}, true)
	}
	for _, bits := range []uint32{0, 0x1d80ffff, 0x1e00ffff, 0x23000001, 0x01000001} {
		encoded := make([]byte, 4)
		binary.LittleEndian.PutUint32(encoded, bits)
		run(fmt.Sprintf("invalid target %x", bits), "target", map[string][]byte{"bits": encoded, "expected": nil}, false)
	}
	for _, bits := range []uint32{0x02000100, 0x01010001} {
		encoded := make([]byte, 4)
		binary.LittleEndian.PutUint32(encoded, bits)
		run(fmt.Sprintf("noncanonical compact %x", bits), "compact", map[string][]byte{"target": scriptInt(t, 1), "bits": encoded}, false)
	}
	for _, elapsed := range []int64{-1, 302399, 302400, 1209600, 4838400, 4838401} {
		clamped := max(int64(302400), min(int64(4838400), elapsed))
		target := new(big.Int).Quo(new(big.Int).Mul(old, big.NewInt(clamped)), big.NewInt(1209600))
		bits := make([]byte, 4)
		binary.LittleEndian.PutUint32(bits, blockchain.BigToCompact(target))
		run(fmt.Sprintf("retarget %d", elapsed), "retarget", map[string][]byte{"oldTarget": scriptPositiveBigInt(t, old.Bytes()), "firstTime": scriptInt(t, 100), "lastTime": scriptInt(t, 100+elapsed), "bits": bits}, true)
	}
	fixture := headerFixtures(t)[0]
	for _, mutation := range []string{"valid", "truncated", "trailing", "not coinbase", "witness encoding", "nonminimal varint"} {
		raw := beaconHex(t, fixture.Coinbase)
		switch mutation {
		case "truncated":
			raw = raw[:len(raw)-1]
		case "trailing":
			raw = append(raw, 0)
		case "not coinbase":
			raw[5] = 1
		case "witness encoding":
			raw = append(append(bytes.Clone(raw[:4]), 0, 1), raw[4:]...)
		case "nonminimal varint":
			raw = append(append(bytes.Clone(raw[:41]), 253, raw[41], 0), raw[42:]...)
		}
		run("coinbase "+mutation, "reward", map[string][]byte{"transaction": raw, "expected": scriptPositiveBigInt(t, fixtureReward(t, fixture).Bytes())}, mutation == "valid")
	}
	// Large witnesses are parsed and hashed without concatenating the full tx.
	for _, count := range []int{1, 16, 17} {
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, SignatureScript: []byte{1, 1}})
		for range count {
			tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: bytes.Repeat([]byte{0x51}, 200)})
		}
		var raw bytes.Buffer
		if err := tx.SerializeNoWitness(&raw); err != nil {
			t.Fatal(err)
		}
		run(fmt.Sprintf("coinbase outputs %d", count), "reward", map[string][]byte{"transaction": raw.Bytes(), "expected": scriptInt(t, int64(count)*1000)}, count <= 16)
	}
	for _, length := range []int{4096, 4097} {
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, SignatureScript: []byte{1, 1}})
		tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: make([]byte, length-64)})
		var raw bytes.Buffer
		if err := tx.SerializeNoWitness(&raw); err != nil {
			t.Fatal(err)
		}
		if raw.Len() != length {
			t.Fatalf("capacity fixture: %d != %d", raw.Len(), length)
		}
		run(fmt.Sprintf("coinbase bytes %d", length), "reward", map[string][]byte{"transaction": raw.Bytes(), "expected": scriptInt(t, 1000)}, length == 4096)
	}
}
