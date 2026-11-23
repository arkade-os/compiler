package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

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

func beaconState(t *testing.T, height int64, fields ...[]byte) []byte {
	t.Helper()
	state := beaconNum(t, big.NewInt(height), 8)
	for _, field := range fields {
		state = append(state, field...)
	}
	return state
}

// Build all spend leaves into the same Taproot tree, as a deployment does.
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

func beaconObservations(t *testing.T, kind byte) map[string]instantiatedGroup {
	t.Helper()
	controlGidx := int64(2)
	if kind == 2 {
		controlGidx = 0
	}
	return beaconInstances(t, compileArtifact(t, "../../examples/hashprice/beacon_coin.ark"), map[string][]byte{
		"controlGidx": scriptInt(t, controlGidx),
	})
}

func beaconObservation(t *testing.T, kind byte) instantiatedGroup {
	t.Helper()
	return beaconObservations(t, kind)["continue"]
}

func blockBeaconState(t *testing.T, height int64, hash, bits, epoch []byte, count int64, floor *big.Int) []byte {
	t.Helper()
	return beaconState(t, height, beaconNum(t, big.NewInt(count), 8), hash, bits, epoch, beaconNum(t, floor, 33))
}

func blockObservation(t *testing.T, height int64, header []byte, bits, epoch []byte, work *big.Int) []byte {
	t.Helper()
	return beaconState(t, height, header, bits, epoch, beaconNum(t, work, 33))
}

const (
	hashpriceHistogramDepth = 20
	hashpriceMaxBucket      = (1 << hashpriceHistogramDepth) - 1
)

func hashpriceBucket(q *big.Int) uint32 {
	scaled := new(big.Int).Mul(q, big.NewInt(274658203125))
	scaled.Rsh(scaled, 219)
	scaled.Quo(scaled, big.NewInt(4369))
	if !scaled.IsUint64() || scaled.Uint64() >= hashpriceMaxBucket {
		return hashpriceMaxBucket
	}
	return uint32(scaled.Uint64())
}

type histogramNode struct {
	count int64
	hash  [32]byte
}

func histogramCountBytes(count int64) []byte {
	b, err := arkade.BigNumFromInt64(count).FixedBytes(8)
	if err != nil {
		panic(err)
	}
	return b
}

func histogramLeafHash(count int64) [32]byte {
	var pre [9]byte
	pre[0] = 0x00
	copy(pre[1:], histogramCountBytes(count))
	return sha256.Sum256(pre[:])
}

func histogramBranchHash(left, right histogramNode) [32]byte {
	var pre [81]byte
	pre[0] = 0x01
	copy(pre[1:9], histogramCountBytes(left.count))
	copy(pre[9:41], left.hash[:])
	copy(pre[41:49], histogramCountBytes(right.count))
	copy(pre[49:81], right.hash[:])
	return sha256.Sum256(pre[:])
}

var histogramZeroNodes = func() [hashpriceHistogramDepth + 1]histogramNode {
	var zeros [hashpriceHistogramDepth + 1]histogramNode
	zeros[0] = histogramNode{count: 0, hash: histogramLeafHash(0)}
	for lvl := 1; lvl <= hashpriceHistogramDepth; lvl++ {
		zeros[lvl] = histogramNode{
			count: 0,
			hash:  histogramBranchHash(zeros[lvl-1], zeros[lvl-1]),
		}
	}
	return zeros
}()

type sparseHistogram struct {
	levels [hashpriceHistogramDepth + 1]map[uint32]histogramNode
}

func newSparseHistogram() *sparseHistogram {
	h := &sparseHistogram{}
	for i := range h.levels {
		h.levels[i] = make(map[uint32]histogramNode)
	}
	return h
}

func (h *sparseHistogram) clone() *sparseHistogram {
	cp := newSparseHistogram()
	for i := range h.levels {
		for k, v := range h.levels[i] {
			cp.levels[i][k] = v
		}
	}
	return cp
}

func (h *sparseHistogram) node(level int, index uint32) histogramNode {
	if n, ok := h.levels[level][index]; ok {
		return n
	}
	return histogramZeroNodes[level]
}

func (h *sparseHistogram) add(bucket uint32, delta int64) {
	leaf := h.node(0, bucket)
	nextCount := leaf.count + delta
	if nextCount == 0 {
		delete(h.levels[0], bucket)
	} else {
		h.levels[0][bucket] = histogramNode{count: nextCount, hash: histogramLeafHash(nextCount)}
	}
	idx := bucket
	for lvl := 0; lvl < hashpriceHistogramDepth; lvl++ {
		parentIdx := idx >> 1
		left := h.node(lvl, parentIdx<<1)
		right := h.node(lvl, (parentIdx<<1)|1)
		total := left.count + right.count
		if total == 0 {
			delete(h.levels[lvl+1], parentIdx)
		} else {
			h.levels[lvl+1][parentIdx] = histogramNode{
				count: total,
				hash:  histogramBranchHash(left, right),
			}
		}
		idx = parentIdx
	}
}

func (h *sparseHistogram) root() []byte {
	root := h.node(hashpriceHistogramDepth, 0).hash
	return bytes.Clone(root[:])
}

func (h *sparseHistogram) writeWitness(t *testing.T, values map[string][]byte, countKey, sibPrefix string, bucket uint32) {
	t.Helper()
	values[countKey] = scriptInt(t, h.node(0, bucket).count)
	idx := bucket
	for lvl := 0; lvl < hashpriceHistogramDepth; lvl++ {
		sib := h.node(lvl, idx^1)
		values[fmt.Sprintf("%s.%d.count", sibPrefix, lvl)] = scriptInt(t, sib.count)
		values[fmt.Sprintf("%s.%d.hash", sibPrefix, lvl)] = bytes.Clone(sib.hash[:])
		idx >>= 1
	}
}

func hashPriceBeaconState(t *testing.T, height int64, accumulator *big.Int, count int64, histRoot []byte) []byte {
	t.Helper()
	if histRoot == nil {
		histRoot = histogramZeroNodes[hashpriceHistogramDepth].hash[:]
	}
	return beaconState(t, height, beaconNum(t, big.NewInt(count), 8), beaconNum(t, accumulator, 64), histRoot)
}

func hashPriceObservation(t *testing.T, height int64, numerator, accumulator *big.Int, hash []byte, mintedAt int64, rootBefore, rootAfter []byte) []byte {
	t.Helper()
	if rootBefore == nil {
		rootBefore = histogramZeroNodes[hashpriceHistogramDepth].hash[:]
	}
	if rootAfter == nil {
		rootAfter = histogramZeroNodes[hashpriceHistogramDepth].hash[:]
	}
	return beaconState(t, height, beaconNum(t, numerator, 64), beaconNum(t, accumulator, 64), hash, beaconNum(t, big.NewInt(mintedAt), 8), rootBefore, rootAfter)
}

func linkBeaconInput(t *testing.T, next *psbt.Packet, vin int, previous *psbt.Packet, vout uint32) {
	t.Helper()
	next.UnsignedTx.TxIn[vin].PreviousOutPoint = wire.OutPoint{Hash: previous.UnsignedTx.TxHash(), Index: vout}
	next.Inputs[vin].WitnessUtxo = previous.UnsignedTx.TxOut[vout]
	next.Inputs[vin].Unknowns = nil
	if err := txutils.SetArkPsbtField(next, vin, arkade.PrevArkTxField, *previous.UnsignedTx); err != nil {
		t.Fatal(err)
	}
}

func fixtureWork(t *testing.T, f headerFixture) *big.Int {
	t.Helper()
	work := new(big.Int)
	for _, encoded := range f.Headers[:6] {
		header := beaconHex(t, encoded)
		work.Add(work, blockchain.CalcWork(binary.LittleEndian.Uint32(header[72:76])))
	}
	return work
}

func headerWitness(t *testing.T, f headerFixture) map[string][]byte {
	t.Helper()
	values := map[string][]byte{}
	for i, header := range f.Headers[:6] {
		values[fmt.Sprintf("headers.%d", i)] = beaconHex(t, header)
	}
	return values
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

func hashpriceProofFixture(t *testing.T) headerFixture {
	t.Helper()
	for _, f := range headerFixtures(t) {
		if f.Height == 976289 {
			return f
		}
	}
	t.Fatal("missing SP1 coinbase block fixture")
	return headerFixture{}
}

type hashpriceSP1Fixture struct {
	Proof        string `json:"proof"`
	PublicValues string `json:"public_values"`
	GenericProof string `json:"generic_proof"`
}

func hashpriceSP1(t *testing.T) hashpriceSP1Fixture {
	t.Helper()
	data, err := os.ReadFile("testdata/hashprice_coinbase_sp1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture hashpriceSP1Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func hashpriceMintValues(t *testing.T, f headerFixture, mintedAt int64, hist *sparseHistogram, bucket uint32) map[string][]byte {
	t.Helper()
	fixture := hashpriceSP1(t)
	proof, public := beaconHex(t, fixture.Proof), beaconHex(t, fixture.PublicValues)
	if len(public) != 40 || !bytes.Equal(public[:32], chainhash.DoubleHashB(beaconHex(t, f.Coinbase))) {
		t.Fatal("SP1 fixture does not match coinbase")
	}
	values := groth16ProofInputs(t, proof)
	values["mintedAt"] = scriptInt(t, mintedAt)
	values["coinbaseTxid"] = bytes.Clone(public[:32])
	values["reward"] = scriptInt(t, int64(binary.LittleEndian.Uint64(public[32:])))
	values["merkleDepth"] = scriptInt(t, int64(len(f.Merkle)))
	for i := range 20 {
		value := make([]byte, 32)
		if i < len(f.Merkle) {
			value = beaconHex(t, f.Merkle[i])
		}
		values[fmt.Sprintf("siblings.%d", i)] = value
	}
	hist.writeWitness(t, values, "bucketCount", "histogramSiblings", bucket)
	return values
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
			before := blockBeaconState(t, f.Height-1, parentHash, first[72:76], epoch[68:72], 0, new(big.Int))
			epochTime := epoch[68:72]
			if f.Height%2016 == 0 {
				epochTime = first[68:72]
			}
			after := blockBeaconState(t, f.Height, chainhash.DoubleHashB(first), second[72:76], epochTime, 0, new(big.Int))
			observation := blockObservation(t, f.Height, first, second[72:76], epochTime, fixtureWork(t, f))
			for _, mutation := range []string{"valid", "link", "pow", "difficulty", "height", "state hash", "state target", "state epoch", "output script", "supply", "missing header", "long header", "work", "coin target", "coin epoch", "recovering", "below floor", "equal floor", "above floor", "floor not cleared"} {
				t.Run(mutation, func(t *testing.T) {
					values := headerWitness(t, f)
					inputState := bytes.Clone(before)
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
					case "height":
						states[0][0] ^= 1
					case "state hash":
						states[0][16] ^= 1
					case "state target":
						states[0][48] ^= 1
					case "state epoch":
						states[0][52] ^= 1
					case "output script":
						outs[1].PkScript[2] ^= 1
					case "supply":
						assets[1].Outputs[0].Amount = 2
					case "missing header":
						values["headers.5"] = nil
					case "long header":
						values["headers.5"] = append(values["headers.5"], 0)
					case "work":
						states[1][96] ^= 1
					case "coin target":
						states[1][88] ^= 1
					case "coin epoch":
						states[1][92] ^= 1
					case "recovering":
						inputState[8] = 1
					case "below floor", "equal floor", "above floor", "floor not cleared":
						floor := fixtureWork(t, f)
						if mutation == "below floor" {
							floor.Add(floor, big.NewInt(1))
						}
						if mutation == "above floor" {
							floor.Sub(floor, big.NewInt(1))
						}
						copy(inputState[56:], beaconNum(t, floor, 33))
						if mutation == "floor not cleared" {
							copy(states[0][56:], inputState[56:])
						}
					}
					witness := covenantWitness(t, verifier, covenantGroup(t, verifier, "mint"), values)
					ptx := beaconSpend(t, []beaconCoin{{issuer, inputState, witness, blockControlID}}, outs, states, assets)
					// Pre-BIP65 fixtures have obsolete versions and must be rejected.
					beaconResult(t, ptx, f.Height > 388381 && (mutation == "valid" || mutation == "equal floor" || mutation == "above floor"))
				})
			}
		})
	}
}

func TestHashpriceBeacon(t *testing.T) {
	f := hashpriceProofFixture(t)
	header := beaconHex(t, f.Headers[0])
	reward := fixtureReward(t, f)
	source := beaconObservation(t, 2)
	hpc := beaconObservation(t, 4)
	checkpointHeight := int64(975744) // 484 * 2016: 544 prior observations before height 976289
	contract := compileArtifact(t, "../../examples/hashprice/hashprice_beacon.ark")
	issuer := beaconInstances(t, contract, map[string][]byte{
		"coinGidx":            scriptInt(t, 3),
		"sourceGidx":          scriptInt(t, 1),
		"blockCoinScript":     source.pkScript[2:],
		"hashPriceCoinScript": hpc.pkScript[2:],
		"checkpointHeight":    scriptInt(t, checkpointHeight),
	})["mint"]
	target := blockchain.CompactToBig(binary.LittleEndian.Uint32(header[72:76]))
	q := new(big.Int).Mul(reward, target)
	bucket := hashpriceBucket(q)
	if bucket != 4665 {
		t.Fatalf("mainnet block 976289 bucket = %d, want 4665 (46650..46659 sats/PH/s-day)", bucket)
	}
	histBefore := newSparseHistogram()
	histBefore.add(100, 200)
	histBefore.add(bucket, 12)
	histBefore.add(9000, 332)
	histAfter := histBefore.clone()
	histAfter.add(bucket, 1)
	rootBefore := histBefore.root()
	rootAfter := histAfter.root()
	previous := new(big.Int).Lsh(big.NewInt(1), 300)
	next := new(big.Int).Add(previous, q)
	before := hashPriceBeaconState(t, f.Height-1, previous, 0, rootBefore)
	block := blockObservation(t, f.Height, header, beaconHex(t, f.Headers[1])[72:76], beaconHex(t, f.EpochStartHeader)[68:72], fixtureWork(t, f))
	after := hashPriceBeaconState(t, f.Height, next, 0, rootAfter)
	// Produce the BHC through the real header beacon, then consume that exact
	// output in the ordinary mint case. Mutations use isolated authenticated states.
	headerContract := compileArtifact(t, "../../examples/hashprice/block_header_beacon.ark")
	headerIssuer := beaconInstances(t, headerContract, map[string][]byte{"coinGidx": scriptInt(t, 1), "blockCoinScript": source.pkScript[2:]})["mint"]
	parent := beaconHex(t, f.ParentHeader)
	epoch := beaconHex(t, f.EpochStartHeader)[68:72]
	headerBefore := blockBeaconState(t, f.Height-1, chainhash.DoubleHashB(parent), header[72:76], epoch, 0, new(big.Int))
	headerAfter := blockBeaconState(t, f.Height, chainhash.DoubleHashB(header), beaconHex(t, f.Headers[1])[72:76], epoch, 0, new(big.Int))
	headerProof := covenantWitness(t, headerContract, covenantGroup(t, headerContract, "mint"), headerWitness(t, f))
	headerMint := beaconSpend(t, []beaconCoin{{headerIssuer, headerBefore, headerProof, blockControlID}},
		[]*wire.TxOut{beaconOut(headerIssuer), beaconOut(source)}, [][]byte{headerAfter, block},
		asset.Packet{beaconGroup(blockControlID, []uint16{0}, []uint16{0}), beaconGroup(blockCoinID, nil, []uint16{1})})
	beaconResult(t, headerMint, true)
	for _, mutation := range []string{"valid", "past endpoint", "future endpoint", "single transaction", "max merkle depth", "overflow bucket", "too old", "too far ahead", "negative time", "skip", "accumulator", "numerator", "block hash", "minting time", "recovering", "output recovery", "source state", "source identity", "source script", "extra supply", "burn source", "forged reward", "negative reward", "excessive reward", "wrong txid", "header merkle root", "nonzero index", "zero proof", "generic guest proof", "sibling", "short sibling", "unused sibling", "short depth", "negative depth", "excessive depth", "wrong bucket count", "negative bucket count", "wrong histogram sibling hash", "wrong histogram sibling count", "negative histogram sibling count", "short histogram sibling", "wrong rootBefore", "wrong rootAfter", "wrong coin rootBefore", "wrong coin rootAfter", "wrong checkpoint total"} {
		t.Run(mutation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				mintedAt := time.Now().Unix()
				switch mutation {
				case "past endpoint":
					mintedAt -= 3600
				case "future endpoint":
					mintedAt += 3600
				case "too old":
					mintedAt -= 3601
				case "too far ahead":
					mintedAt += 3601
				}
				observation := hashPriceObservation(t, f.Height, q, next, chainhash.DoubleHashB(header), mintedAt, rootBefore, rootAfter)
				inputState := bytes.Clone(before)
				sourceState := bytes.Clone(block)
				states := [][]byte{bytes.Clone(after), bytes.Clone(sourceState), bytes.Clone(observation)}
				outs := []*wire.TxOut{beaconOut(issuer), beaconOut(source), beaconOut(hpc)}
				assets := asset.Packet{beaconGroup(hashPriceControlID, []uint16{0}, []uint16{0}), beaconGroup(blockCoinID, []uint16{1}, []uint16{1}), beaconGroup(hashPriceCoinID, nil, []uint16{2})}
				values := hashpriceMintValues(t, f, mintedAt, histBefore, bucket)
				// Synthetic authenticated BHCs isolate each proof binding. Header
				// issuance and PoW are tested separately against mined fixtures.
				setRoot := func(root []byte) {
					copy(sourceState[44:76], root)
					copy(states[1][44:76], root)
					copy(states[2][136:168], chainhash.DoubleHashB(sourceState[8:88]))
				}
				branch := func(depth int, rightFirst bool) []byte {
					root := bytes.Clone(values["coinbaseTxid"])
					for i := range depth {
						sibling := values[fmt.Sprintf("siblings.%d", i)]
						pair := append(bytes.Clone(root), sibling...)
						if i == 0 && rightFirst {
							pair = append(bytes.Clone(sibling), root...)
						}
						root = chainhash.DoubleHashB(pair)
					}
					return root
				}
				switch mutation {
				case "single transaction":
					values["merkleDepth"] = nil
					for i := range 20 {
						values[fmt.Sprintf("siblings.%d", i)] = make([]byte, 32)
					}
					setRoot(values["coinbaseTxid"])
				case "max merkle depth":
					values["merkleDepth"] = scriptInt(t, 20)
					for i := range 20 {
						values[fmt.Sprintf("siblings.%d", i)] = chainhash.DoubleHashB([]byte{byte(i)})
					}
					setRoot(branch(20, false))
				case "overflow bucket":
					// Difficulty 1 (0x1d00ffff) with ~3.13 BTC reward far exceeds 10,485,750 sats/PH/s-day and clamps to max bucket.
					binary.LittleEndian.PutUint32(sourceState[80:84], 0x1d00ffff)
					copy(states[1][80:84], sourceState[80:84])
					copy(states[2][136:168], chainhash.DoubleHashB(sourceState[8:88]))
					maxTarget := blockchain.CompactToBig(0x1d00ffff)
					maxQ := new(big.Int).Mul(reward, maxTarget)
					maxAcc := new(big.Int).Add(previous, maxQ)
					maxHistAfter := histBefore.clone()
					maxHistAfter.add(hashpriceMaxBucket, 1)
					maxRootAfter := maxHistAfter.root()
					histBefore.writeWitness(t, values, "bucketCount", "histogramSiblings", hashpriceMaxBucket)
					copy(states[0][16:80], beaconNum(t, maxAcc, 64))
					copy(states[0][80:112], maxRootAfter)
					copy(states[2][8:72], beaconNum(t, maxQ, 64))
					copy(states[2][72:136], beaconNum(t, maxAcc, 64))
					copy(states[2][208:240], maxRootAfter)
				case "forged reward":
					forged := new(big.Int).Add(reward, big.NewInt(1))
					values["reward"] = scriptBigInt(t, forged)
					numerator := new(big.Int).Mul(forged, target)
					accumulator := new(big.Int).Add(previous, numerator)
					copy(states[0][16:80], beaconNum(t, accumulator, 64))
					copy(states[2][8:72], beaconNum(t, numerator, 64))
					copy(states[2][72:136], beaconNum(t, accumulator, 64))
				case "negative reward":
					values["reward"] = scriptInt(t, -1)
				case "excessive reward":
					values["reward"] = scriptInt(t, 2100000000000001)
				case "wrong txid":
					values["coinbaseTxid"][0] ^= 1
					setRoot(branch(len(f.Merkle), false))
				case "header merkle root":
					root := bytes.Clone(sourceState[44:76])
					root[0] ^= 1
					setRoot(root)
				case "nonzero index":
					setRoot(branch(len(f.Merkle), true))
				case "zero proof":
					for name := range values {
						if strings.HasPrefix(name, "proof.") {
							values[name] = nil
						}
					}
				case "generic guest proof":
					for name, value := range groth16ProofInputs(t, beaconHex(t, hashpriceSP1(t).GenericProof)) {
						values[name] = value
					}
				case "sibling":
					values["siblings.0"][0] ^= 1
				case "short sibling":
					values["siblings.0"] = values["siblings.0"][:31]
				case "unused sibling":
					values["siblings.19"][0] = 1
				case "short depth":
					values["merkleDepth"] = scriptInt(t, int64(len(f.Merkle)-1))
				case "negative depth":
					values["merkleDepth"] = scriptInt(t, -1)
				case "excessive depth":
					values["merkleDepth"] = scriptInt(t, 21)
				case "wrong bucket count":
					values["bucketCount"] = scriptInt(t, 13)
				case "negative bucket count":
					values["bucketCount"] = scriptInt(t, -1)
				case "wrong histogram sibling hash":
					values["histogramSiblings.0.hash"][0] ^= 1
				case "wrong histogram sibling count":
					values["histogramSiblings.19.count"] = scriptInt(t, 999)
				case "negative histogram sibling count":
					values["histogramSiblings.0.count"] = scriptInt(t, -1)
				case "short histogram sibling":
					values["histogramSiblings.0.hash"] = values["histogramSiblings.0.hash"][:31]
				case "wrong rootBefore":
					inputState[80] ^= 1
				case "wrong rootAfter":
					states[0][80] ^= 1
				case "wrong coin rootBefore":
					states[2][176] ^= 1
				case "wrong coin rootAfter":
					states[2][208] ^= 1
				case "wrong checkpoint total":
					// Extra observation in prior histogram mismatches height - 1 - checkpointHeight.
					badHist := histBefore.clone()
					badHist.add(1, 1)
					badAfter := badHist.clone()
					badAfter.add(bucket, 1)
					copy(inputState[80:112], badHist.root())
					copy(states[0][80:112], badAfter.root())
					copy(states[2][176:208], badHist.root())
					copy(states[2][208:240], badAfter.root())
					badHist.writeWitness(t, values, "bucketCount", "histogramSiblings", bucket)
				case "skip":
					states[0][0]++
				case "accumulator":
					states[0][16]++
				case "numerator":
					states[2][8]++
				case "block hash":
					states[2][136] ^= 1
				case "minting time":
					states[2][168] ^= 1
				case "negative time":
					mintedAt = -1
				case "recovering":
					inputState[8] = 1
				case "output recovery":
					states[0][8] = 1
				case "source state":
					states[1][88]++
				case "source identity":
					assets[1].AssetId = &asset.AssetId{Txid: chainhash.Hash{5}, Index: 0}
				case "source script":
					outs[1].PkScript[2] ^= 1
				case "extra supply":
					assets[2].Outputs[0].Amount++
				case "burn source":
					assets[1].Outputs = nil
				}
				values["mintedAt"] = scriptInt(t, mintedAt)
				witness := covenantWitness(t, contract, covenantGroup(t, contract, "mint"), values)
				if len(witness) != 73 {
					t.Fatalf("mint witness has %d items, want 73", len(witness))
				}
				if witness.SerializeSize() > 1826 {
					t.Fatalf("mint witness exceeds its 1826-byte serialized bound: %d", witness.SerializeSize())
				}
				for _, item := range witness {
					if len(item) > 32 {
						t.Fatalf("mint witness item has %d bytes", len(item))
					}
				}
				if len(issuer.covenant) > txscript.MaxScriptSize {
					t.Fatal("mint script exceeds VM limit")
				}
				ptx := beaconSpend(t, []beaconCoin{{issuer, inputState, witness, hashPriceControlID}, {source, sourceState, nil, blockCoinID}}, outs, states, assets)
				if mutation == "valid" {
					linkBeaconInput(t, ptx, 1, headerMint, 1)
				}
				valid := mutation == "valid" || mutation == "past endpoint" || mutation == "future endpoint" || mutation == "single transaction" || mutation == "max merkle depth" || mutation == "overflow bucket"
				beaconResult(t, ptx, valid)
				if mutation == "valid" || mutation == "max merkle depth" {
					t.Logf("HashPriceBeacon mint: script=%d bytes, witness=%d bytes serialized / %d items, largest item=32 bytes", len(issuer.covenant), witness.SerializeSize(), len(witness))
				}
			})
		})
	}
}

func TestHashpriceAccumulatorChallenge(t *testing.T) {
	f := hashpriceProofFixture(t)
	header := beaconHex(t, f.Headers[0])
	bhc, hpc := beaconObservation(t, 2), beaconObservation(t, 4)
	checkpointHeight := int64(975744)
	contract := compileArtifact(t, "../../examples/hashprice/hashprice_beacon.ark")
	beacon := beaconInstances(t, contract, map[string][]byte{
		"coinGidx":            scriptInt(t, 3),
		"sourceGidx":          scriptInt(t, 1),
		"blockCoinScript":     bhc.pkScript[2:],
		"hashPriceCoinScript": hpc.pkScript[2:],
		"checkpointHeight":    scriptInt(t, checkpointHeight),
	})["challenge"]
	rootCurrent := bytes.Repeat([]byte{0x11}, 32)
	rootBefore := bytes.Repeat([]byte{0x22}, 32)
	rootAfter := bytes.Repeat([]byte{0x33}, 32)
	for _, mutation := range []string{"valid", "latest", "long suffix", "same hash", "source height", "unissued", "zero height", "checkpoint height", "recovering", "negative numerator", "negative rollback", "hpc identity", "bhc identity", "hpc script", "bhc script", "hpc state size", "bhc state size", "output height", "output accumulator", "output count", "output root", "output hash", "output timestamp", "source state", "hpc value", "bhc value", "burn disputed", "burn source", "clone"} {
		t.Run(mutation, func(t *testing.T) {
			before := hashPriceBeaconState(t, f.Height+2, big.NewInt(999), 0, rootCurrent)
			disputed := hashPriceObservation(t, f.Height, big.NewInt(7), big.NewInt(107), chainhash.DoubleHashB(header), pastTimeout, rootBefore, rootAfter)
			disputed[136] ^= 1
			block := blockObservation(t, f.Height, header, header[72:76], make([]byte, 4), fixtureWork(t, f))
			reset := hashPriceBeaconState(t, f.Height-1, big.NewInt(100), 3, rootBefore)
			inputs := []beaconCoin{{beacon, before, nil, hashPriceControlID}, {hpc, disputed, nil, hashPriceCoinID}, {bhc, block, nil, blockCoinID}}
			outputs := []*wire.TxOut{beaconOut(beacon), beaconOut(hpc), beaconOut(bhc)}
			assets := asset.Packet{beaconGroup(hashPriceControlID, []uint16{0}, []uint16{0}), beaconGroup(hashPriceCoinID, []uint16{1}, []uint16{1}), beaconGroup(blockCoinID, []uint16{2}, []uint16{2})}
			switch mutation {
			case "latest":
				copy(before[0:8], disputed[0:8])
				reset[8] = 1
			case "long suffix":
				copy(before[0:8], beaconNum(t, big.NewInt(f.Height+10000), 8))
				copy(reset[8:16], beaconNum(t, big.NewInt(10001), 8))
			case "same hash":
				disputed[136] ^= 1
			case "source height":
				block[0] ^= 1
			case "unissued":
				copy(before[0:8], reset[0:8])
			case "zero height":
				clear(disputed[0:8])
				clear(block[0:8])
			case "checkpoint height":
				copy(disputed[0:8], beaconNum(t, big.NewInt(checkpointHeight), 8))
				copy(block[0:8], beaconNum(t, big.NewInt(checkpointHeight), 8))
				copy(reset[0:8], beaconNum(t, big.NewInt(checkpointHeight-1), 8))
				copy(reset[8:16], beaconNum(t, big.NewInt(f.Height+2-checkpointHeight+1), 8))
			case "recovering":
				before[8] = 1
			case "negative numerator":
				disputed[71] = 0x80
				copy(reset[16:80], beaconNum(t, big.NewInt(114), 64))
			case "negative rollback":
				copy(disputed[72:136], beaconNum(t, big.NewInt(6), 64))
				clear(reset[16:80])
				reset[16], reset[79] = 1, 0x80
			case "hpc identity":
				wrong := asset.AssetId{Txid: chainhash.Hash{5}, Index: 3}
				inputs[1].id, assets[1].AssetId = wrong, &wrong
			case "bhc identity":
				wrong := asset.AssetId{Txid: chainhash.Hash{5}, Index: 1}
				inputs[2].id, assets[2].AssetId = wrong, &wrong
			case "hpc script":
				inputs[1].instance, outputs[1] = bhc, beaconOut(bhc)
			case "bhc script":
				inputs[2].instance, outputs[2] = hpc, beaconOut(hpc)
			case "hpc state size":
				disputed = disputed[:239]
				inputs[1].state = disputed
			case "bhc state size":
				block = block[:128]
				inputs[2].state = block
			case "output height":
				reset[0] ^= 1
			case "output accumulator":
				reset[16] ^= 1
			case "output count":
				reset[8]++
			case "output root":
				reset[80] ^= 1
			case "hpc value":
				outputs[1].Value--
			case "bhc value":
				outputs[2].Value--
			case "burn disputed":
				assets[1].Outputs = nil
			case "burn source":
				assets[2].Outputs = nil
			case "clone":
				assets[1].Outputs[0].Amount++
			}
			states := [][]byte{reset, bytes.Clone(disputed), bytes.Clone(block)}
			switch mutation {
			case "output hash":
				states[1][136] ^= 1
			case "output timestamp":
				states[1][168] ^= 1
			case "source state":
				states[2][88] ^= 1
			}
			ptx := beaconSpend(t, inputs, outputs, states, assets)
			beaconResult(t, ptx, mutation == "valid" || mutation == "latest" || mutation == "long suffix")
		})
	}
}

func TestHashpriceAccumulatorBurns(t *testing.T) {
	coins, bhc := beaconObservations(t, 4), beaconObservation(t, 2)
	contract := compileArtifact(t, "../../examples/hashprice/hashprice_beacon.ark")
	beacon := beaconInstances(t, contract, map[string][]byte{
		"coinGidx":            scriptInt(t, 3),
		"sourceGidx":          scriptInt(t, 1),
		"blockCoinScript":     bhc.pkScript[2:],
		"hashPriceCoinScript": coins["burn"].pkScript[2:],
		"checkpointHeight":    scriptInt(t, 2016),
	})["burn"]
	histRoot := bytes.Repeat([]byte{0x44}, 32)
	for _, mutation := range []string{"valid", "complete", "normal", "too many", "zero burns", "retained height", "older", "control identity", "coin identity", "input amount", "duplicate allocation", "continued coin", "wrong decrement", "changed height", "changed accumulator", "changed root", "negative controller height", "controller size"} {
		t.Run(mutation, func(t *testing.T) {
			before := hashPriceBeaconState(t, 3000, big.NewInt(42), 3, histRoot)
			after := hashPriceBeaconState(t, 3000, big.NewInt(42), 1, histRoot)
			first := hashPriceObservation(t, 3003, big.NewInt(1), big.NewInt(45), make([]byte, 32), pastTimeout, nil, nil)
			second := hashPriceObservation(t, 3001, big.NewInt(1), big.NewInt(43), make([]byte, 32), pastTimeout, nil, nil)
			inputs := []beaconCoin{{beacon, before, nil, hashPriceControlID}, {coins["burn"], first, nil, hashPriceCoinID}, {coins["burn"], second, nil, hashPriceCoinID}}
			assets := asset.Packet{beaconGroup(hashPriceControlID, []uint16{0}, []uint16{0}), beaconGroup(hashPriceCoinID, []uint16{1, 2}, nil)}
			switch mutation {
			case "complete":
				before[8], after[8] = 2, 0
			case "normal":
				before[8] = 0
			case "too many":
				before[8], after[8] = 1, 0
			case "zero burns":
				inputs, assets = inputs[:1], assets[:1]
				after[8] = before[8]
			case "retained height":
				copy(second[0:8], before[0:8])
			case "older":
				copy(second[0:8], beaconNum(t, big.NewInt(2999), 8))
			case "control identity":
				assets[0].AssetId, inputs[0].id = &blockControlID, blockControlID
			case "coin identity":
				assets[1].AssetId = &blockCoinID
				inputs[1].id, inputs[2].id = blockCoinID, blockCoinID
			case "input amount":
				assets[1].Inputs[0].Amount = 2
				before[8] = 4
			case "duplicate allocation":
				assets[1].Inputs = append(assets[1].Inputs, assets[1].Inputs[0])
				before[8] = 4
			case "continued coin":
				inputs[1].instance = coins["continue"]
			case "wrong decrement":
				after[8] = 0
			case "changed height":
				after[0] ^= 1
			case "changed accumulator":
				after[16] ^= 1
			case "changed root":
				after[80] ^= 1
			case "negative controller height":
				before[7] = 0x80
			case "controller size":
				inputs[0].state = before[:111]
			}
			ptx := beaconSpend(t, inputs, []*wire.TxOut{beaconOut(beacon)}, [][]byte{after}, assets)
			withExtraInput(t, ptx, fundingTx([]byte{txscript.OP_TRUE}, 10000))
			beaconResult(t, ptx, mutation == "valid" || mutation == "complete")
		})
	}
}

func TestHashpriceAccumulatorRecovery(t *testing.T) {
	bhcs, hpcs := beaconObservations(t, 2), beaconObservations(t, 4)
	contract := compileArtifact(t, "../../examples/hashprice/hashprice_beacon.ark")
	f := hashpriceProofFixture(t)
	checkpointHeight := f.Height - 1
	beacon := beaconInstances(t, contract, map[string][]byte{
		"coinGidx":            scriptInt(t, 3),
		"sourceGidx":          scriptInt(t, 1),
		"blockCoinScript":     bhcs["continue"].pkScript[2:],
		"hashPriceCoinScript": hpcs["continue"].pkScript[2:],
		"checkpointHeight":    scriptInt(t, checkpointHeight),
	})
	synctest.Test(t, func(t *testing.T) {
		type liveCoin struct {
			state []byte
			tx    *psbt.Packet
			vout  uint32
		}
		var controller *psbt.Packet
		height, count, accumulator := checkpointHeight, int64(0), big.NewInt(50)
		hist := newSparseHistogram()
		link := func(ptx *psbt.Packet, vin int, coin *liveCoin) {
			if coin.tx != nil {
				linkBeaconInput(t, ptx, vin, coin.tx, coin.vout)
			}
		}
		linkController := func(ptx *psbt.Packet) {
			if controller != nil {
				linkBeaconInput(t, ptx, 0, controller, 0)
			}
		}
		mint := func(source *liveCoin, numerator *big.Int, valid bool) *liveCoin {
			bucket := hashpriceBucket(numerator)
			rootBefore := hist.root()
			nextHist := hist.clone()
			nextHist.add(bucket, 1)
			rootAfter := nextHist.root()
			before := hashPriceBeaconState(t, height, accumulator, count, rootBefore)
			next := new(big.Int).Add(accumulator, numerator)
			after := hashPriceBeaconState(t, height+1, next, 0, rootAfter)
			mintedAt := time.Now().Unix()
			observation := hashPriceObservation(t, height+1, numerator, next, chainhash.DoubleHashB(source.state[8:88]), mintedAt, rootBefore, rootAfter)
			witness := covenantWitness(t, contract, covenantGroup(t, contract, "mint"), hashpriceMintValues(t, f, mintedAt, hist, bucket))
			ptx := beaconSpend(t, []beaconCoin{{beacon["mint"], before, witness, hashPriceControlID}, {bhcs["continue"], source.state, nil, blockCoinID}},
				[]*wire.TxOut{beaconOut(beacon["mint"]), beaconOut(bhcs["continue"]), beaconOut(hpcs["continue"])}, [][]byte{after, source.state, observation},
				asset.Packet{beaconGroup(hashPriceControlID, []uint16{0}, []uint16{0}), beaconGroup(blockCoinID, []uint16{1}, []uint16{1}), beaconGroup(hashPriceCoinID, nil, []uint16{2})})
			linkController(ptx)
			link(ptx, 1, source)
			beaconResult(t, ptx, valid)
			if !valid {
				return nil
			}
			controller, height, accumulator, hist = ptx, height+1, next, nextHist
			source.tx, source.vout = ptx, 1
			return &liveCoin{observation, ptx, 2}
		}
		challenge := func(disputed, source *liveCoin, retainedHeight int64, retainedAccumulator *big.Int, retainedHist *sparseHistogram) {
			before := hashPriceBeaconState(t, height, accumulator, count, hist.root())
			after := hashPriceBeaconState(t, retainedHeight, retainedAccumulator, height-retainedHeight, retainedHist.root())
			ptx := beaconSpend(t, []beaconCoin{{beacon["challenge"], before, nil, hashPriceControlID}, {hpcs["continue"], disputed.state, nil, hashPriceCoinID}, {bhcs["continue"], source.state, nil, blockCoinID}},
				[]*wire.TxOut{beaconOut(beacon["challenge"]), beaconOut(hpcs["continue"]), beaconOut(bhcs["continue"])}, [][]byte{after, disputed.state, source.state},
				asset.Packet{beaconGroup(hashPriceControlID, []uint16{0}, []uint16{0}), beaconGroup(hashPriceCoinID, []uint16{1}, []uint16{1}), beaconGroup(blockCoinID, []uint16{2}, []uint16{2})})
			linkController(ptx)
			link(ptx, 1, disputed)
			link(ptx, 2, source)
			beaconResult(t, ptx, true)
			controller, count, height, accumulator, hist = ptx, height-retainedHeight, retainedHeight, retainedAccumulator, retainedHist.clone()
			disputed.tx, disputed.vout = ptx, 1
			source.tx, source.vout = ptx, 2
		}
		burn := func(discarded *liveCoin) {
			before := hashPriceBeaconState(t, height, accumulator, count, hist.root())
			after := hashPriceBeaconState(t, height, accumulator, count-1, hist.root())
			ptx := beaconSpend(t, []beaconCoin{{beacon["burn"], before, nil, hashPriceControlID}, {hpcs["burn"], discarded.state, nil, hashPriceCoinID}},
				[]*wire.TxOut{beaconOut(beacon["burn"])}, [][]byte{after},
				asset.Packet{beaconGroup(hashPriceControlID, []uint16{0}, []uint16{0}), beaconGroup(hashPriceCoinID, []uint16{1}, nil)})
			linkController(ptx)
			link(ptx, 1, discarded)
			withExtraInput(t, ptx, fundingTx([]byte{txscript.OP_TRUE}, 10000))
			beaconResult(t, ptx, true)
			controller, count = ptx, count-1
		}

		// Authenticated source replacements isolate HPC recovery; BHC recovery
		// is exercised separately with real header proofs.
		var oldSources, replacements [2]*liveCoin
		var oldQ, replacementQ [2]*big.Int
		for i := range 2 {
			header := beaconHex(t, f.Headers[0])
			reward := fixtureReward(t, f)
			target := blockchain.CompactToBig(binary.LittleEndian.Uint32(header[72:76]))
			replacementQ[i] = new(big.Int).Mul(reward, target)
			oldQ[i] = new(big.Int)
			state := blockObservation(t, f.Height+int64(i), header, header[72:76], make([]byte, 4), fixtureWork(t, f))
			replacements[i] = &liveCoin{state: state}
			old := bytes.Clone(state)
			old[87] ^= 1
			oldBits := blockchain.BigToCompact(new(big.Int).Lsh(target, 1))
			binary.LittleEndian.PutUint32(old[80:84], oldBits)
			oldQ[i].Mul(reward, blockchain.CompactToBig(oldBits))
			oldSources[i] = &liveCoin{state: old}
		}
		histAtCheckpoint := hist.clone()
		first := mint(oldSources[0], oldQ[0], true)
		histAfterFirst := hist.clone()
		second := mint(oldSources[1], oldQ[1], true)
		time.Sleep(25 * time.Hour) // Virtual time: old HPCs have passed the consumer window.

		// Rewind the later mismatch first, retaining the earlier wrong contribution.
		challenge(second, replacements[1], f.Height, new(big.Int).Add(big.NewInt(50), oldQ[0]), histAfterFirst)
		mint(replacements[1], replacementQ[1], false)
		burn(second)
		mixed := mint(replacements[1], replacementQ[1], true)
		if bytes.Equal(mixed.state[168:176], second.state[168:176]) {
			t.Fatal("replacement inherited the old minting time")
		}

		// A successive rewind removes both the old contribution and its mixed descendant.
		challenge(first, replacements[0], f.Height-1, big.NewInt(50), histAtCheckpoint)
		mint(replacements[0], replacementQ[0], false)
		burn(mixed)
		mint(replacements[0], replacementQ[0], false)
		burn(first)
		mint(replacements[0], replacementQ[0], true)
		last := mint(replacements[1], replacementQ[1], true)
		want := new(big.Int).Add(big.NewInt(50), replacementQ[0])
		want.Add(want, replacementQ[1])
		if !bytes.Equal(last.state[72:136], beaconNum(t, want, 64)) {
			t.Fatal("recovered accumulator includes discarded rewards")
		}
		wantHist := newSparseHistogram()
		wantHist.add(hashpriceBucket(replacementQ[0]), 1)
		wantHist.add(hashpriceBucket(replacementQ[1]), 1)
		if !bytes.Equal(last.state[208:240], wantHist.root()) {
			t.Fatal("recovered histogram includes discarded observations")
		}
		if !bytes.Equal(last.state[168:176], beaconNum(t, big.NewInt(time.Now().Unix()), 8)) {
			t.Fatal("replacement timestamp is not fresh")
		}
	})
}

func TestHashpriceRecovery(t *testing.T) {
	coins := beaconObservations(t, 2)
	contract := compileArtifact(t, "../../examples/hashprice/block_header_beacon.ark")
	beacon := beaconInstances(t, contract, map[string][]byte{"coinGidx": scriptInt(t, 1), "blockCoinScript": coins["continue"].pkScript[2:]})
	// Follow real transaction outputs between challenge, both burn batches and mint.
	for _, f := range headerFixtures(t) {
		if f.Height <= 388381 {
			continue // Recovery starts from a post-BIP65 checkpoint.
		}
		t.Run(fmt.Sprint(f.Height), func(t *testing.T) {
			parent := beaconHex(t, f.ParentHeader)
			first := beaconHex(t, f.Headers[0])
			epoch := beaconHex(t, f.EpochStartHeader)[68:72]
			work := fixtureWork(t, f)
			anchor := blockObservation(t, f.Height-1, parent, first[72:76], epoch, work)
			// Synthetic authenticated prior state isolates the recovery transition;
			// the winning proof uses real mined headers, including retarget fixtures.
			oldHeader := bytes.Clone(first)
			oldHeader[79] ^= 1
			old := blockObservation(t, f.Height, oldHeader, first[72:76], epoch, new(big.Int).Sub(work, big.NewInt(1)))
			reset := blockBeaconState(t, f.Height-1, chainhash.DoubleHashB(parent), first[72:76], epoch, 2, work)
			var challenged *psbt.Packet
			for _, mutation := range []string{"valid", "long suffix", "tie", "less work", "same hash", "link", "pow", "difficulty", "missing header", "successor height", "successor parent", "recovering", "unissued", "anchor identity", "anchor script", "output count", "output floor", "output hash", "output bits", "output epoch", "burn disputed", "clone"} {
				t.Run(mutation, func(t *testing.T) {
					values := headerWitness(t, f)
					before := blockBeaconState(t, f.Height+1, chainhash.DoubleHashB(first), first[72:76], epoch, 0, new(big.Int))
					disputed := bytes.Clone(old)
					next := bytes.Clone(reset)
					outs := []*wire.TxOut{beaconOut(beacon["challenge"]), beaconOut(coins["continue"]), beaconOut(coins["continue"])}
					assets := asset.Packet{beaconGroup(blockControlID, []uint16{0}, []uint16{0}), beaconGroup(blockCoinID, []uint16{1, 2}, []uint16{1, 2})}
					switch mutation {
					case "long suffix":
						copy(before[0:8], beaconNum(t, big.NewInt(f.Height+10000), 8))
						copy(next[8:16], beaconNum(t, big.NewInt(10001), 8))
					case "tie", "less work":
						oldWork := new(big.Int).Set(work)
						if mutation == "less work" {
							oldWork.Add(oldWork, big.NewInt(1))
						}
						copy(disputed[96:], beaconNum(t, oldWork, 33))
					case "same hash":
						copy(disputed[8:88], first)
					case "link":
						values["headers.0"][4] ^= 1
					case "pow":
						values["headers.5"][79] ^= 1
					case "difficulty":
						values["headers.1"][72] ^= 1
					case "missing header":
						values["headers.5"] = nil
					case "successor height":
						disputed[0] ^= 1
					case "successor parent":
						disputed[12] ^= 1
					case "recovering":
						before[8] = 1
					case "unissued":
						copy(before[0:8], anchor[0:8])
					case "anchor identity":
						assets[1].Inputs = assets[1].Inputs[1:]
					case "anchor script":
						outs[1].PkScript[2] ^= 1
					case "output count":
						next[8]++
					case "output floor":
						next[56] ^= 1
					case "output hash":
						next[16] ^= 1
					case "output bits":
						next[48] ^= 1
					case "output epoch":
						next[52] ^= 1
					case "burn disputed":
						assets[1].Outputs = assets[1].Outputs[:1]
					case "clone":
						assets[1].Outputs[1].Amount++
					}
					witness := covenantWitness(t, contract, covenantGroup(t, contract, "challenge"), values)
					ptx := beaconSpend(t, []beaconCoin{{beacon["challenge"], before, witness, blockControlID}, {coins["continue"], anchor, nil, blockCoinID}, {coins["continue"], disputed, nil, blockCoinID}}, outs, [][]byte{next, anchor, disputed}, assets)
					beaconResult(t, ptx, mutation == "valid" || mutation == "long suffix")
					if mutation == "valid" {
						challenged = ptx
					}
				})
			}
			if challenged == nil {
				t.Fatal("challenge failed")
			}
			// Burn in reverse height order. A fee input must not affect the counter.
			previous := challenged
			before := reset
			for remaining := int64(1); remaining >= 0; remaining-- {
				discarded := bytes.Clone(old)
				copy(discarded[0:8], beaconNum(t, big.NewInt(f.Height+remaining), 8))
				after := bytes.Clone(before)
				copy(after[8:16], beaconNum(t, big.NewInt(remaining), 8))
				ptx := beaconSpend(t, []beaconCoin{{beacon["burn"], before, nil, blockControlID}, {coins["burn"], discarded, nil, blockCoinID}}, []*wire.TxOut{beaconOut(beacon["burn"])}, [][]byte{after}, asset.Packet{beaconGroup(blockControlID, []uint16{0}, []uint16{0}), beaconGroup(blockCoinID, []uint16{1}, nil)})
				linkBeaconInput(t, ptx, 0, previous, 0)
				if remaining == 0 {
					linkBeaconInput(t, ptx, 1, challenged, 2)
				}
				withExtraInput(t, ptx, fundingTx([]byte{txscript.OP_TRUE}, 10000))
				beaconResult(t, ptx, true)
				previous, before = ptx, after
			}
			// The original height can now be issued again, meeting and clearing the floor.
			values := headerWitness(t, f)
			if f.Height%2016 == 0 {
				epoch = first[68:72]
			}
			bits := beaconHex(t, f.Headers[1])[72:76]
			after := blockBeaconState(t, f.Height, chainhash.DoubleHashB(first), bits, epoch, 0, new(big.Int))
			observation := blockObservation(t, f.Height, first, bits, epoch, work)
			witness := covenantWitness(t, contract, covenantGroup(t, contract, "mint"), values)
			ptx := beaconSpend(t, []beaconCoin{{beacon["mint"], before, witness, blockControlID}}, []*wire.TxOut{beaconOut(beacon["mint"]), beaconOut(coins["continue"])}, [][]byte{after, observation}, asset.Packet{beaconGroup(blockControlID, []uint16{0}, []uint16{0}), beaconGroup(blockCoinID, nil, []uint16{1})})
			linkBeaconInput(t, ptx, 0, previous, 0)
			beaconResult(t, ptx, true)
		})
	}
}

func TestHashpriceRecoveryBurns(t *testing.T) {
	coins := beaconObservations(t, 2)
	contract := compileArtifact(t, "../../examples/hashprice/block_header_beacon.ark")
	beacon := beaconInstances(t, contract, map[string][]byte{"coinGidx": scriptInt(t, 1), "blockCoinScript": coins["burn"].pkScript[2:]})["burn"]
	for _, mutation := range []string{"valid", "complete", "normal", "too many", "zero burns", "last good", "older", "control identity", "coin identity", "input amount", "duplicate allocation", "continued coin", "wrong decrement", "changed floor", "changed height", "changed hash", "changed bits", "changed epoch"} {
		t.Run(mutation, func(t *testing.T) {
			before := blockBeaconState(t, 3000, make([]byte, 32), make([]byte, 4), make([]byte, 4), 3, big.NewInt(42))
			after := bytes.Clone(before)
			after[8] = 1
			first := blockObservation(t, 3003, make([]byte, 80), make([]byte, 4), make([]byte, 4), big.NewInt(1))
			second := bytes.Clone(first)
			copy(second[0:8], beaconNum(t, big.NewInt(3001), 8))
			inputs := []beaconCoin{{beacon, before, nil, blockControlID}, {coins["burn"], first, nil, blockCoinID}, {coins["burn"], second, nil, blockCoinID}}
			assets := asset.Packet{beaconGroup(blockControlID, []uint16{0}, []uint16{0}), beaconGroup(blockCoinID, []uint16{1, 2}, nil)}
			switch mutation {
			case "complete":
				before[8], after[8] = 2, 0
			case "normal":
				before[8] = 0
			case "too many":
				before[8], after[8] = 1, 0
			case "zero burns":
				inputs, assets = inputs[:1], assets[:1]
				after[8] = before[8]
			case "last good":
				copy(second[0:8], before[0:8])
			case "older":
				copy(second[0:8], beaconNum(t, big.NewInt(2999), 8))
			case "control identity":
				assets[0].AssetId = &hashPriceControlID
				inputs[0].id = hashPriceControlID
			case "coin identity":
				assets[1].AssetId = &hashPriceCoinID
				inputs[1].id, inputs[2].id = hashPriceCoinID, hashPriceCoinID
			case "input amount":
				assets[1].Inputs[0].Amount = 2
				before[8], after[8] = 4, 1
			case "duplicate allocation":
				assets[1].Inputs = append(assets[1].Inputs, assets[1].Inputs[0])
				before[8], after[8] = 4, 1
			case "continued coin":
				inputs[1].instance = coins["continue"]
			case "wrong decrement":
				after[8] = 0
			case "changed floor":
				after[56]++
			case "changed height":
				after[0]++
			case "changed hash":
				after[16]++
			case "changed bits":
				after[48]++
			case "changed epoch":
				after[52]++
			}
			ptx := beaconSpend(t, inputs, []*wire.TxOut{beaconOut(beacon)}, [][]byte{after}, assets)
			withExtraInput(t, ptx, fundingTx([]byte{txscript.OP_TRUE}, 10000))
			beaconResult(t, ptx, mutation == "valid" || mutation == "complete")
		})
	}
}

func TestHashpriceCoinPreservation(t *testing.T) {
	for _, kind := range []byte{2, 4} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			id := hashPriceCoinID
			state := hashPriceObservation(t, 2017, big.NewInt(1), big.NewInt(2), make([]byte, 32), pastTimeout, nil, nil)
			if kind == 2 {
				id = blockCoinID
				state = beaconState(t, 2017, make([]byte, 121))
			}
			coin := beaconObservation(t, kind)
			for _, mutation := range []string{"continue", "state", "payload", "burn", "unauthorized clone"} {
				t.Run(mutation, func(t *testing.T) {
					outs := []*wire.TxOut{beaconOut(coin)}
					states := [][]byte{bytes.Clone(state)}
					assets := asset.Packet{beaconGroup(id, []uint16{0}, []uint16{0})}
					switch mutation {
					case "state":
						states[0][0]++
					case "payload":
						states[0][len(state)-1] ^= 1
					case "burn":
						assets[0].Outputs = nil
					case "unauthorized clone":
						outs = append(outs, beaconOut(coin))
						states = append(states, bytes.Clone(state))
						assets[0].Outputs = append(assets[0].Outputs, asset.AssetOutput{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 1})
					}
					ptx := beaconSpend(t, []beaconCoin{{coin, state, nil, id}}, outs, states, assets)
					beaconResult(t, ptx, mutation == "continue")
				})
			}
		})
	}
}

func TestHashpriceCoinContinuations(t *testing.T) {
	coin := beaconObservation(t, 4)
	first := hashPriceObservation(t, 2017, big.NewInt(1), big.NewInt(2), make([]byte, 32), pastTimeout, nil, nil)
	second := hashPriceObservation(t, 2027, big.NewInt(3), big.NewInt(4), make([]byte, 32), pastTimeout+100, nil, nil)
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

func TestHashpriceMedianSettlement(t *testing.T) {
	source := `pragma arkade ^0.1.0;

struct HistogramSibling { int count; bytes32 hash; }

contract HashPriceMedianSettlement(
  bytes32 beaconTxid,
  int hpcGidx,
  bytes32 hpcScript,
  int checkpointHeight,
  int startHeight,
  int endHeight,
  int strikeBucket,
  bytes32 longScript,
  bytes32 shortScript
) {
  const int SETTLEMENT_DELAY = 86400;
  const int BUCKETS = 1048576;

  @allow(unsigned-spend-path, "anyone may settle using authenticated endpoint HPCs")
  function settle(
    int bucket,
    int countL,
    HistogramSibling[20] sibsL,
    int countR,
    HistogramSibling[20] sibsR
  ) {
    require(this.activeInputIndex == 0, "settlement input 0");
    require(endHeight >= startHeight && startHeight > checkpointHeight, "valid interval");
    require(bucket >= 0 && bucket < BUCKETS, "bucket range");

    bytes stateL = readHpc(1, startHeight - 1);
    bytes stateR = readHpc(2, endHeight);
    int mintedAtR = bin2num(substr(stateR, 168, 8));
    require(mintedAtR >= 0 && checkTime(mintedAtR + SETTLEMENT_DELAY), "settlement age");

    bytes rootL = substr(stateL, 208, 32);
    bytes rootR = substr(stateR, 208, 32);
    require(countL >= 0 && countR >= 0, "leaf counts");
    bytes32 hashL = sha256(0x00 + num2bin(countL, 8));
    bytes32 hashR = sha256(0x00 + num2bin(countR, 8));
    int totalL = countL;
    int totalR = countR;
    int belowL = 0;
    int belowR = 0;
    int path = bucket;
    for (i, sibL) in sibsL {
      let sibR = sibsR[i];
      require(sibL.count >= 0 && sibR.count >= 0, "sibling counts");
      bytes eL = num2bin(totalL, 8) + hashL;
      bytes sL = num2bin(sibL.count, 8) + sibL.hash;
      bytes eR = num2bin(totalR, 8) + hashR;
      bytes sR = num2bin(sibR.count, 8) + sibR.hash;
      int isRight = path % 2;
      path = path >> 1;
      if (isRight == 0) {
        hashL = sha256(0x01 + eL + sL);
        hashR = sha256(0x01 + eR + sR);
      } else {
        hashL = sha256(0x01 + sL + eL);
        hashR = sha256(0x01 + sR + eR);
        belowL = belowL + sibL.count;
        belowR = belowR + sibR.count;
      }
      totalL = totalL + sibL.count;
      totalR = totalR + sibR.count;
    }
    require(hashL == rootL && hashR == rootR, "histogram roots");
    require(totalL == (startHeight - 1) - checkpointHeight, "totalL");
    require(totalR == endHeight - checkpointHeight, "totalR");

    int n = endHeight - startHeight + 1;
    int k = (n + 1) / 2;
    int below = belowR - belowL;
    int inside = countR - countL;
    require(below >= 0 && below < k && k <= below + inside && below + inside <= n, "median rank");

    bytes32 winner = shortScript;
    if (bucket >= strikeBucket) {
      winner = longScript;
    }
    require(tx.outputs[0].script.program == winner, "winner script");
    require(tx.outputs[0].value == tx.inputs[0].value, "payout value");
  }

  private function readHpc(int vin, int expectedHeight) bytes {
    require(tx.inputs[vin].script.program == hpcScript, "hpc script");
    require(tx.inputs[vin].assets.length == 1, "one hpc asset");
    let alloc = tx.inputs[vin].assets[0];
    require(alloc.amount == 1 && alloc.assetId.txid == beaconTxid && alloc.assetId.gidx == hpcGidx, "hpc identity");
    let prev = tx.inputs[vin].outpoint;
    require(prev.vout <= 223, "vout range");
    bytes state = tx.inputs[vin].packet(32 + prev.vout);
    require(size(state) == 240, "hpc size");
    require(bin2num(substr(state, 0, 8)) == expectedHeight, "hpc height");
    return state;
  }
}
`
	path := filepath.Join(t.TempDir(), "hashprice_median_settlement.ark")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, path)
	hpc := beaconObservation(t, 4)
	longScript := bytes.Repeat([]byte{0xbb}, 32)
	shortScript := bytes.Repeat([]byte{0xcc}, 32)
	longPk := append([]byte{txscript.OP_1, 32}, longScript...)
	shortPk := append([]byte{txscript.OP_1, 32}, shortScript...)

	const (
		checkpointH = int64(96768)
		startH      = int64(100000)
		endH        = int64(110000) // N = 10,001 observations, median rank k = 5,001
		strikeB     = uint32(4600)
		medianB     = uint32(4665) // 46,650..46,659 sats / (PH/s * day)
	)
	histL := newSparseHistogram()
	histL.add(4000, 1400)
	histL.add(medianB, 25)
	histL.add(5200, 1806) // totalL = 3,231 = 99,999 - 96,768

	histR := histL.clone()
	histR.add(4400, 4950)    // below = 4,950 (< 5,001)
	histR.add(medianB, 105)  // inside = 105 (4,950 + 105 = 5,055 >= 5,001)
	histR.add(5500, 4946)    // above = 4,946; totalR = 13,232 = 110,000 - 96,768

	runSettle := func(name string, endHeight int64, strike uint32, payoutPk []byte, hL, hR *sparseHistogram, claimed int64, ageOffset int64, mutate func(map[string][]byte), wantValid bool) {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				mintedAtR := time.Now().Unix() - ageOffset
				sL := hashPriceObservation(t, startH-1, big.NewInt(1), big.NewInt(100), make([]byte, 32), mintedAtR-600000, nil, hL.root())
				sR := hashPriceObservation(t, endHeight, big.NewInt(2), big.NewInt(500), make([]byte, 32), mintedAtR, nil, hR.root())

				settlement := beaconInstances(t, contract, map[string][]byte{
					"beaconTxid":       hashPriceCoinID.Txid[:],
					"hpcGidx":          scriptInt(t, int64(hashPriceCoinID.Index)),
					"hpcScript":        hpc.pkScript[2:],
					"checkpointHeight": scriptInt(t, checkpointH),
					"startHeight":      scriptInt(t, startH),
					"endHeight":        scriptInt(t, endHeight),
					"strikeBucket":     scriptInt(t, int64(strike)),
					"longScript":       longScript,
					"shortScript":      shortScript,
				})["settle"]

				openBucket := uint32(claimed & hashpriceMaxBucket)
				values := map[string][]byte{"bucket": scriptInt(t, claimed)}
				hL.writeWitness(t, values, "countL", "sibsL", openBucket)
				hR.writeWitness(t, values, "countR", "sibsR", openBucket)
				if mutate != nil {
					mutate(values)
				}
				witness := covenantWitness(t, contract, covenantGroup(t, contract, "settle"), values)
				if name == "valid 100k-110k" {
					t.Logf("HashPriceMedianSettlement.settle (D=20): script=%d bytes, witness=%d bytes serialized / %d items", len(settlement.covenant), witness.SerializeSize(), len(witness))
				}

				prevEscrow := fundingTx(settlement.pkScript, 100000)
				makePrevHPC := func(st []byte) *wire.MsgTx {
					prev := fundingTx([]byte{txscript.OP_TRUE}, 10000)
					prev.AddTxOut(&wire.TxOut{Value: 10000, PkScript: hpc.pkScript})
					out, err := (extension.Extension{
						asset.Packet{beaconGroup(hashPriceCoinID, nil, []uint16{1})},
						extension.UnknownPacket{PacketType: 33, Data: st},
					}).TxOut()
					if err != nil {
						t.Fatal(err)
					}
					prev.AddTxOut(out)
					return prev
				}
				prevL := makePrevHPC(sL)
				prevR := makePrevHPC(sR)

				tx := wire.NewMsgTx(2)
				tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prevEscrow.TxHash(), Index: 0}})
				tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prevL.TxHash(), Index: 1}})
				tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prevR.TxHash(), Index: 1}})
				tx.AddTxOut(&wire.TxOut{Value: 100000, PkScript: bytes.Clone(payoutPk)})
				tx.AddTxOut(beaconOut(hpc))
				tx.AddTxOut(beaconOut(hpc))

				em, err := arkade.NewPacket(
					arkade.EmulatorEntry{Vin: 0, Script: settlement.covenant, Witness: witness},
					arkade.EmulatorEntry{Vin: 1, Script: hpc.covenant},
					arkade.EmulatorEntry{Vin: 2, Script: hpc.covenant},
				)
				if err != nil {
					t.Fatal(err)
				}
				extOut, err := (extension.Extension{
					asset.Packet{beaconGroup(hashPriceCoinID, []uint16{1, 2}, []uint16{1, 2})},
					em,
					extension.UnknownPacket{PacketType: 33, Data: sL},
					extension.UnknownPacket{PacketType: 34, Data: sR},
				}).TxOut()
				if err != nil {
					t.Fatal(err)
				}
				tx.AddTxOut(extOut)
				tx.AddTxOut(txutils.AnchorOutput())

				ptx, err := psbt.NewFromUnsignedTx(tx)
				if err != nil {
					t.Fatal(err)
				}
				ptx.Inputs[0].WitnessUtxo = prevEscrow.TxOut[0]
				ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{settlement.tapLeafScript}
				if err := txutils.SetArkPsbtField(ptx, 0, arkade.PrevArkTxField, *prevEscrow); err != nil {
					t.Fatal(err)
				}
				for idx, prev := range []*wire.MsgTx{prevL, prevR} {
					vin := idx + 1
					ptx.Inputs[vin].WitnessUtxo = prev.TxOut[1]
					ptx.Inputs[vin].TaprootLeafScript = []*psbt.TaprootTapLeafScript{hpc.tapLeafScript}
					if err := txutils.SetArkPsbtField(ptx, vin, arkade.PrevArkTxField, *prev); err != nil {
						t.Fatal(err)
					}
				}
				beaconResult(t, ptx, wantValid)
			})
		})
	}

	// Odd N = 10,001 (100,000..110,000), median bucket 4665 >= strike 4600 => long wins.
	runSettle("valid 100k-110k", endH, strikeB, longPk, histL, histR, int64(medianB), 90000, nil, true)
	// Same interval with higher strike 4700 => short wins.
	runSettle("valid short win", endH, 4700, shortPk, histL, histR, int64(medianB), 90000, nil, true)
	// Even N = 10,000 (100,000..109,999), lower median rank k = 5,000 lands on bucket 4400 when 4400 holds 5,000 items.
	histEvenR := histL.clone()
	histEvenR.add(4400, 5000)
	histEvenR.add(5500, 5000)
	runSettle("valid even N lower median", endH-1, strikeB, shortPk, histL, histEvenR, 4400, 90000, nil, true)

	// Negative cases.
	runSettle("wrong lower bucket", endH, strikeB, longPk, histL, histR, 4400, 90000, nil, false)
	runSettle("wrong higher bucket", endH, strikeB, longPk, histL, histR, 5500, 90000, nil, false)
	runSettle("empty bucket", endH, strikeB, longPk, histL, histR, int64(medianB+1), 90000, nil, false)
	runSettle("bucket wraparound", endH, strikeB, longPk, histL, histR, int64(medianB)+(1<<hashpriceHistogramDepth), 90000, nil, false)
	runSettle("negative bucket", endH, strikeB, longPk, histL, histR, -1, 90000, nil, false)
	runSettle("wrong winner", endH, strikeB, shortPk, histL, histR, int64(medianB), 90000, nil, false)
	runSettle("tampered countR", endH, strikeB, longPk, histL, histR, int64(medianB), 90000, func(v map[string][]byte) {
		v["countR"] = scriptInt(t, 131)
	}, false)
	runSettle("tampered sibling count", endH, strikeB, longPk, histL, histR, int64(medianB), 90000, func(v map[string][]byte) {
		v["sibsR.10.count"] = scriptInt(t, 9999)
	}, false)
	runSettle("tampered sibling hash", endH, strikeB, longPk, histL, histR, int64(medianB), 90000, func(v map[string][]byte) {
		v["sibsR.0.hash"][0] ^= 1
	}, false)
	runSettle("immature settlement age", endH, strikeB, longPk, histL, histR, int64(medianB), 86399, nil, false)
	wrongTotalHistR := histR.clone()
	wrongTotalHistR.add(5500, 1)
	runSettle("wrong totalR", endH, strikeB, longPk, histL, wrongTotalHistR, int64(medianB), 90000, nil, false)
}

func TestHashpriceMath(t *testing.T) {
	// Exercise the production target/work helpers and retarget blocks directly.
	// Keep the test-only public entry points out of the deployed contract.
	raw, err := os.ReadFile("../../examples/hashprice/block_header_beacon.ark")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	fragment := func(start, end string) string {
		t.Helper()
		i := strings.Index(source, start)
		if i < 0 {
			t.Fatalf("missing production block: %s", start)
		}
		j := strings.Index(source[i:], end)
		if j < 0 {
			t.Fatalf("missing production block end: %s", end)
		}
		return source[i : i+j+len(end)]
	}
	compactEnd := `"retarget encoding"
      );`
	compact := fragment("int exponent = uint(substr(nextBits, 3, 1));", compactEnd)
	retarget := fragment("int elapsed = uint(substr(epochEnd, 68, 4)) - epochStart;", compactEnd)
	retarget = strings.Replace(retarget, "uint(substr(epochEnd, 68, 4)) - epochStart", "lastTime - firstTime", 1)

	source = source[:strings.LastIndex(source, "}")] + `
  function testWork(int target, int expected) { require(blockWork(target) == expected); }
  function testTarget(bytes bits, int expected) { require(decodeTarget(bits) == expected); }
  function testCompact(int target, bytes bits) {
    int rawTarget = target; bytes nextBits = bits;
    int nextTarget = decodeTarget(nextBits);
` + compact + `
  }
  function testRetarget(int oldTarget, int firstTime, int lastTime, bytes bits) {
    bytes nextBits = bits;
    int nextTarget = decodeTarget(nextBits);
` + retarget + `
  }

}`
	path := filepath.Join(t.TempDir(), "hashprice_math.ark")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, path)
	instances := beaconInstances(t, contract, map[string][]byte{"coinGidx": scriptInt(t, 1), "blockCoinScript": make([]byte, 32)})
	run := func(name, function string, values map[string][]byte, valid bool) {
		t.Run(name, func(t *testing.T) {
			function = "test" + strings.ToUpper(function[:1]) + function[1:]
			instance := instances[function]
			witness := covenantWitness(t, contract, covenantGroup(t, contract, function), values)
			ptx := spendingPSBTWithWitness(t, fundingTx(instance.pkScript, 10000), instance, 10000, instance.pkScript, witness)
			beaconResult(t, ptx, valid)
		})
	}
	old := new(big.Int).Lsh(big.NewInt(1), 200)
	for _, target := range []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(255), old, blockchain.CompactToBig(0x1d00ffff)} {
		want := new(big.Int).Quo(new(big.Int).Lsh(big.NewInt(1), 256), new(big.Int).Add(target, big.NewInt(1)))
		run("work "+target.String(), "work", map[string][]byte{"target": scriptPositiveBigInt(t, target.Bytes()), "expected": scriptPositiveBigInt(t, want.Bytes())}, true)
		want.Add(want, big.NewInt(1))
		run("wrong work "+target.String(), "work", map[string][]byte{"target": scriptPositiveBigInt(t, target.Bytes()), "expected": scriptPositiveBigInt(t, want.Bytes())}, false)
	}
	run("zero work target", "work", map[string][]byte{"target": nil, "expected": nil}, false)
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
}
