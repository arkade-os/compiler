package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const counterPacketType = 2

type artifact struct {
	Name      string          `json:"contractName"`
	Functions []functionGroup `json:"functions"`
	Warnings  []string        `json:"warnings"`
}

type functionGroup struct {
	Name   string         `json:"name"`
	Arkade *assembly      `json:"arkade"`
	Leaves []leafArtifact `json:"leaves"`
}

type assembly struct {
	ASM []string `json:"asm"`
}

type leafArtifact struct {
	Name string   `json:"name"`
	ASM  []string `json:"asm"`
}

type instantiatedGroup struct {
	covenant      []byte
	pkScript      []byte
	tapLeafScript *psbt.TaprootTapLeafScript
}

type testPrevOutFetcher struct {
	txscript.PrevOutputFetcher
	arkTxs map[wire.OutPoint]*wire.MsgTx
}

func (f *testPrevOutFetcher) FetchPrevOutArkTx(outpoint wire.OutPoint) *wire.MsgTx {
	return f.arkTxs[outpoint]
}

func (f *testPrevOutFetcher) FetchVtxoPrevOutPkScript(outpoint wire.OutPoint) []byte {
	tx := f.arkTxs[outpoint]
	if tx == nil || int(outpoint.Index) >= len(tx.TxOut) {
		return nil
	}
	return tx.TxOut[outpoint.Index].PkScript
}

func TestCompiledHTLCCovenant(t *testing.T) {
	contract := compileArtifact(t, filepath.Join("..", "..", "examples", "htlc", "htlc.ark"))
	serverKey := fixedPublicKey(1)
	emulatorKey := fixedPublicKey(2)
	claim := instantiateGroup(t, contract, "claim", map[string][]byte{
		"preimageHash": bytes.Repeat([]byte{0x42}, 20),
	}, serverKey, emulatorKey)

	prevTx := fundingTx(claim.pkScript, 10_000)

	valid := spendingPSBT(t, prevTx, claim, 10_000, claim.pkScript)
	requireVMResult(t, valid, emulatorKey, true)

	underfunded := spendingPSBT(t, prevTx, claim, 9_999, claim.pkScript)
	requireVMResult(t, underfunded, emulatorKey, false)
}

func TestCompiledCounterRecursion(t *testing.T) {
	contract := compileArtifact(t, filepath.Join("testdata", "counter.ark"))
	serverKey := fixedPublicKey(1)
	emulatorKey := fixedPublicKey(2)
	counter := instantiateGroup(t, contract, "increment", nil, serverKey, emulatorKey)

	deployment := fundingTx(counter.pkScript, 20_000)
	addCounterPacket(t, deployment, 0)

	first := spendingPSBT(t, deployment, counter, 20_000, counter.pkScript, counterPacket(t, 1))
	requireVMResult(t, first, emulatorKey, true)

	skippedState := spendingPSBT(t, deployment, counter, 20_000, counter.pkScript, counterPacket(t, 2))
	requireVMResult(t, skippedState, emulatorKey, false)

	second := spendingPSBT(
		t, first.UnsignedTx, counter, 20_000, counter.pkScript, counterPacket(t, 2),
	)
	requireVMResult(t, second, emulatorKey, true)

	wrongScript := spendingPSBT(
		t, first.UnsignedTx, counter, 20_000, p2trScript(t, []byte{txscript.OP_TRUE}), counterPacket(t, 2),
	)
	requireVMResult(t, wrongScript, emulatorKey, false)

	underfunded := spendingPSBT(
		t, first.UnsignedTx, counter, 19_999, counter.pkScript, counterPacket(t, 2),
	)
	requireVMResult(t, underfunded, emulatorKey, false)
}

func compileArtifact(t *testing.T, source string) artifact {
	t.Helper()

	compiler := os.Getenv("ARKADEC")
	if compiler == "" {
		compiler = filepath.Join("..", "..", "target", "debug", "arkadec")
	}
	output := filepath.Join(t.TempDir(), "artifact.json")
	cmd := exec.Command(compiler, source, "-o", output)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile %s: %v\n%s", source, err, combined)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}

	var contract artifact
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatalf("decode artifact: %v", err)
	}
	if len(contract.Warnings) > 0 {
		t.Fatalf("compile %s returned warnings: %v", source, contract.Warnings)
	}
	return contract
}

func instantiateGroup(
	t *testing.T,
	contract artifact,
	name string,
	values map[string][]byte,
	serverKey, emulatorKey *btcec.PublicKey,
) instantiatedGroup {
	t.Helper()

	var group *functionGroup
	for i := range contract.Functions {
		if contract.Functions[i].Name == name {
			group = &contract.Functions[i]
			break
		}
	}
	if group == nil || group.Arkade == nil {
		t.Fatalf("%s.%s covenant not found", contract.Name, name)
	}

	var leaf *leafArtifact
	for i := range group.Leaves {
		if group.Leaves[i].Name == name {
			leaf = &group.Leaves[i]
			break
		}
	}
	if leaf == nil {
		t.Fatalf("%s.%s leaf not found", contract.Name, name)
	}

	covenant := assemble(t, group.Arkade.ASM, values)
	leafValues := make(map[string][]byte, len(values)+2)
	for key, value := range values {
		leafValues[key] = value
	}
	leafValues["SERVER_KEY"] = schnorr.SerializePubKey(serverKey)
	leafValues["EMULATOR_KEY:"+name] = schnorr.SerializePubKey(
		arkade.ComputeArkadeScriptPublicKey(emulatorKey, arkade.ArkadeScriptHash(covenant)),
	)
	leafScript := assemble(t, leaf.ASM, leafValues)
	pkScript, tapLeafScript := taprootLeaf(t, leafScript)

	return instantiatedGroup{
		covenant:      covenant,
		pkScript:      pkScript,
		tapLeafScript: tapLeafScript,
	}
}

func assemble(t *testing.T, tokens []string, values map[string][]byte) []byte {
	t.Helper()

	builder := txscript.NewScriptBuilder()
	for index, token := range tokens {
		if opcode, ok := arkade.OpcodeByName[token]; ok {
			builder.AddOp(opcode)
			continue
		}
		if strings.HasPrefix(token, "<") && strings.HasSuffix(token, ">") {
			name := token[1 : len(token)-1]
			value, ok := values[name]
			if !ok {
				t.Fatalf("ASM token %d: unresolved placeholder %s", index, token)
			}
			builder.AddData(value)
			continue
		}
		number, err := strconv.ParseInt(token, 10, 64)
		if err != nil {
			t.Fatalf("ASM token %d: unsupported token %q", index, token)
		}
		builder.AddInt64(number)
	}

	script, err := builder.Script()
	if err != nil {
		t.Fatalf("assemble %v: %v", tokens, err)
	}
	return script
}

func taprootLeaf(t *testing.T, script []byte) ([]byte, *psbt.TaprootTapLeafScript) {
	t.Helper()

	internalKey := fixedPublicKey(3)
	leaf := txscript.NewBaseTapLeaf(script)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	controlBlock := tree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	controlBlockBytes, err := controlBlock.ToBytes()
	if err != nil {
		t.Fatalf("control block: %v", err)
	}
	rootHash := tree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, rootHash[:])
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	if err != nil {
		t.Fatalf("taproot output: %v", err)
	}

	return pkScript, &psbt.TaprootTapLeafScript{
		ControlBlock: controlBlockBytes,
		Script:       script,
		LeafVersion:  txscript.BaseLeafVersion,
	}
}

func p2trScript(t *testing.T, script []byte) []byte {
	t.Helper()
	pkScript, _ := taprootLeaf(t, script)
	return pkScript
}

func fundingTx(pkScript []byte, amount int64) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	tx.AddTxOut(&wire.TxOut{Value: amount, PkScript: pkScript})
	return tx
}

func spendingPSBT(
	t *testing.T,
	prevTx *wire.MsgTx,
	group instantiatedGroup,
	amount int64,
	outputScript []byte,
	packets ...extension.Packet,
) *psbt.Packet {
	t.Helper()

	outpoint := wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: outpoint})
	tx.AddTxOut(&wire.TxOut{Value: amount, PkScript: outputScript})

	emulatorPacket, err := arkade.NewPacket(arkade.EmulatorEntry{
		Vin:    0,
		Script: group.covenant,
	})
	if err != nil {
		t.Fatalf("emulator packet: %v", err)
	}
	packets = append(packets, emulatorPacket)
	ext := extension.Extension(packets)
	extensionOutput, err := ext.TxOut()
	if err != nil {
		t.Fatalf("extension output: %v", err)
	}
	tx.AddTxOut(extensionOutput)

	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatalf("PSBT: %v", err)
	}
	ptx.Inputs[0].WitnessUtxo = prevTx.TxOut[0]
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{group.tapLeafScript}
	if err := txutils.SetArkPsbtField(ptx, 0, arkade.PrevArkTxField, *prevTx); err != nil {
		t.Fatalf("previous Ark transaction: %v", err)
	}
	return ptx
}

func requireVMResult(
	t *testing.T,
	ptx *psbt.Packet,
	emulatorKey *btcec.PublicKey,
	wantSuccess bool,
) {
	t.Helper()

	err := executeArkadeScripts(ptx, emulatorKey)
	if wantSuccess && err != nil {
		t.Fatalf("VM rejected compiled script: %v", err)
	}
	if !wantSuccess && err == nil {
		t.Fatal("VM accepted invalid transaction")
	}
}

func executeArkadeScripts(ptx *psbt.Packet, emulatorKey *btcec.PublicKey) error {
	prevouts := make(map[wire.OutPoint]*wire.TxOut, len(ptx.Inputs))
	arkTxs := make(map[wire.OutPoint]*wire.MsgTx, len(ptx.Inputs))
	for index, input := range ptx.Inputs {
		outpoint := ptx.UnsignedTx.TxIn[index].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo

		fields, err := txutils.GetArkPsbtFields(ptx, index, arkade.PrevArkTxField)
		if err != nil {
			return fmt.Errorf("read previous Ark transaction: %w", err)
		}
		if len(fields) != 1 {
			return fmt.Errorf("input %d has %d previous Ark transactions", index, len(fields))
		}
		prevTx := fields[0]
		arkTxs[outpoint] = &prevTx
	}

	fetcher := &testPrevOutFetcher{
		PrevOutputFetcher: txscript.NewMultiPrevOutFetcher(prevouts),
		arkTxs:            arkTxs,
	}
	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return fmt.Errorf("find emulator packet: %w", err)
	}
	if len(packet) == 0 {
		return fmt.Errorf("emulator packet not found")
	}

	for _, entry := range packet {
		script, err := arkade.ReadArkadeScript(ptx, emulatorKey, entry)
		if err != nil {
			return fmt.Errorf("read input %d script: %w", entry.Vin, err)
		}
		if err := script.Execute(ptx.UnsignedTx, fetcher, int(entry.Vin)); err != nil {
			return fmt.Errorf("execute input %d script: %w", entry.Vin, err)
		}
	}
	return nil
}

func addCounterPacket(t *testing.T, tx *wire.MsgTx, value uint64) {
	t.Helper()
	packet := counterPacket(t, value)
	ext := extension.Extension{packet}
	output, err := ext.TxOut()
	if err != nil {
		t.Fatalf("counter packet: %v", err)
	}
	tx.AddTxOut(output)
}

func counterPacket(t *testing.T, value uint64) extension.Packet {
	t.Helper()
	payload, err := arkade.BigNumFromUint64(value + 1).Bytes()
	if err != nil {
		t.Fatalf("counter payload: %v", err)
	}
	return extension.UnknownPacket{PacketType: counterPacketType, Data: payload}
}

func fixedPublicKey(value byte) *btcec.PublicKey {
	_, publicKey := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{value}, 32))
	return publicKey
}
