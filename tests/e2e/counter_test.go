package e2e

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const counterPacketType = 2

func TestCompiledCounterRecursion(t *testing.T) {
	contract := compileArtifact(t, "contracts/counter.ark")
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	counter := instantiateGroup(
		t, contract, "increment", nil, serverKey.PubKey(), emulatorKey.PubKey(),
	)

	t.Run("covenant recursion", func(t *testing.T) {
		deployment := fundingTx(counter.pkScript, 20_000)
		addCounterPacket(t, deployment)

		first := spendingPSBT(t, deployment, counter, 20_000, counter.pkScript, counterPacket(t, 2))
		requireVMResult(t, first, emulatorKey.PubKey(), "")

		skippedState := spendingPSBT(t, deployment, counter, 20_000, counter.pkScript, counterPacket(t, 3))
		requireVMResult(t, skippedState, emulatorKey.PubKey(), "OP_VERIFY failed")

		second := spendingPSBT(
			t, first.UnsignedTx, counter, 20_000, counter.pkScript, counterPacket(t, 3),
		)
		requireVMResult(t, second, emulatorKey.PubKey(), "")

		wrongScript := spendingPSBT(
			t, first.UnsignedTx, counter, 20_000, p2trScript(t, []byte{txscript.OP_TRUE}), counterPacket(t, 3),
		)
		requireVMResult(t, wrongScript, emulatorKey.PubKey(), "OP_VERIFY failed")

		underfunded := spendingPSBT(
			t, first.UnsignedTx, counter, 19_999, counter.pkScript, counterPacket(t, 3),
		)
		requireVMResult(t, underfunded, emulatorKey.PubKey(), "OP_VERIFY failed")
	})

	t.Run("tapscript", func(t *testing.T) {
		prevTx := fundingTx(counter.pkScript, 20_000)
		keys := []*btcec.PrivateKey{
			serverKey,
			arkade.ComputeArkadeScriptPrivateKey(
				emulatorKey,
				arkade.ArkadeScriptHash(counter.covenant),
			),
		}

		requireTapscriptResult(
			t, prevTx, counter, 0, wire.MaxTxInSequenceNum-1, keys, nil, "",
		)
		requireTapscriptResult(
			t, prevTx, counter, 0, wire.MaxTxInSequenceNum-1, keys[:1], nil,
			"index 0 is invalid for stack size 0",
		)
		requireTapscriptResult(
			t,
			prevTx,
			counter,
			0,
			wire.MaxTxInSequenceNum-1,
			[]*btcec.PrivateKey{serverKey, fixedPrivateKey(4)},
			nil,
			"signature not empty on failed checksig",
		)
	})
}

func addCounterPacket(t *testing.T, tx *wire.MsgTx) {
	t.Helper()
	ext := extension.Extension{counterPacket(t, 1)}
	output, err := ext.TxOut()
	if err != nil {
		t.Fatalf("counter packet: %v", err)
	}
	tx.AddTxOut(output)
}

func counterPacket(t *testing.T, value uint64) extension.Packet {
	t.Helper()
	payload, err := arkade.BigNumFromUint64(value).Bytes()
	if err != nil {
		t.Fatalf("counter payload: %v", err)
	}
	return extension.UnknownPacket{PacketType: counterPacketType, Data: payload}
}
