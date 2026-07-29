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
		addCounterPacket(t, deployment, 0)

		first := spendingPSBT(t, deployment, counter, 20_000, counter.pkScript, counterPacket(t, 1))
		requireVMResult(t, first, emulatorKey.PubKey(), true)

		skippedState := spendingPSBT(t, deployment, counter, 20_000, counter.pkScript, counterPacket(t, 2))
		requireVMResult(t, skippedState, emulatorKey.PubKey(), false)

		second := spendingPSBT(
			t, first.UnsignedTx, counter, 20_000, counter.pkScript, counterPacket(t, 2),
		)
		requireVMResult(t, second, emulatorKey.PubKey(), true)

		wrongScript := spendingPSBT(
			t, first.UnsignedTx, counter, 20_000, p2trScript(t, []byte{txscript.OP_TRUE}), counterPacket(t, 2),
		)
		requireVMResult(t, wrongScript, emulatorKey.PubKey(), false)

		underfunded := spendingPSBT(
			t, first.UnsignedTx, counter, 19_999, counter.pkScript, counterPacket(t, 2),
		)
		requireVMResult(t, underfunded, emulatorKey.PubKey(), false)
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

		requireTapscriptResult(t, prevTx, counter, 0, keys, nil, true)
		requireTapscriptResult(t, prevTx, counter, 0, keys[:1], nil, false)
	})
}

func addCounterPacket(t *testing.T, tx *wire.MsgTx, value uint64) {
	t.Helper()
	ext := extension.Extension{counterPacket(t, value)}
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
