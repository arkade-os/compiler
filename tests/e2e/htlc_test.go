package e2e

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
)

func TestCompiledHTLC(t *testing.T) {
	contract := compileArtifact(t, filepath.Join("..", "..", "examples", "htlc", "htlc.ark"))
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	preimage := bytes.Repeat([]byte{0x42}, 32)
	preimageHash := []byte{
		0x87, 0x39, 0xf4, 0x0e, 0xc4, 0xdb, 0xf5, 0x69, 0xdc, 0xb3,
		0x81, 0x34, 0xc6, 0xe7, 0x31, 0x09, 0x08, 0x56, 0x69, 0x81,
	}
	const refundTime = uint32(500_000_000)
	refundTimeBytes, err := arkade.BigNumFromUint64(uint64(refundTime)).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string][]byte{
		"preimageHash": preimageHash,
		"refundTime":   refundTimeBytes,
	}
	claim := instantiateGroup(
		t, contract, "claim", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)
	refund := instantiateGroup(
		t, contract, "refund", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)

	t.Run("covenant", func(t *testing.T) {
		prevTx := fundingTx(claim.pkScript, 10_000)

		valid := spendingPSBT(t, prevTx, claim, 10_000, claim.pkScript)
		requireVMResult(t, valid, emulatorKey.PubKey(), true)

		underfunded := spendingPSBT(t, prevTx, claim, 9_999, claim.pkScript)
		requireVMResult(t, underfunded, emulatorKey.PubKey(), false)
	})

	t.Run("claim tapscript", func(t *testing.T) {
		prevTx := fundingTx(claim.pkScript, 10_000)
		keys := []*btcec.PrivateKey{
			serverKey,
			arkade.ComputeArkadeScriptPrivateKey(
				emulatorKey,
				arkade.ArkadeScriptHash(claim.covenant),
			),
		}

		requireTapscriptResult(
			t, prevTx, claim, 0, keys, wire.TxWitness{preimage}, true,
		)
		requireTapscriptResult(
			t,
			prevTx,
			claim,
			0,
			keys,
			wire.TxWitness{bytes.Repeat([]byte{0x43}, 32)},
			false,
		)
	})

	t.Run("refund tapscript", func(t *testing.T) {
		prevTx := fundingTx(refund.pkScript, 10_000)
		keys := []*btcec.PrivateKey{
			serverKey,
			arkade.ComputeArkadeScriptPrivateKey(
				emulatorKey,
				arkade.ArkadeScriptHash(refund.covenant),
			),
		}

		requireTapscriptResult(t, prevTx, refund, refundTime, keys, nil, true)
		requireTapscriptResult(t, prevTx, refund, refundTime-1, keys, nil, false)
	})
}
