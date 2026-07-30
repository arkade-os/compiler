package e2e

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
)

func TestCompiledHTLC(t *testing.T) {
	contract := compileArtifact(t, filepath.Join("..", "..", "examples", "htlc", "htlc.ark"))
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	preimage := bytes.Repeat([]byte{0x42}, 32)
	const refundTime = uint32(500_000_001)
	refundTimeBytes, err := arkade.BigNumFromUint64(uint64(refundTime)).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string][]byte{
		"preimageHash": btcutil.Hash160(preimage),
		"refundTime":   refundTimeBytes,
	}
	claim := instantiateGroup(
		t, contract, "claim", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)
	refund := instantiateGroup(
		t, contract, "refund", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)

	t.Run("covenant", func(t *testing.T) {
		for name, group := range map[string]instantiatedGroup{
			"claim":  claim,
			"refund": refund,
		} {
			t.Run(name, func(t *testing.T) {
				prevTx := fundingTx(group.pkScript, 10_000)

				valid := spendingPSBT(t, prevTx, group, 10_000, group.pkScript)
				requireVMResult(t, valid, emulatorKey.PubKey(), "")

				underfunded := spendingPSBT(t, prevTx, group, 9_999, group.pkScript)
				requireVMResult(t, underfunded, emulatorKey.PubKey(), "OP_VERIFY failed")
			})
		}
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
			t, prevTx, claim, 0, wire.MaxTxInSequenceNum-1, keys, wire.TxWitness{preimage}, "",
		)
		requireTapscriptResult(
			t,
			prevTx,
			claim,
			0,
			wire.MaxTxInSequenceNum-1,
			keys,
			wire.TxWitness{bytes.Repeat([]byte{0x43}, 32)},
			"OP_VERIFY failed",
		)
		requireTapscriptResult(
			t,
			prevTx,
			claim,
			0,
			wire.MaxTxInSequenceNum-1,
			[]*btcec.PrivateKey{serverKey, fixedPrivateKey(4)},
			wire.TxWitness{preimage},
			"signature not empty on failed checksig",
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

		requireTapscriptResult(
			t, prevTx, refund, refundTime, wire.MaxTxInSequenceNum-1, keys, nil, "",
		)
		requireTapscriptResult(
			t, prevTx, refund, refundTime-1, wire.MaxTxInSequenceNum-1, keys, nil,
			"locktime requirement not satisfied",
		)
	})
}
