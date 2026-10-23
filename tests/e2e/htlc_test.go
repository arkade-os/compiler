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
	exitBytes, err := arkade.BigNumFromUint64(144).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	// Stand-ins for the SingleSig scripts the SDK derives; the covenant compares witness programs.
	receiverScript := p2trScript(t, []byte{0x51})
	senderScript := p2trScript(t, []byte{0x52})
	values := map[string][]byte{
		"CONTRACT:SingleSig(<receiver>)": receiverScript[2:],
		"CONTRACT:SingleSig(<sender>)":   senderScript[2:],
		"preimageHash":                   btcutil.Hash160(preimage),
		"refundTime":                     refundTimeBytes,
		"sender":                         fixedPublicKey(4).SerializeCompressed(),
		"receiver":                       fixedPublicKey(5).SerializeCompressed(),
		"SERVER_EXIT_DELAY":              exitBytes,
	}
	claim := instantiateGroup(
		t, contract, "claim", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)
	refund := instantiateGroup(
		t, contract, "refund", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)

	t.Run("covenant", func(t *testing.T) {
		for name, test := range map[string]struct {
			group         instantiatedGroup
			payout, other []byte
		}{
			"claim":  {claim, receiverScript, senderScript},
			"refund": {refund, senderScript, receiverScript},
		} {
			t.Run(name, func(t *testing.T) {
				group := test.group
				prevTx := fundingTx(group.pkScript, 10_000)

				valid := spendingPSBT(t, prevTx, group, 10_000, test.payout)
				requireVMResult(t, valid, emulatorKey.PubKey(), "")

				underfunded := spendingPSBT(t, prevTx, group, 9_999, test.payout)
				requireVMResult(t, underfunded, emulatorKey.PubKey(), "false stack entry")

				misdirected := spendingPSBT(t, prevTx, group, 10_000, test.other)
				requireVMResult(t, misdirected, emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
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
