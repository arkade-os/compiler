package e2e

import (
	"bytes"
	"crypto/sha256"
	"math"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// The emulator compares checkTime against its wall clock, so the timeouts
// are fixed Unix times safely in the past (2023) and future (2100).
const (
	amount        = int64(500_000)
	exitDelay     = int64(512)
	pastTimeout   = int64(1_700_000_000)
	futureTimeout = int64(4_102_444_800)
)

// p2trTo builds the scriptPubKey paying a 32-byte Taproot witness program —
// the value the covenant compares an output against.
func p2trTo(program []byte) []byte {
	return append([]byte{0x51, 0x20}, program...)
}

func TestCompiledEscrow(t *testing.T) {
	contract := compileArtifact(
		t, filepath.Join("..", "..", "examples", "escrow", "escrow.ark"),
	)

	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	partyAKey := fixedPrivateKey(4)
	partyBKey := fixedPrivateKey(5)
	oracleKey := fixedPrivateKey(6)

	// The oracle signs sha256(statement). The contract commits sha256 of that.
	statement := []byte("deed transferred, lot 42")
	oracleMsg := sha256.Sum256(statement)
	oracleMessageHash := sha256.Sum256(oracleMsg[:])

	partyAProgram := bytes.Repeat([]byte{0xa1}, 32)
	partyBProgram := bytes.Repeat([]byte{0xb2}, 32)

	values := map[string][]byte{
		"partyAPk":          schnorr.SerializePubKey(partyAKey.PubKey()),
		"partyBPk":          schnorr.SerializePubKey(partyBKey.PubKey()),
		"oraclePk":          schnorr.SerializePubKey(oracleKey.PubKey()),
		"oracleMessageHash": oracleMessageHash[:],
		"partyAScript":      partyAProgram,
		"partyBScript":      partyBProgram,
		"amount":            scriptInt(t, amount),
		"timeoutAt":         scriptInt(t, pastTimeout),
		"exit":              scriptInt(t, exitDelay),
	}
	pendingValues := make(map[string][]byte, len(values))
	for key, value := range values {
		pendingValues[key] = value
	}
	pendingValues["timeoutAt"] = scriptInt(t, futureTimeout)

	complete := instantiateGroup(
		t, contract, "complete", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)
	cancel := instantiateGroup(
		t, contract, "cancel", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)
	pending := instantiateGroup(
		t, contract, "cancel", pendingValues, serverKey.PubKey(), emulatorKey.PubKey(),
	)

	t.Run("complete", func(t *testing.T) {
		group := covenantGroup(t, contract, "complete")

		attested := func(
			funded int64, msg []byte, signer *btcec.PrivateKey, outputs []*wire.TxOut,
		) *psbt.Packet {
			witness := covenantWitness(t, contract, group, map[string][]byte{
				"oracleMsg": msg,
				"oracleSig": signBIP340(t, signer, msg),
			})
			return spendingPSBTOutputs(
				t, fundingTx(complete.pkScript, funded), complete, 0, outputs, witness,
			)
		}
		toPartyB := []*wire.TxOut{
			{Value: amount, PkScript: p2trTo(partyBProgram)},
		}

		t.Run("oracle attestation releases the committed amount", func(t *testing.T) {
			requireVMResult(
				t, attested(amount, oracleMsg[:], oracleKey, toPartyB),
				emulatorKey.PubKey(), "",
			)
		})

		t.Run("surplus returns to party A", func(t *testing.T) {
			const surplus = int64(20_000)
			requireVMResult(
				t, attested(amount+surplus, oracleMsg[:], oracleKey, []*wire.TxOut{
					{Value: amount, PkScript: p2trTo(partyBProgram)},
					{Value: surplus, PkScript: p2trTo(partyAProgram)},
				}),
				emulatorKey.PubKey(), "",
			)
		})

		t.Run("surplus cannot be folded into party B's payout", func(t *testing.T) {
			const surplus = int64(20_000)
			requireVMResult(
				t, attested(amount+surplus, oracleMsg[:], oracleKey, []*wire.TxOut{
					{Value: amount + surplus, PkScript: p2trTo(partyBProgram)},
				}),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("a sub-dust surplus does not block the release", func(t *testing.T) {
			requireVMResult(
				t, attested(amount+100, oracleMsg[:], oracleKey, toPartyB),
				emulatorKey.PubKey(), "",
			)
		})

		t.Run("a different message is not the attested event", func(t *testing.T) {
			other := sha256.Sum256([]byte("deed transferred, lot 43"))
			requireVMResult(
				t, attested(amount, other[:], oracleKey, toPartyB),
				emulatorKey.PubKey(), "OP_EQUALVERIFY failed",
			)
		})

		t.Run("the right message signed by the wrong key", func(t *testing.T) {
			requireVMResult(
				t, attested(amount, oracleMsg[:], partyBKey, toPartyB),
				emulatorKey.PubKey(), "signature verification failed",
			)
		})

		t.Run("the payout cannot be redirected", func(t *testing.T) {
			thief := bytes.Repeat([]byte{0xcc}, 32)
			requireVMResult(
				t, attested(amount, oracleMsg[:], oracleKey, []*wire.TxOut{
					{Value: amount, PkScript: p2trTo(thief)},
				}),
				emulatorKey.PubKey(), "OP_EQUALVERIFY failed",
			)
		})

		t.Run("party B cannot be shorted", func(t *testing.T) {
			requireVMResult(
				t, attested(amount, oracleMsg[:], oracleKey, []*wire.TxOut{
					{Value: amount - 1, PkScript: p2trTo(partyBProgram)},
				}),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("a second input cannot share the payout", func(t *testing.T) {
			extra := fundingTx(complete.pkScript, amount)
			requireVMResult(
				t, withExtraInput(t, attested(amount, oracleMsg[:], oracleKey, toPartyB), extra),
				emulatorKey.PubKey(), "OP_EQUALVERIFY failed",
			)
		})
	})

	t.Run("cancel", func(t *testing.T) {
		// No witness: the timeout refund carries no signature at all.
		refund := func(
			group instantiatedGroup, lockTime uint32, outputs []*wire.TxOut,
		) *psbt.Packet {
			deployment := fundingTx(group.pkScript, amount)
			return spendingPSBTOutputs(t, deployment, group, lockTime, outputs, nil)
		}
		toPartyA := []*wire.TxOut{
			{Value: amount, PkScript: p2trTo(partyAProgram)},
		}

		t.Run("anyone may refund party A after the timeout", func(t *testing.T) {
			// arkd rebuilds this spend with nLockTime 0.
			requireVMResult(t, refund(cancel, 0, toPartyA), emulatorKey.PubKey(), "")
		})

		t.Run("before the timeout", func(t *testing.T) {
			requireVMResult(
				t, refund(pending, 0, toPartyA), emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("a forged locktime does not open the refund early", func(t *testing.T) {
			requireVMResult(
				t, refund(pending, math.MaxUint32, toPartyA),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("the refund cannot be sent to party B", func(t *testing.T) {
			toPartyB := []*wire.TxOut{
				{Value: amount, PkScript: p2trTo(partyBProgram)},
			}
			requireVMResult(
				t, refund(cancel, 0, toPartyB), emulatorKey.PubKey(), "false stack entry",
			)
		})

		t.Run("the refund cannot be skimmed", func(t *testing.T) {
			skimmed := []*wire.TxOut{
				{Value: amount - 50_000, PkScript: p2trTo(partyAProgram)},
				{Value: 50_000, PkScript: p2trTo(bytes.Repeat([]byte{0xcc}, 32))},
			}
			requireVMResult(
				t, refund(cancel, 0, skimmed), emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("a second input cannot share the refund", func(t *testing.T) {
			extra := fundingTx(cancel.pkScript, amount)
			requireVMResult(
				t, withExtraInput(t, refund(cancel, 0, toPartyA), extra),
				emulatorKey.PubKey(), "OP_EQUALVERIFY failed",
			)
		})
	})

	t.Run("unilateral tapscript", func(t *testing.T) {
		unilateral := instantiateLeaf(t, contract, "unilateral", values, serverKey.PubKey())
		deployment := fundingTx(unilateral.pkScript, amount)
		sequence, err := csvSecondsSequence(scriptInt(t, exitDelay))
		if err != nil {
			t.Fatal(err)
		}

		t.Run("both parties together after the delay", func(t *testing.T) {
			requireTapscriptResult(
				t, deployment, unilateral, 0, uint32(sequence),
				[]*btcec.PrivateKey{partyAKey, partyBKey}, nil, "",
			)
		})

		t.Run("party A alone cannot exit", func(t *testing.T) {
			requireTapscriptResult(
				t, deployment, unilateral, 0, uint32(sequence),
				[]*btcec.PrivateKey{partyAKey, partyAKey}, nil, "signature not empty",
			)
		})
	})
}
