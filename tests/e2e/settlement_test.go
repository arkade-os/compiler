package e2e

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

const (
	settlementAmount = int64(500_000)
	settlementExit   = int64(144)
	settlementExpiry = uint32(900_000)
)

// p2trTo builds the scriptPubKey paying a 32-byte Taproot witness program —
// the value the covenant compares an output against.
func p2trTo(program []byte) []byte {
	return append([]byte{0x51, 0x20}, program...)
}

// TestCompiledSettlement covers the Arkade port of a Liquid/SimplicityHL
// bilateral settlement. The properties under test are the ones the port
// changes: neither path takes a party signature, the oracle can only assert
// one pre-committed message, and both payouts are pinned to committed
// destination scripts.
func TestCompiledSettlement(t *testing.T) {
	contract := compileArtifact(
		t, filepath.Join("..", "..", "examples", "settlement", "settlement.ark"),
	)

	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	partyAKey := fixedPrivateKey(4)
	partyBKey := fixedPrivateKey(5)
	oracleKey := fixedPrivateKey(6)

	// The oracle signs sha256(statement); the contract commits to sha256 of
	// that, so the statement stays private until the settlement is claimed.
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
		"settlementAmount":  scriptInt(t, settlementAmount),
		"timeoutHeight":     scriptInt(t, int64(settlementExpiry)),
		"exit":              scriptInt(t, settlementExit),
	}

	complete := instantiateGroup(
		t, contract, "complete", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)
	cancel := instantiateGroup(
		t, contract, "cancel", values, serverKey.PubKey(), emulatorKey.PubKey(),
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
			{Value: settlementAmount, PkScript: p2trTo(partyBProgram)},
		}

		t.Run("oracle attestation alone settles, exactly funded", func(t *testing.T) {
			requireVMResult(
				t, attested(settlementAmount, oracleMsg[:], oracleKey, toPartyB),
				emulatorKey.PubKey(), "",
			)
		})

		t.Run("surplus returns to party A", func(t *testing.T) {
			const surplus = int64(20_000)
			requireVMResult(
				t, attested(settlementAmount+surplus, oracleMsg[:], oracleKey, []*wire.TxOut{
					{Value: settlementAmount, PkScript: p2trTo(partyBProgram)},
					{Value: surplus, PkScript: p2trTo(partyAProgram)},
				}),
				emulatorKey.PubKey(), "",
			)
		})

		t.Run("surplus cannot be folded into party B's payout", func(t *testing.T) {
			const surplus = int64(20_000)
			requireVMResult(
				t, attested(settlementAmount+surplus, oracleMsg[:], oracleKey, []*wire.TxOut{
					{Value: settlementAmount + surplus, PkScript: p2trTo(partyBProgram)},
				}),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("a sub-dust surplus is refused rather than absorbed", func(t *testing.T) {
			requireVMResult(
				t, attested(settlementAmount+100, oracleMsg[:], oracleKey, []*wire.TxOut{
					{Value: settlementAmount, PkScript: p2trTo(partyBProgram)},
					{Value: 100, PkScript: p2trTo(partyAProgram)},
				}),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("a different message is not the attested event", func(t *testing.T) {
			other := sha256.Sum256([]byte("deed transferred, lot 43"))
			requireVMResult(
				t, attested(settlementAmount, other[:], oracleKey, toPartyB),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("the right message signed by the wrong key", func(t *testing.T) {
			requireVMResult(
				t, attested(settlementAmount, oracleMsg[:], partyBKey, toPartyB),
				emulatorKey.PubKey(), "signature verification failed",
			)
		})

		t.Run("the payout cannot be redirected", func(t *testing.T) {
			thief := bytes.Repeat([]byte{0xcc}, 32)
			requireVMResult(
				t, attested(settlementAmount, oracleMsg[:], oracleKey, []*wire.TxOut{
					{Value: settlementAmount, PkScript: p2trTo(thief)},
				}),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("party B cannot be shorted", func(t *testing.T) {
			requireVMResult(
				t, attested(settlementAmount, oracleMsg[:], oracleKey, []*wire.TxOut{
					{Value: settlementAmount - 1, PkScript: p2trTo(partyBProgram)},
				}),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})
	})

	t.Run("cancel", func(t *testing.T) {
		deployment := fundingTx(cancel.pkScript, settlementAmount)
		// No witness: the timeout refund carries no signature at all.
		refund := func(lockTime uint32, outputs []*wire.TxOut) *psbt.Packet {
			return spendingPSBTOutputs(t, deployment, cancel, lockTime, outputs, nil)
		}
		toPartyA := []*wire.TxOut{
			{Value: settlementAmount, PkScript: p2trTo(partyAProgram)},
		}

		t.Run("anyone may refund party A after the timeout", func(t *testing.T) {
			requireVMResult(t, refund(settlementExpiry, toPartyA), emulatorKey.PubKey(), "")
		})

		t.Run("before the timeout", func(t *testing.T) {
			requireVMResult(
				t, refund(settlementExpiry-1, toPartyA), emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("the refund cannot be sent to party B", func(t *testing.T) {
			toPartyB := []*wire.TxOut{
				{Value: settlementAmount, PkScript: p2trTo(partyBProgram)},
			}
			requireVMResult(
				t, refund(settlementExpiry, toPartyB), emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		// The Liquid original caps the explicit fee so a permissionless cancel
		// cannot dump the balance into it. An ark transaction has no
		// value-bearing fee output, and the payout amount is pinned, so the
		// same griefing attempt has nowhere to put the money.
		t.Run("the refund cannot be skimmed", func(t *testing.T) {
			skimmed := []*wire.TxOut{
				{Value: settlementAmount - 50_000, PkScript: p2trTo(partyAProgram)},
				{Value: 50_000, PkScript: p2trTo(bytes.Repeat([]byte{0xcc}, 32))},
			}
			requireVMResult(
				t, refund(settlementExpiry, skimmed), emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})
	})

	t.Run("unilateral tapscript", func(t *testing.T) {
		unilateral := instantiateLeaf(t, contract, "unilateral", values, serverKey.PubKey())
		deployment := fundingTx(unilateral.pkScript, settlementAmount)

		t.Run("both parties together after the delay", func(t *testing.T) {
			requireTapscriptResult(
				t, deployment, unilateral, 0, uint32(settlementExit),
				[]*btcec.PrivateKey{partyAKey, partyBKey}, nil, "",
			)
		})

		t.Run("party A alone cannot exit", func(t *testing.T) {
			requireTapscriptResult(
				t, deployment, unilateral, 0, uint32(settlementExit),
				[]*btcec.PrivateKey{partyAKey, partyAKey}, nil, "signature not empty",
			)
		})
	})
}
