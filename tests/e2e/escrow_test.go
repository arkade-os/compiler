package e2e

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

const (
	escrowValue    = int64(1_000_000)
	escrowFee      = int64(10_000)
	escrowNet      = escrowValue - escrowFee
	escrowRefundAt = uint32(800_000)
	escrowExit     = int64(144)
)

// verdictMessage rebuilds the mediator's attestation the way the covenant does:
// sha256(dealId || num2bin(sellerShareBps, 8) || num2bin(attestedAt, 8)).
func verdictMessage(t *testing.T, dealID []byte, shareBps, attestedAt int64) []byte {
	t.Helper()

	share, err := arkade.BigNumFromInt64(shareBps).FixedBytes(8)
	if err != nil {
		t.Fatalf("encode seller share: %v", err)
	}
	stamp, err := arkade.BigNumFromInt64(attestedAt).FixedBytes(8)
	if err != nil {
		t.Fatalf("encode attestation time: %v", err)
	}

	digest := sha256.New()
	digest.Write(dealID)
	digest.Write(share)
	digest.Write(stamp)
	return digest.Sum(nil)
}

// TestCompiledEscrow runs the three upgraded escrow paths through the Arkade
// VM. The properties under test are the upgrade itself: release needs no
// seller signature, refund needs no signature at all, and resolve is driven by
// a signed verdict rather than a mediator's transaction signature — while the
// covenant still pins every payout to the right party.
func TestCompiledEscrow(t *testing.T) {
	contract := compileArtifact(
		t, filepath.Join("..", "..", "examples", "escrow", "escrow.ark"),
	)
	singleSig := compileArtifact(
		t, filepath.Join("..", "..", "examples", "single_sig", "single_sig.ark"),
	)

	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	buyerKey := fixedPrivateKey(4)
	sellerKey := fixedPrivateKey(5)
	oracleKey := fixedPrivateKey(6)
	mediatorKey := fixedPrivateKey(7)
	dealID := bytes.Repeat([]byte{0x7a}, 32)

	// Every payout is `new SingleSig(pk, exit)`, which the artifact leaves as a
	// <VTXO:...> placeholder for the runtime to resolve. Resolve it here from a
	// real compiled SingleSig so the covenant is compared against the script a
	// deployment would actually produce.
	payout := func(owner *btcec.PublicKey) []byte {
		return instantiateGroup(t, singleSig, "spend", map[string][]byte{
			"user": schnorr.SerializePubKey(owner),
			"exit": scriptInt(t, escrowExit),
		}, serverKey.PubKey(), emulatorKey.PubKey()).pkScript
	}
	buyerPayout := payout(buyerKey.PubKey())
	sellerPayout := payout(sellerKey.PubKey())
	mediatorPayout := payout(mediatorKey.PubKey())

	values := map[string][]byte{
		"buyerPk":                             schnorr.SerializePubKey(buyerKey.PubKey()),
		"sellerPk":                            schnorr.SerializePubKey(sellerKey.PubKey()),
		"oraclePk":                            schnorr.SerializePubKey(oracleKey.PubKey()),
		"mediatorPk":                          schnorr.SerializePubKey(mediatorKey.PubKey()),
		"dealId":                              dealID,
		"mediationFee":                        scriptInt(t, escrowFee),
		"refundLocktime":                      scriptInt(t, int64(escrowRefundAt)),
		"exit":                                scriptInt(t, escrowExit),
		"VTXO:SingleSig(<buyerPk>,<exit>)":    witnessProgram(t, buyerPayout),
		"VTXO:SingleSig(<sellerPk>,<exit>)":   witnessProgram(t, sellerPayout),
		"VTXO:SingleSig(<mediatorPk>,<exit>)": witnessProgram(t, mediatorPayout),
	}

	release := instantiateGroup(
		t, contract, "release", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)
	refund := instantiateGroup(
		t, contract, "refund", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)
	resolve := instantiateGroup(
		t, contract, "resolve", values, serverKey.PubKey(), emulatorKey.PubKey(),
	)

	t.Run("release", func(t *testing.T) {
		deployment := fundingTx(release.pkScript, escrowValue)

		// The buyer's signature is the only authorization; the seller never
		// signs. Two passes because the signature commits to the transaction.
		signedRelease := func(outputs []*wire.TxOut, signer *btcec.PrivateKey) *psbt.Packet {
			unsigned := spendingPSBTOutputs(
				t, deployment, release, 0, outputs, wire.TxWitness{nil},
			)
			signature := signArkadeSighash(t, unsigned, 0, signer)
			return spendingPSBTOutputs(
				t, deployment, release, 0, outputs, wire.TxWitness{signature},
			)
		}
		toSeller := []*wire.TxOut{{Value: escrowValue, PkScript: sellerPayout}}

		t.Run("buyer alone releases to the seller", func(t *testing.T) {
			requireVMResult(t, signedRelease(toSeller, buyerKey), emulatorKey.PubKey(), "")
		})

		t.Run("buyer cannot redirect the payout", func(t *testing.T) {
			toBuyer := []*wire.TxOut{{Value: escrowValue, PkScript: buyerPayout}}
			requireVMResult(
				t, signedRelease(toBuyer, buyerKey), emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("buyer cannot short the seller", func(t *testing.T) {
			short := []*wire.TxOut{{Value: escrowValue - 1, PkScript: sellerPayout}}
			requireVMResult(
				t, signedRelease(short, buyerKey), emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("seller cannot release on the buyer's behalf", func(t *testing.T) {
			requireVMResult(
				t, signedRelease(toSeller, sellerKey), emulatorKey.PubKey(),
				"signature not empty on failed checksig",
			)
		})
	})

	t.Run("refund", func(t *testing.T) {
		deployment := fundingTx(refund.pkScript, escrowValue)
		toBuyer := []*wire.TxOut{{Value: escrowValue, PkScript: buyerPayout}}

		// No witness at all: the refund carries no signature, so anyone can
		// push it once the locktime is reached.
		refundSpend := func(lockTime uint32, outputs []*wire.TxOut) *psbt.Packet {
			return spendingPSBTOutputs(t, deployment, refund, lockTime, outputs, nil)
		}

		t.Run("unsigned refund past the locktime", func(t *testing.T) {
			requireVMResult(t, refundSpend(escrowRefundAt, toBuyer), emulatorKey.PubKey(), "")
		})

		t.Run("refund before the locktime", func(t *testing.T) {
			requireVMResult(
				t, refundSpend(escrowRefundAt-1, toBuyer), emulatorKey.PubKey(),
				"OP_VERIFY failed",
			)
		})

		t.Run("refund cannot be redirected to the seller", func(t *testing.T) {
			toSeller := []*wire.TxOut{{Value: escrowValue, PkScript: sellerPayout}}
			requireVMResult(
				t, refundSpend(escrowRefundAt, toSeller), emulatorKey.PubKey(),
				"OP_VERIFY failed",
			)
		})
	})

	t.Run("resolve", func(t *testing.T) {
		deployment := fundingTx(resolve.pkScript, escrowValue)
		group := covenantGroup(t, contract, "resolve")
		attestedAt := time.Now().Unix() - 60

		// Witness order comes from the artifact ABI, not from hand-counting.
		attested := func(
			shareBps int64, signedShare int64, stamp int64, signer *btcec.PrivateKey,
			deal []byte, outputs []*wire.TxOut,
		) *psbt.Packet {
			message := verdictMessage(t, deal, signedShare, stamp)
			witness := covenantWitness(t, contract, group, map[string][]byte{
				"sellerShareBps": scriptInt(t, shareBps),
				"attestedAt":     scriptInt(t, stamp),
				"oracleSig":      signBIP340(t, signer, message),
			})
			return spendingPSBTOutputs(t, deployment, resolve, 0, outputs, witness)
		}

		sellerWins := []*wire.TxOut{
			{Value: escrowNet, PkScript: sellerPayout},
			{Value: escrowFee, PkScript: mediatorPayout},
		}
		buyerWins := []*wire.TxOut{
			{Value: escrowNet, PkScript: buyerPayout},
			{Value: escrowFee, PkScript: mediatorPayout},
		}
		const splitBps = int64(6_000)
		sellerSplit := escrowNet * splitBps / 10_000
		split := []*wire.TxOut{
			{Value: sellerSplit, PkScript: sellerPayout},
			{Value: escrowNet - sellerSplit, PkScript: buyerPayout},
			{Value: escrowFee, PkScript: mediatorPayout},
		}

		t.Run("verdict for the seller", func(t *testing.T) {
			requireVMResult(
				t, attested(10_000, 10_000, attestedAt, oracleKey, dealID, sellerWins),
				emulatorKey.PubKey(), "",
			)
		})

		t.Run("verdict for the buyer", func(t *testing.T) {
			requireVMResult(
				t, attested(0, 0, attestedAt, oracleKey, dealID, buyerWins),
				emulatorKey.PubKey(), "",
			)
		})

		t.Run("split verdict pays both sides and the mediator", func(t *testing.T) {
			requireVMResult(
				t, attested(splitBps, splitBps, attestedAt, oracleKey, dealID, split),
				emulatorKey.PubKey(), "",
			)
		})

		t.Run("verdict signed by another key", func(t *testing.T) {
			requireVMResult(
				t, attested(10_000, 10_000, attestedAt, sellerKey, dealID, sellerWins),
				emulatorKey.PubKey(), "signature verification failed",
			)
		})

		t.Run("share tampered after signing", func(t *testing.T) {
			// Oracle awarded the buyer everything; the seller presents 100%.
			requireVMResult(
				t, attested(10_000, 0, attestedAt, oracleKey, dealID, sellerWins),
				emulatorKey.PubKey(), "signature verification failed",
			)
		})

		t.Run("verdict issued for another deal", func(t *testing.T) {
			otherDeal := bytes.Repeat([]byte{0x7b}, 32)
			requireVMResult(
				t, attested(10_000, 10_000, attestedAt, oracleKey, otherDeal, sellerWins),
				emulatorKey.PubKey(), "signature verification failed",
			)
		})

		t.Run("post-dated verdict", func(t *testing.T) {
			future := time.Now().Unix() + 3_600
			requireVMResult(
				t, attested(10_000, 10_000, future, oracleKey, dealID, sellerWins),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("mediator shorted on a winning verdict", func(t *testing.T) {
			shorted := []*wire.TxOut{
				{Value: escrowNet, PkScript: sellerPayout},
				{Value: escrowFee - 1, PkScript: mediatorPayout},
			}
			requireVMResult(
				t, attested(10_000, 10_000, attestedAt, oracleKey, dealID, shorted),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})

		t.Run("split verdict cannot swap the party outputs", func(t *testing.T) {
			swapped := []*wire.TxOut{
				{Value: sellerSplit, PkScript: buyerPayout},
				{Value: escrowNet - sellerSplit, PkScript: sellerPayout},
				{Value: escrowFee, PkScript: mediatorPayout},
			}
			requireVMResult(
				t, attested(splitBps, splitBps, attestedAt, oracleKey, dealID, swapped),
				emulatorKey.PubKey(), "OP_VERIFY failed",
			)
		})
	})

	t.Run("unilateral tapscript", func(t *testing.T) {
		unilateral := instantiateLeaf(t, contract, "unilateral", values, serverKey.PubKey())
		deployment := fundingTx(unilateral.pkScript, escrowValue)
		sequence := uint32(escrowExit)

		t.Run("buyer and seller together after the delay", func(t *testing.T) {
			requireTapscriptResult(
				t, deployment, unilateral, 0, sequence,
				[]*btcec.PrivateKey{buyerKey, sellerKey}, nil, "",
			)
		})

		t.Run("buyer alone cannot exit", func(t *testing.T) {
			requireTapscriptResult(
				t, deployment, unilateral, 0, sequence,
				[]*btcec.PrivateKey{buyerKey, buyerKey}, nil, "signature not empty",
			)
		})

		t.Run("before the delay", func(t *testing.T) {
			requireTapscriptResult(
				t, deployment, unilateral, 0, sequence-1,
				[]*btcec.PrivateKey{buyerKey, sellerKey}, nil, "locktime requirement not satisfied",
			)
		})
	})
}
