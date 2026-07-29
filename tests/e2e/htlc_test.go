package e2e

import (
	"bytes"
	"path/filepath"
	"testing"
)

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
