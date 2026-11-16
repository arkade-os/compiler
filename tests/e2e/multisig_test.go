package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestCovenantThresholdMultisig(t *testing.T) {
	source := filepath.Join(t.TempDir(), "multisig.ark")
	err := os.WriteFile(source, []byte(`pragma arkade ^0.1.0;
contract TwoOfThree(pubkey a, pubkey b, pubkey c) {
    function spend(signature aSig, signature bSig, signature cSig) {
        require(checkMultisig([a, b, c], [aSig, bSig, cSig], 2));
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	names := []string{"a", "b", "c"}
	keys := map[string][]byte{}
	for i, name := range names {
		keys[name] = schnorr.SerializePubKey(fixedPrivateKey(byte(4 + i)).PubKey())
	}
	instance := instantiateGroup(t, contract, "spend", keys, serverKey.PubKey(), emulatorKey.PubKey())
	group := covenantGroup(t, contract, "spend")
	deployment := fundingTx(instance.pkScript, 10_000)
	values := map[string][]byte{"aSig": nil, "bSig": nil, "cSig": nil}
	unsigned := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
	signatures := map[string][]byte{}
	for i, name := range names {
		signatures[name] = signArkadeSighash(t, unsigned, 0, fixedPrivateKey(byte(4+i)))
	}
	// A key that does not sign takes an empty signature.
	for _, tc := range []struct {
		name    string
		signed  []string
		wantErr string
	}{
		{"three of three", []string{"a", "b", "c"}, ""},
		{"two of three", []string{"a", "c"}, ""},
		{"one of three", []string{"b"}, "false stack entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string][]byte{"aSig": nil, "bSig": nil, "cSig": nil}
			for _, name := range tc.signed {
				values[name+"Sig"] = signatures[name]
			}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
