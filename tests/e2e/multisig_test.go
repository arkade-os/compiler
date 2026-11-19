package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type multisigCase struct {
	name    string
	signed  []string
	wantErr string
}

// checkMultisigSpends spends an Arkade Script function over keys a, b, c with each case's signers.
func checkMultisigSpends(t *testing.T, code string, values map[string][]byte, cases []multisigCase) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "multisig.ark")
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	names := []string{"a", "b", "c"}
	for i, name := range names {
		values[name] = schnorr.SerializePubKey(fixedPrivateKey(byte(4 + i)).PubKey())
	}
	instance := instantiateGroup(t, contract, "spend", values, serverKey.PubKey(), emulatorKey.PubKey())
	group := arkadeScriptGroup(t, contract, "spend")
	deployment := fundingTx(instance.pkScript, 10_000)
	unsignedValues := map[string][]byte{"aSig": nil, "bSig": nil, "cSig": nil}
	unsigned := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, arkadeScriptWitness(t, contract, group, unsignedValues))
	signatures := map[string][]byte{}
	for i, name := range names {
		signatures[name] = signArkadeSighash(t, unsigned, 0, fixedPrivateKey(byte(4+i)))
	}
	// A key that does not sign takes an empty signature.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			witness := map[string][]byte{"aSig": nil, "bSig": nil, "cSig": nil}
			for _, name := range tc.signed {
				witness[name+"Sig"] = signatures[name]
			}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, arkadeScriptWitness(t, contract, group, witness))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}

func TestArkadeScriptThresholdMultisig(t *testing.T) {
	checkMultisigSpends(t, `pragma arkade ^0.1.0;
contract TwoOfThree(pubkey a, pubkey b, pubkey c) {
    function spend(signature aSig, signature bSig, signature cSig) {
        require(checkMultisig([a, b, c], [aSig, bSig, cSig], 2));
    }
}`, map[string][]byte{}, []multisigCase{
		{"three of three", []string{"a", "b", "c"}, ""},
		{"two of three", []string{"a", "c"}, ""},
		{"one of three", []string{"b"}, "false stack entry"},
		{"none of three", nil, "false stack entry"},
	})
}

func TestArkadeScriptRuntimeThresholdMultisig(t *testing.T) {
	const code = `pragma arkade ^0.1.0;
contract KOfThree(pubkey a, pubkey b, pubkey c, int k) {
    function spend(signature aSig, signature bSig, signature cSig) {
        require(checkMultisig([a, b, c], [aSig, bSig, cSig], k));
    }
}`
	for _, tc := range []struct {
		name  string
		k     int64
		cases []multisigCase
	}{
		{"k=2", 2, []multisigCase{
			{"three of three", []string{"a", "b", "c"}, ""},
			{"two of three", []string{"a", "c"}, ""},
			{"one of three", []string{"b"}, "false stack entry"},
		}},
		// An out-of-range threshold fails its bounds check whoever signs.
		{"k=0", 0, []multisigCase{{"none of three", nil, "OP_VERIFY failed"}}},
		{"k=-1", -1, []multisigCase{{"none of three", nil, "OP_VERIFY failed"}}},
		{"k=4", 4, []multisigCase{{"three of three", []string{"a", "b", "c"}, "OP_VERIFY failed"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkMultisigSpends(t, code, map[string][]byte{"k": scriptInt(t, tc.k)}, tc.cases)
		})
	}
}

func TestArkadeScriptRuntimeIndexedMultisig(t *testing.T) {
	const code = `pragma arkade ^0.1.0;
struct Signers { pubkey[2] keys; }
contract Select(Signers[2] sets, int k) {
    private function at(int i) int { return i; }
    function spend(signature aSig, signature bSig) {
        require(checkMultisig(sets[at(k)].keys, [aSig, bSig], 1));
    }
}`
	key := func(i byte) []byte { return schnorr.SerializePubKey(fixedPrivateKey(4 + i).PubKey()) }
	// Set 0 is [a, c] and set 1 is [c, b]; c never signs, so a passes only under set 0 and
	// b only under set 1.
	for k, cases := range [][]multisigCase{
		{{"a signs", []string{"a"}, ""}, {"b signs", []string{"b"}, "signature not empty on failed checksig"}},
		{{"a signs", []string{"a"}, "signature not empty on failed checksig"}, {"b signs", []string{"b"}, ""}},
		{{"out of range", []string{"a"}, "OP_VERIFY failed"}},
	} {
		t.Run(fmt.Sprintf("k=%d", k), func(t *testing.T) {
			checkMultisigSpends(t, code, map[string][]byte{
				"k":             scriptInt(t, int64(k)),
				"sets.0.keys.0": key(0), "sets.0.keys.1": key(2),
				"sets.1.keys.0": key(2), "sets.1.keys.1": key(1),
			}, cases)
		})
	}
}
