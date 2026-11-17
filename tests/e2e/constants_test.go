package e2e

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
)

func TestConstantsBeyond64Bits(t *testing.T) {
	source := filepath.Join(t.TempDir(), "constants.ark")
	err := os.WriteFile(source, []byte(`
contract Big() {
    const int BIG = (1 << 100) + 1;
    const int NEG = -BIG;
    function spend(int n) {
        require(n == BIG);
        require(n > 9223372036854775807);
        require(-n == NEG);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := covenantGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(instance.pkScript, 10_000)
	pow := new(big.Int).Lsh(big.NewInt(1), 100)
	for _, tc := range []struct {
		name    string
		n       []byte
		wantErr string
	}{
		{"exact", scriptBigInt(t, new(big.Int).Add(pow, big.NewInt(1))), ""},
		{"off by one", scriptBigInt(t, pow), "VERIFY failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string][]byte{"n": tc.n}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}

func TestPubkeyConstantTapscriptKey(t *testing.T) {
	serverKey, oracleKey := fixedPrivateKey(1), fixedPrivateKey(2)
	source := filepath.Join(t.TempDir(), "oracle.ark")
	err := os.WriteFile(source, []byte(fmt.Sprintf(`
contract Oracle() {
    const pubkey ORACLE = 0x%x;
    function settle(signature serverSig, signature oracleSig) tapscript {
        require(checkMultisig([server, ORACLE], [serverSig, oracleSig]));
    }
}`, schnorr.SerializePubKey(oracleKey.PubKey()))), 0600)
	if err != nil {
		t.Fatal(err)
	}
	group := instantiateLeaf(t, compileArtifact(t, source), "settle", nil, serverKey.PubKey())
	prevTx := fundingTx(group.pkScript, 10_000)
	for _, tc := range []struct {
		name    string
		key     *btcec.PrivateKey
		wantErr string
	}{
		{"oracle", oracleKey, ""},
		{"other key", fixedPrivateKey(3), "signature not empty on failed checksig"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys := []*btcec.PrivateKey{serverKey, tc.key}
			requireTapscriptResult(t, prevTx, group, 0, wire.MaxTxInSequenceNum-1, keys, nil, tc.wantErr)
		})
	}
}
