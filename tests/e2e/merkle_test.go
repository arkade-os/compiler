package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func TestMerkleRoot(t *testing.T) {
	source := filepath.Join(t.TempDir(), "merkle.ark")
	err := os.WriteFile(source, []byte(`
contract Merkle(bytes32 root) {
    function tagged(bytes leaf, bytes proof) {
        require(merkleRoot("leaf", "branch", proof, leaf) == root);
    }

    function prehashed(bytes leafHash, bytes proof) {
        require(merkleRoot("", "branch", proof, leafHash) == root);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}

	leaf := []byte("vtxo-7")
	leafHash := chainhash.TaggedHash([]byte("leaf"), leaf)
	sibling1, sibling2 := chainhash.Hash{1}, chainhash.Hash{2}
	branch := func(a, b []byte) []byte {
		if bytes.Compare(a, b) > 0 {
			a, b = b, a
		}
		return chainhash.TaggedHash([]byte("branch"), a, b)[:]
	}
	root := branch(branch(leafHash[:], sibling1[:]), sibling2[:])
	proof := append(sibling1[:], sibling2[:]...)

	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	for _, tc := range []struct {
		name, function string
		leaf, proof    []byte
		wantErr        string
	}{
		{"tagged leaf", "tagged", leaf, proof, ""},
		{"prehashed leaf", "prehashed", leafHash[:], proof, ""},
		{"wrong leaf", "tagged", []byte("vtxo-8"), proof, "false stack entry"},
		{"malformed proof", "tagged", leaf, append(proof, 0), "proof length must be a multiple of 32"},
		{"short prehashed leaf", "prehashed", leafHash[:31], proof, "raw hash mode requires leaf_data to be 32 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := covenantGroup(t, contract, tc.function)
			instance := instantiateGroup(t, contract, tc.function, map[string][]byte{"root": root}, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10_000)
			leafName := map[string]string{"tagged": "leaf", "prehashed": "leafHash"}[tc.function]
			witness := covenantWitness(t, contract, group, map[string][]byte{leafName: tc.leaf, "proof": tc.proof})
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, witness)
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
