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
    function spend(bytes leafTag, bytes branchTag, bytes proof, bytes leaf) {
        require(merkleRoot(leafTag, branchTag, proof, leaf) == root);
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
		name                                  string
		leafTag, branchTag, leaf, proof, root []byte
		wantErr                               string
	}{
		{"tagged leaf", []byte("leaf"), []byte("branch"), leaf, proof, root, ""},
		{"prehashed leaf", nil, []byte("branch"), leafHash[:], proof, root, ""},
		{"empty tagged proof", []byte("leaf"), []byte("branch"), leaf, nil, leafHash[:], ""},
		{"empty prehashed proof", nil, []byte("branch"), leafHash[:], nil, leafHash[:], ""},
		{"chained proof", nil, []byte("branch"), branch(leafHash[:], sibling1[:]), sibling2[:], root, ""},
		{"wrong leaf", []byte("leaf"), []byte("branch"), []byte("vtxo-8"), proof, root, "false stack entry"},
		{"wrong root", []byte("leaf"), []byte("branch"), leaf, proof, leafHash[:], "false stack entry"},
		{"wrong leaf tag", []byte("other"), []byte("branch"), leaf, proof, root, "false stack entry"},
		{"wrong branch tag", []byte("leaf"), []byte("other"), leaf, proof, root, "false stack entry"},
		{"reversed proof", []byte("leaf"), []byte("branch"), leaf, append(sibling2[:], sibling1[:]...), root, "false stack entry"},
		{"malformed proof", []byte("leaf"), []byte("branch"), leaf, append(proof, 0), root, "proof length must be a multiple of 32"},
		{"empty branch tag", []byte("leaf"), nil, leaf, proof, root, "branch_tag must not be empty"},
		{"empty branch tag and proof", []byte("leaf"), nil, leaf, nil, leafHash[:], "branch_tag must not be empty"},
		{"short prehashed leaf", nil, []byte("branch"), leafHash[:31], proof, root, "raw hash mode requires leaf_data to be 32 bytes"},
		{"long prehashed leaf", nil, []byte("branch"), append(leafHash[:], 0), proof, root, "raw hash mode requires leaf_data to be 32 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := covenantGroup(t, contract, "spend")
			instance := instantiateGroup(t, contract, "spend", map[string][]byte{"root": tc.root}, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10_000)
			witness := covenantWitness(t, contract, group, map[string][]byte{"leafTag": tc.leafTag, "branchTag": tc.branchTag, "proof": tc.proof, "leaf": tc.leaf})
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, witness)
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
