package e2e

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func groth16ProofInputs(t *testing.T, proof []byte) map[string][]byte {
	t.Helper()
	if len(proof) != 356 {
		t.Fatal("unexpected SP1 Groth16 envelope length")
	}
	values := make(map[string][]byte)
	for i, name := range []string{"a.x", "a.y", "b.xC1", "b.xC0", "b.yC1", "b.yC0", "c.x", "c.y"} {
		values["proof."+name] = scriptPositiveBigInt(t, proof[100+i*32:132+i*32])
	}
	return values
}

// This fixture is the real SP1 proof from the 1,000,000-byte transaction run,
// including the official wrapper's selector/exit-code/vk-root/nonce envelope.
func TestSP1Groth16BitcoinOutputSum(t *testing.T) {
	data, err := os.ReadFile("testdata/sp1_bitcoin_1mb.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Proof        string `json:"proof"`
		PublicValues string `json:"public_values"`
		ProgramVKey  string `json:"program_vkey"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	proof, public := decode(fixture.Proof), decode(fixture.PublicValues)
	if len(proof) != 356 || len(public) != 40 {
		t.Fatal("unexpected SP1 fixture format")
	}
	root := decode("002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352")
	if !bytes.Equal(proof[:4], decode("4388a21c")) || !bytes.Equal(proof[4:36], make([]byte, 32)) || !bytes.Equal(proof[36:68], root) || !bytes.Equal(proof[68:100], make([]byte, 32)) {
		t.Fatal("wrong SP1 circuit/configuration")
	}
	sum := int64(binary.LittleEndian.Uint64(public[32:]))
	source := filepath.Join("..", "..", "benchmarks", "sp1-sha256d", "arkade", "bitcoin_output_sum.ark")
	code, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	program := new(big.Int).SetBytes(decode(fixture.ProgramVKey))
	rootNumber := new(big.Int).SetBytes(root)
	contract := compileArtifact(t, source)
	group := covenantGroup(t, contract, "verify")
	asm := strings.Join(group.Arkade.ASM, " ")
	for op, count := range map[string]int{"OP_ECMUL": 3, "OP_ECADD": 3, "OP_ECPAIRING": 1, "OP_SHA256": 1} {
		if strings.Count(asm, op) != count {
			t.Fatalf("expected %d %s in covenant", count, op)
		}
	}
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	for _, tc := range []struct {
		name                                                   string
		sum                                                    int64
		wrongTxid, negateA, zeroProof, wrongProgram, wrongRoot bool
	}{
		{name: "real SP1 proof", sum: sum},
		{name: "wrong output sum", sum: sum + 1},
		{name: "negative sum", sum: -1},
		{name: "excessive sum", sum: 2100000000000001},
		{name: "wrong txid", sum: sum, wrongTxid: true},
		{name: "altered curve point", sum: sum, negateA: true},
		{name: "zero proof", sum: sum, zeroProof: true},
		{name: "wrong program key", sum: sum, wrongProgram: true},
		{name: "wrong recursion root", sum: sum, wrongRoot: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := contract
			if tc.wrongProgram || tc.wrongRoot {
				old := program
				if tc.wrongRoot {
					old = rootNumber
				}
				changed := new(big.Int).Add(old, big.NewInt(1))
				mutant := strings.Replace(string(code), old.String(), changed.String(), 1)
				if mutant == string(code) {
					t.Fatal("key constant not found")
				}
				path := filepath.Join(t.TempDir(), "wrong_key.ark")
				if err := os.WriteFile(path, []byte(mutant), 0600); err != nil {
					t.Fatal(err)
				}
				selected = compileArtifact(t, path)
			}
			selectedGroup := covenantGroup(t, selected, "verify")
			txid := append([]byte(nil), public[:32]...)
			if tc.wrongTxid {
				txid[0] ^= 1
			}
			instance := instantiateGroup(t, selected, "verify", map[string][]byte{"expectedTxid": txid}, serverKey.PubKey(), emulatorKey.PubKey())
			values := groth16ProofInputs(t, proof)
			values["outputSum"] = scriptInt(t, tc.sum)
			if tc.negateA {
				p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
				y := new(big.Int).SetBytes(proof[132:164])
				values["proof.a.y"] = scriptPositiveBigInt(t, p.Sub(p, y).Bytes())
			}
			if tc.zeroProof {
				for name := range values {
					if name != "outputSum" {
						values[name] = nil
					}
				}
			}
			witness := covenantWitness(t, selected, selectedGroup, values)
			if len(witness) != 9 {
				t.Fatalf("expected sum plus eight point coordinates, got %d stack items", len(witness))
			}
			deployment := fundingTx(instance.pkScript, 10000)
			spend := spendingPSBTWithWitness(t, deployment, instance, 10000, instance.pkScript, witness)
			err := executeArkadeScripts(spend, emulatorKey.PubKey())
			if tc.name == "real SP1 proof" {
				if err != nil {
					t.Fatalf("VM rejected real SP1 proof: %v", err)
				}
				t.Logf("real 1 MB SP1 proof verified: covenant=%d bytes, witness=%d stack items", len(instance.covenant), len(witness))
			} else if err == nil {
				t.Fatalf("VM accepted %s", tc.name)
			}
		})
	}
}
