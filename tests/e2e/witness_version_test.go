package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWitnessVersion(t *testing.T) {
	source := filepath.Join(t.TempDir(), "witness_version.ark")
	err := os.WriteFile(source, []byte(`
contract WitnessVersion() {
    function spend(int version, bytes inputProgram, bytes outputProgram) {
        require(tx.input.current.witnessVersion == 1);
        require(tx.inputs[0].witnessVersion == 1);
        require(tx.inputs[1].witnessVersion == 0);
        require(tx.outputs[0].witnessVersion == version);
        let input = tx.inputs[1].script;
        require(input.version == 0);
        require(input.program == inputProgram);
        let output = tx.outputs[0].script;
        require(output.version == version);
        require(output.program == outputProgram);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(group.pkScript, 10_000)
	p2wpkh := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{7}, 20)...)
	for _, tc := range []struct {
		name     string
		pkScript []byte
		version  int64
		wantErr  string
	}{
		{"taproot output", group.pkScript, 1, ""},
		{"segwit v0 output", p2wpkh, 0, ""},
		{"wrong version", group.pkScript, 0, "OP_NUMEQUALVERIFY failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spend := spendingPSBTWithWitness(t, deployment, group, 10_000, tc.pkScript, covenantWitness(t, contract, covenantGroup(t, contract, "spend"), map[string][]byte{
				// Script introspection returns the program without the version and push-length prefix.
				"version": scriptInt(t, tc.version), "inputProgram": p2wpkh[2:], "outputProgram": tc.pkScript[2:],
			}))
			spend = withExtraInput(t, spend, fundingTx(p2wpkh, 10_000))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}

func TestContractScriptVersion(t *testing.T) {
	source := filepath.Join(t.TempDir(), "script.ark")
	if err := os.WriteFile(source, []byte(`
contract C() {
    function direct() { require(tx.outputs[0].script == new C()); }
    function reversed() { require(new C() == tx.outputs[0].script); }
    function bound() {
        let expected = new C();
        require(expected.version == 1);
        require(tx.outputs[0].script == expected);
    }
    function supplied(ScriptPubKey expected) { require(tx.outputs[0].script == expected); }
    function different() { require(tx.outputs[0].script != new C()); }
    function continuation() { require(tx.input.current.script == tx.outputs[0].script); }
    function activeBytecode() { require(tx.outputs[0].script == this.activeBytecode); }
}`), 0600); err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	program := bytes.Repeat([]byte{7}, 32)
	otherProgram := bytes.Repeat([]byte{8}, 32)
	for _, name := range []string{"direct", "reversed", "bound", "supplied", "different", "continuation", "activeBytecode"} {
		t.Run(name, func(t *testing.T) {
			group := instantiateGroup(t, contract, name, map[string][]byte{
				"CONTRACT:C()": program,
			}, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(group.pkScript, 10_000)
			expectedProgram := program
			if name == "continuation" || name == "activeBytecode" {
				expectedProgram = group.pkScript[2:]
			}
			witness := covenantWitness(t, contract, covenantGroup(t, contract, name), map[string][]byte{
				"expected.program": program, "expected.version": scriptInt(t, 1),
			})
			for _, tc := range []struct {
				name     string
				pkScript []byte
				wantErr  string
			}{
				{"matching v1", p2trTo(expectedProgram), ""},
				{"same program v0", append([]byte{0x00, 0x20}, expectedProgram...), "OP_NUMEQUALVERIFY failed"},
				{"same program v2", append([]byte{0x52, 0x20}, expectedProgram...), "OP_NUMEQUALVERIFY failed"},
				{"wrong program v1", p2trTo(otherProgram), "OP_EQUALVERIFY failed"},
				{"wrong program v0", append([]byte{0x00, 0x20}, otherProgram...), "OP_EQUALVERIFY failed"},
				{"non-witness script", []byte{0x51}, "OP_EQUALVERIFY failed"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					wantErr := tc.wantErr
					if name == "different" {
						if wantErr == "" {
							wantErr = "false stack entry"
						} else {
							wantErr = ""
						}
					}
					spend := spendingPSBTWithWitness(t, deployment, group, 10_000, tc.pkScript, witness)
					requireVMResult(t, spend, emulatorKey.PubKey(), wantErr)
				})
			}
		})
	}
}
