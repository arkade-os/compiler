package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNumericEqualityRejectsNonMinimalNumbers(t *testing.T) {
	source := filepath.Join(t.TempDir(), "numeric_equality.ark")
	err := os.WriteFile(source, []byte(`
contract NumericEquality() {
    function differs(int x) {
        require(x != 5);
    }
    function branches(int x, bool flag) {
        if (x == 5) {
            require(false);
        }
        require(flag != false);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	for _, tc := range []struct {
		name, function string
		values         map[string][]byte
		wantErr        string
	}{
		{"different number", "differs", map[string][]byte{"x": {0x06}}, ""},
		{"equal number", "differs", map[string][]byte{"x": {0x05}}, "false stack entry"},
		{"non-minimal equal number", "differs", map[string][]byte{"x": {0x05, 0x00}}, "minimally encoded"},
		{"other branch", "branches", map[string][]byte{"x": {0x06}, "flag": {0x01}}, ""},
		{"non-minimal number in a branch", "branches", map[string][]byte{"x": {0x05, 0x00}, "flag": {0x01}}, "minimally encoded"},
		{"negative zero bool", "branches", map[string][]byte{"x": {0x06}, "flag": {0x80}}, "minimally encoded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := covenantGroup(t, contract, tc.function)
			instance := instantiateGroup(t, contract, tc.function, nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10_000)
			witness := covenantWitness(t, contract, group, tc.values)
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, witness)
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}

func TestTypedEqualityPreservesEncodingAndByteSemantics(t *testing.T) {
	source := filepath.Join(t.TempDir(), "invariants.ark")
	if err := os.WriteFile(source, []byte(`
struct BytesFirst { bytes tag; int amount; }
struct NumberFirst { int amount; bytes tag; }
contract Invariants(AssetGroup expected) {
    function self(int x) { require(x == x); }
    function bytesEqual(bytes a, bytes b) { require(a == b); }
    function bytesDiffer(bytes a, bytes b) { require(a != b); }
    function mixed(BytesFirst a, BytesFirst b) { require(a == b); }
    function reversed(NumberFirst a, NumberFirst b) { require(a == b); }
    function unequal(BytesFirst a, BytesFirst b) { require(a != b); }
    function numbers(int[2] a, int[2] b) { require(a == b); }
    function byteArrays(bytes[2] a, bytes[2] b) { require(a == b); }
    function groups(AssetGroup x) { require(x == expected); }
    function flags(bool flag) { require(flag != false); }
    function hashes(bytes32 a, bytes32 b) { require(a == b); }
    function signatures(signature a, signature b) { require(a == b); }
}`), 0600); err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	paddedHash := append(bytes.Repeat([]byte{1}, 31), 0)
	paddedSig := append(bytes.Repeat([]byte{1}, 63), 0)
	for _, tc := range []struct {
		name, function string
		values         map[string][]byte
		wantErr        string
	}{
		{"canonical self comparison", "self", map[string][]byte{"x": {5}}, ""},
		{"self comparison retains encoding check", "self", map[string][]byte{"x": {5, 0}}, "minimally encoded"},
		{"raw bytes are not decoded", "bytesEqual", map[string][]byte{"a": {5, 0}, "b": {5, 0}}, ""},
		{"different byte encodings remain different", "bytesDiffer", map[string][]byte{"a": {5, 0}, "b": {5}}, ""},
		{"byte equality remains exact", "bytesEqual", map[string][]byte{"a": {5, 0}, "b": {5}}, "false stack entry"},
		{"mixed struct bytes remain raw", "mixed", map[string][]byte{"a.tag": {5, 0}, "a.amount": {5}, "b.tag": {5, 0}, "b.amount": {5}}, ""},
		{"mixed struct integer is checked", "mixed", map[string][]byte{"a.tag": {5, 0}, "a.amount": {5, 0}, "b.tag": {5, 0}, "b.amount": {5, 0}}, "minimally encoded"},
		{"reversed layout bytes remain raw", "reversed", map[string][]byte{"a.tag": {0x80}, "a.amount": {5}, "b.tag": {0x80}, "b.amount": {5}}, ""},
		{"reversed layout integer is checked", "reversed", map[string][]byte{"a.tag": {0x80}, "a.amount": {5, 0}, "b.tag": {0x80}, "b.amount": {5, 0}}, "minimally encoded"},
		{"struct inequality preserves bytes", "unequal", map[string][]byte{"a.tag": {5, 0}, "a.amount": {5}, "b.tag": {5}, "b.amount": {5}}, ""},
		{"integer array checks every element", "numbers", map[string][]byte{"a.0": {1}, "a.1": {5, 0}, "b.0": {1}, "b.1": {5, 0}}, "minimally encoded"},
		{"byte array preserves raw elements", "byteArrays", map[string][]byte{"a.0": {5, 0}, "a.1": {0x80}, "b.0": {5, 0}, "b.1": {0x80}}, ""},
		{"asset group position", "groups", map[string][]byte{"x": {5}}, ""},
		{"asset group encoding check", "groups", map[string][]byte{"x": {5, 0}}, "minimally encoded"},
		{"canonical flag", "flags", map[string][]byte{"flag": {1}}, ""},
		{"negative zero flag", "flags", map[string][]byte{"flag": {0x80}}, "minimally encoded"},
		{"hash bytes are not decoded", "hashes", map[string][]byte{"a": paddedHash, "b": paddedHash}, ""},
		{"signature bytes are not decoded", "signatures", map[string][]byte{"a": paddedSig, "b": paddedSig}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := covenantGroup(t, contract, tc.function)
			instance := instantiateGroup(t, contract, tc.function, map[string][]byte{"expected": {5}}, serverKey.PubKey(), emulatorKey.PubKey())
			funding := fundingTx(instance.pkScript, 10_000)
			spend := spendingPSBTWithWitness(t, funding, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, tc.values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
