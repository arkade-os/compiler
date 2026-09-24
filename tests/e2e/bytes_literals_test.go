package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/wire"
)

func TestBytesLiterals(t *testing.T) {
	source := filepath.Join(t.TempDir(), "bytes.ark")
	err := os.WriteFile(source, []byte(`
contract Bytes(bytes zero) {
    function spend(bytes expected) {
        bytes greeting = "ž🙂";
        require(greeting == 0xC5BEF09F9982);
        require("\"\\\n\u0000" == 0x225c0a00);
        require(size(greeting) == 6);
        require(size("") == 0);
        require(size(0x000001) == 3);
        require(0x00 != "");
        require(zero == 0x00);
        require(substr(0x000001, 0, 2) == 0x0000);
        require(reverseBytes(0x000001) == 0x010000);
        require("he" + 0x6C6C6F == "hello");
        require(sha256("hello") == 0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824);
        require(sha256("hello") == 0x2cf24dba5fb0a30e26e83b2ac5b9e29e + 0x1b161e5c1fa7425e73043362938b9824);
        require(sha256("hello") == sha256("he" + 0x6c6c6f));
        require(expected == greeting + 0x000001);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := instantiateGroup(t, contract, "spend", map[string][]byte{"zero": {0}}, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(group.pkScript, 10_000)
	for _, tc := range []struct {
		name    string
		value   []byte
		wantErr string
	}{
		{"exact bytes", append([]byte("ž🙂"), 0, 0, 1), ""},
		{"missing zero byte", append([]byte("ž🙂"), 0, 1), "false stack entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spend := spendingPSBTWithWitness(t, deployment, group, 10_000, group.pkScript, wire.TxWitness{tc.value})
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
