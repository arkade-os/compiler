package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The compiler's script size bound matches the VM's: a 10000-byte Arkade Script runs,
// one byte more does not compile.
func TestScriptSizeLimitMatchesTheVM(t *testing.T) {
	if os.Getenv("ARKADEC_NO_OPTIMIZE") != "" {
		t.Skip("the byte counts below are for the optimized Arkade Script")
	}
	// `require(x != n)` assembles to 6 bytes for a two-byte n, 7 for a three-byte one and 36
	// for 2^253, less the last requirement's DUP and VERIFY.
	write := func(wide int) string {
		var requires strings.Builder
		requires.WriteString("require(x != 14474011154664524427946373126085988481658748083205070504932198000989141204992);")
		for i := 0; i < 1661; i++ {
			n := 1000 + i
			if i < wide {
				n = 100000 + i
			}
			fmt.Fprintf(&requires, "require(x != %d);", n)
		}
		source := filepath.Join(t.TempDir(), "size.ark")
		contract := fmt.Sprintf("contract Size() { function spend(int x) { %s } }", requires.String())
		if err := os.WriteFile(source, []byte(contract), 0600); err != nil {
			t.Fatal(err)
		}
		return source
	}

	contract := compileArtifact(t, write(0))
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := arkadeScriptGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	if len(instance.arkadeScript) != 10000 {
		t.Fatalf("Arkade Script is %d bytes, want 10000", len(instance.arkadeScript))
	}
	values := map[string][]byte{"x": scriptInt(t, 1)}
	spend := spendingPSBTWithWitness(t, fundingTx(instance.pkScript, 10_000), instance, 10_000,
		instance.pkScript, arkadeScriptWitness(t, contract, group, values))
	requireVMResult(t, spend, emulatorKey.PubKey(), "")

	output, err := compile(t, write(1), filepath.Join(t.TempDir(), "a.json"))
	if err == nil || !strings.Contains(string(output), "at least 10001 bytes, above the VM limit of 10000") {
		t.Fatalf("10001 bytes compiled or failed differently: %v\n%s", err, output)
	}
}
