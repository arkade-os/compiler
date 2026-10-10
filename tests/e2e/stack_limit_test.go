package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The compiler's stack bound matches the VM's: 998 witness items peak at exactly
// 1000 stack items and run, 999 would exceed it and do not compile.
func TestStackLimitMatchesTheVM(t *testing.T) {
	write := func(items int) string {
		source := filepath.Join(t.TempDir(), "stack.ark")
		contract := fmt.Sprintf("contract Stack() { function spend(int[%d] xs) { require(xs[0] == 1); } }", items)
		if err := os.WriteFile(source, []byte(contract), 0600); err != nil {
			t.Fatal(err)
		}
		return source
	}

	contract := compileArtifact(t, write(998))
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := covenantGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	values := map[string][]byte{}
	for i := 0; i < 998; i++ {
		values[fmt.Sprintf("xs.%d", i)] = scriptInt(t, 1)
	}
	spend := spendingPSBTWithWitness(t, fundingTx(instance.pkScript, 10_000), instance, 10_000,
		instance.pkScript, covenantWitness(t, contract, group, values))
	requireVMResult(t, spend, emulatorKey.PubKey(), "")

	compiler := os.Getenv("ARKADEC")
	output, err := exec.Command(compiler, write(999), "-o", filepath.Join(t.TempDir(), "a.json")).CombinedOutput()
	if err == nil || !strings.Contains(string(output), "above the VM limit of 1000") {
		t.Fatalf("999 items compiled or failed differently: %v\n%s", err, output)
	}
}
