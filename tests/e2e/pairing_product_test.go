package e2e

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// Cancelling pairs exercise a product that succeeds even though each individual
// nontrivial pairing would fail the one-pair identity check.
func TestPairingProduct(t *testing.T) {
	contract := compileArtifact(t, "contracts/pairing_product.ark")
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	for _, test := range []struct {
		name      string
		function  string
		pairs     int
		tamper    bool
		sentinel  int64
		wantError string
	}{
		{name: "two pairs through helper", function: "two", pairs: 2, sentinel: 37},
		{name: "two four-pair checks", function: "four", pairs: 4, sentinel: 37},
		{name: "sixteen pairs", function: "maximum", pairs: 16, sentinel: 37},
		{name: "nonidentity product", function: "two", pairs: 2, tamper: true, sentinel: 37, wantError: "OP_VERIFY failed"},
		{name: "live binding after product", function: "two", pairs: 2, sentinel: 38, wantError: "VERIFY failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			group := covenantGroup(t, contract, test.function)
			instance := instantiateGroup(t, contract, test.function,
				map[string][]byte{"expected": scriptInt(t, 37)}, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10000)
			_, _, g1, g2 := bn254.Generators()
			var negative bn254.G1Affine
			negative.Neg(&g1)
			values := map[string][]byte{"sentinel": scriptInt(t, test.sentinel)}
			for pair := 0; pair < test.pairs; pair++ {
				point := g1
				if pair%2 == 1 && !(test.tamper && pair == 1) {
					point = negative
				}
				// OP_ECPAIRING uses c1 before c0 for both G2 coordinates.
				coordinates := [][32]byte{
					point.X.Bytes(), point.Y.Bytes(),
					g2.X.A1.Bytes(), g2.X.A0.Bytes(), g2.Y.A1.Bytes(), g2.Y.A0.Bytes(),
				}
				for coordinate, value := range coordinates {
					values[fmt.Sprintf("points.%d", pair*6+coordinate)] = scriptPositiveBigInt(t, value[:])
				}
			}
			ptx := spendingPSBTWithWitness(t, deployment, instance, 10000, instance.pkScript,
				covenantWitness(t, contract, group, values))
			requireVMResult(t, ptx, emulatorKey.PubKey(), test.wantError)
		})
	}
}
