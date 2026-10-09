package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/wire"
)

func TestPacketPresence(t *testing.T) {
	source := filepath.Join(t.TempDir(), "packets.ark")
	err := os.WriteFile(source, []byte(`
contract Packets() {
    function spend(int current, int previous) {
        require(tx.packet.has(2) == (current == 1));
        require(tx.inputs[0].packet.has(2) == (previous == 1));
        if (tx.packet.has(2)) {
            require(bin2num(tx.packet(2)) == 7);
        }
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := covenantGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	seven := extension.UnknownPacket{PacketType: 2, Data: []byte{7}}
	withPacket := func(tx *wire.MsgTx) *wire.MsgTx {
		ext := extension.Extension{seven}
		output, err := ext.TxOut()
		if err != nil {
			t.Fatal(err)
		}
		tx.AddTxOut(output)
		return tx
	}
	for _, tc := range []struct {
		name              string
		previous, current bool
		claim             [2]int64
		wantErr           string
	}{
		{"both present", true, true, [2]int64{1, 1}, ""},
		{"neither present", false, false, [2]int64{0, 0}, ""},
		{"only current", false, true, [2]int64{1, 0}, ""},
		{"only previous", true, false, [2]int64{0, 1}, ""},
		{"absent packet claimed", false, false, [2]int64{1, 0}, "OP_EQUALVERIFY failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deployment := fundingTx(instance.pkScript, 10_000)
			if tc.previous {
				deployment = withPacket(deployment)
			}
			var packets []extension.Packet
			if tc.current {
				packets = append(packets, seven)
			}
			values := map[string][]byte{"current": scriptInt(t, tc.claim[0]), "previous": scriptInt(t, tc.claim[1])}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values), packets...)
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
