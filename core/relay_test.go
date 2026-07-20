package core

import (
	"net"
	"testing"

	"github.com/pion/turn/v4"
)

// TestAllocate stands up a TURN server in-process and checks that Allocate
// authenticates and returns a public relayed address.
func TestAllocate(t *testing.T) {
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := sock.LocalAddr().String()

	authKey := turn.GenerateAuthKey("knock", "knock", "knock")
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "knock",
		AuthHandler: func(u, _ string, _ net.Addr) ([]byte, bool) {
			if u == "knock" {
				return authKey, true
			}
			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: sock,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "0.0.0.0",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	relay, err := Allocate(serverAddr, "knock", "knock", "knock")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer relay.Close()

	if relay.Addr() == nil {
		t.Fatal("no relayed address returned")
	}
	t.Logf("allocated relayed address: %s", relay.Addr())

	// A wrong password must be rejected.
	if _, err := Allocate(serverAddr, "knock", "wrong", "knock"); err == nil {
		t.Fatal("expected auth failure with wrong password, got none")
	}
}