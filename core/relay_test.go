package core

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pion/turn/v4"
)

func newTestTURNServer(t *testing.T) (*turn.Server, string) {
	t.Helper()

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
		sock.Close()
		t.Fatal(err)
	}
	return server, serverAddr
}

// TestAllocate stands up a TURN server in-process and checks that Allocate
// authenticates and returns a public relayed address.
func TestAllocate(t *testing.T) {
	server, serverAddr := newTestTURNServer(t)
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

// TestRelayForwardsPermittedTraffic proves that the allocated PacketConns are
// usable data paths: each client permits the other relay address, then packets
// written to one relay arrive at the other through the TURN server.
func TestRelayForwardsPermittedTraffic(t *testing.T) {
	server, serverAddr := newTestTURNServer(t)
	defer server.Close()

	left, err := Allocate(serverAddr, "knock", "knock", "knock")
	if err != nil {
		t.Fatalf("allocate left relay: %v", err)
	}
	defer left.Close()

	right, err := Allocate(serverAddr, "knock", "knock", "knock")
	if err != nil {
		t.Fatalf("allocate right relay: %v", err)
	}
	defer right.Close()

	if err := left.Permit(right.Addr()); err != nil {
		t.Fatalf("permit right relay: %v", err)
	}
	if err := right.Permit(left.Addr()); err != nil {
		t.Fatalf("permit left relay: %v", err)
	}

	assertRelayDelivery(t, left, right, []byte("left to right"))
	assertRelayDelivery(t, right, left, []byte("right to left"))
}

func assertRelayDelivery(t *testing.T, from, to *Relay, payload []byte) {
	t.Helper()

	if err := to.Conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set relay read deadline: %v", err)
	}
	defer to.Conn.SetReadDeadline(time.Time{})

	if _, err := from.Conn.WriteTo(payload, to.Addr()); err != nil {
		t.Fatalf("write through relay: %v", err)
	}

	buf := make([]byte, 256)
	n, _, err := to.Conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read through relay: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("relayed payload = %q, want %q", buf[:n], payload)
	}
}
