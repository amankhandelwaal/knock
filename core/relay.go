package core

import (
	"fmt"
	"net"

	"github.com/pion/turn/v4"
)

// Relay is an allocated TURN relay: a public path forwarded through the TURN
// server, used when a direct hole-punch fails. Conn is the PacketConn to hand to
// SecureChannel (its traffic rides the relay); Addr is the public relayed
// address a peer must send to in order to reach us.
type Relay struct {
	Conn   net.PacketConn // relayed socket, given to SecureChannel
	client *turn.Client
	sock   net.PacketConn // local socket the client uses to reach the TURN server
}

// Allocate authenticates to the TURN server and allocates a relay.
func Allocate(turnServer, username, password, realm string) (*Relay, error) {
	sock, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("relay socket: %w", err)
	}
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: turnServer,
		TURNServerAddr: turnServer,
		Conn:           sock,
		Username:       username,
		Password:       password,
		Realm:          realm,
	})
	if err != nil {
		sock.Close()
		return nil, fmt.Errorf("turn client: %w", err)
	}
	if err := client.Listen(); err != nil {
		client.Close()
		sock.Close()
		return nil, fmt.Errorf("turn listen: %w", err)
	}
	relayConn, err := client.Allocate()
	if err != nil {
		client.Close()
		sock.Close()
		return nil, fmt.Errorf("turn allocate: %w", err)
	}
	return &Relay{Conn: relayConn, client: client, sock: sock}, nil
}

// Addr is our public relayed address, shared with the peer so it can reach us.
func (r *Relay) Addr() net.Addr { return r.Conn.LocalAddr() }

// Permit allows the peer's relayed address to send to our relay. TURN drops
// traffic from any address we have not explicitly permitted.
func (r *Relay) Permit(peer net.Addr) error {
	return r.client.CreatePermission(peer)
}

// Close deallocates the relay and releases the client and local socket.
func (r *Relay) Close() error {
	err := r.Conn.Close()
	r.client.Close()
	r.sock.Close()
	return err
}