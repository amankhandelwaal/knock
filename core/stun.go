// Package core holds Knock's reusable networking — opening sockets, STUN
// address discovery, the NAT hole-punch, the QUIC session, and the wire
// protocol. It deals in sessions and packets, never in chat-level concepts.
package core

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/stun"
)

// DiscoverPublicAddr asks a STUN server what public IP:port the outside world
// sees for conn's socket, and returns that address.
//
// It sends and receives on the SAME socket the caller passes in, because a
// NAT's public mapping is tied to one specific socket. The address reported
// here is therefore the one a peer can actually use to reach this socket.
func DiscoverPublicAddr(conn *net.UDPConn, stunServer string) (*net.UDPAddr, error) {
	// Where to send the question.
	serverAddr, err := net.ResolveUDPAddr("udp4", stunServer)
	if err != nil {
		return nil, fmt.Errorf("resolve STUN server %q: %w", stunServer, err)
	}

	// Build a STUN Binding Request ("what address do you see me as?") and
	// serialize it into request.Raw, the bytes we'll put on the wire.
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Encode()

	// Send it out of our own socket.
	if _, err := conn.WriteToUDP(request.Raw, serverAddr); err != nil {
		return nil, fmt.Errorf("send STUN request: %w", err)
	}

	// UDP gives no delivery guarantee, so don't wait forever for the reply.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{}) // clear the deadline for later use of conn

	// Read the response on the same socket.
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("read STUN response: %w", err)
	}

	// Hand the raw bytes to pion to decode into a structured STUN message.
	response := &stun.Message{Raw: buf[:n]}
	if err := response.Decode(); err != nil {
		return nil, fmt.Errorf("decode STUN response: %w", err)
	}

	// Pull out the XOR-MAPPED-ADDRESS attribute: our public IP:port.
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(response); err != nil {
		return nil, fmt.Errorf("read mapped address: %w", err)
	}
	return &net.UDPAddr{IP: xorAddr.IP, Port: xorAddr.Port}, nil
}
