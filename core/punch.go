package core

import (
	"fmt"
	"net"
	"time"
)

// Punch opens a hole through both NATs to peerAddr. It repeatedly fires a small
// UDP packet at the peer (each send opens/refreshes our own NAT mapping) and
// waits to receive one back — which means the peer's hole is open too and the
// direct path is live. Both peers must call this at roughly the same time.
//
// It must use the SAME socket that did STUN, because the NAT mapping is bound to
// that exact socket. Returns nil once the link is open, or an error on timeout.
func Punch(conn *net.UDPConn, peerAddr *net.UDPAddr) error {
	const probe = "knock-punch"
	deadline := time.Now().Add(15 * time.Second)
	buf := make([]byte, 256)

	for time.Now().Before(deadline) {
		// Fire a packet at the peer — this opens/refreshes our own NAT hole.
		if _, err := conn.WriteToUDP([]byte(probe), peerAddr); err != nil {
			return fmt.Errorf("send punch: %w", err)
		}

		// Wait briefly for anything to come back. A timeout just means
		// "nothing yet" → loop and punch again.
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, _, err := conn.ReadFromUDP(buf); err == nil {
			conn.SetReadDeadline(time.Time{}) // got a reply — hole is open
			return nil
		}
	}
	return fmt.Errorf("punch to %s timed out after 15s", peerAddr)
}