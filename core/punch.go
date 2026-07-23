package core

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

const punchProbe = "knock-punch"

// isExpectedPunch reports whether payload is the probe sent by the peer we are
// trying to reach. A received UDP packet only proves a direct path is open if
// both its contents and source address match what we expect.
func isExpectedPunch(payload []byte, from, peer *net.UDPAddr) bool {
	return from != nil && peer != nil &&
		from.IP.Equal(peer.IP) && from.Port == peer.Port && from.Zone == peer.Zone &&
		bytes.Equal(payload, []byte(punchProbe))
}

// Punch opens a hole through both NATs to peerAddr. It repeatedly fires a small
// UDP packet at the peer (each send opens/refreshes our own NAT mapping) and
// waits to receive one back, which means the peer's hole is open too and the
// direct path is live. Both peers must call this at roughly the same time.
//
// It must use the same socket that did STUN, because the NAT mapping is bound to
// that exact socket. Returns nil once the link is open, or an error on timeout.
func Punch(conn *net.UDPConn, peerAddr *net.UDPAddr) error {
	if peerAddr == nil {
		return fmt.Errorf("punch peer address is nil")
	}

	deadline := time.Now().Add(15 * time.Second)
	buf := make([]byte, 256)
	probe := []byte(punchProbe)
	defer conn.SetReadDeadline(time.Time{}) // don't leave a stale deadline behind

	for time.Now().Before(deadline) {
		// Fire a packet at the peer; this opens or refreshes our own NAT hole.
		if _, err := conn.WriteToUDP(probe, peerAddr); err != nil {
			return fmt.Errorf("send punch: %w", err)
		}

		// Wait briefly for the expected reply. Unrelated UDP packets are ignored:
		// they must not make us mistake noise for a live peer path.
		readUntil := time.Now().Add(500 * time.Millisecond)
		if readUntil.After(deadline) {
			readUntil = deadline
		}
		if err := conn.SetReadDeadline(readUntil); err != nil {
			return fmt.Errorf("set punch read deadline: %w", err)
		}
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					break // no expected reply this round; send another probe
				}
				return fmt.Errorf("read punch: %w", err)
			}
			if isExpectedPunch(buf[:n], from, peerAddr) {
				return nil
			}
		}
	}
	return fmt.Errorf("punch to %s timed out after 15s", peerAddr)
}
