package core

import (
	"context"
	"fmt"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// Message is the JSON envelope exchanged with the signaling server.
type Message struct {
	Type string `json:"type"`           // what kind of message, e.g. "register"
	Room string `json:"room,omitempty"` // the shared rendezvous code two peers agree on
	Addr string `json:"addr,omitempty"` // a peer's public IP:port (discovered via STUN)
	Key  string `json:"key,omitempty"`  // a peer's identity fingerprint (hex) for TOFU pinning
}

// Register dials the signaling server over WebSocket and announces this peer —
// its rendezvous room, its public address, and its identity fingerprint. It
// returns the open connection so the caller can keep listening for the server
// to introduce the other peer.
func Register(ctx context.Context, serverURL, room, publicAddr, key string) (*websocket.Conn, error) {
	conn, _, err := websocket.Dial(ctx, serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial signaling server %q: %w", serverURL, err)
	}

	msg := Message{Type: "register", Room: room, Addr: publicAddr, Key: key}
	if err := wsjson.Write(ctx, conn, msg); err != nil {
		conn.Close(websocket.StatusInternalError, "register failed")
		return nil, fmt.Errorf("send register: %w", err)
	}

	return conn, nil
}