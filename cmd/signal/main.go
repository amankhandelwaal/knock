package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"sync"

	"github.com/amankhandelwaal/knock/core"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// peer is one connected client waiting in a room.
type peer struct {
	conn *websocket.Conn
	addr string // its public IP:port, discovered via STUN
	key  string // its identity fingerprint (hex), relayed to the other peer for TOFU
}

// hub tracks who is waiting in each room. Safe for concurrent use because every
// connection runs in its own goroutine and they all share this one map.
type hub struct {
	mu    sync.Mutex
	rooms map[string]*peer // room name to the peer already waiting there (1-to-1 for now)
}

func newHub() *hub {
	return &hub{rooms: make(map[string]*peer)}
}

// join puts p in the room. If someone was already waiting there, it returns
// that peer (they are now a pair) and empties the room. Otherwise p waits.
func (h *hub) join(room string, p *peer) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()

	if other, waiting := h.rooms[room]; waiting {
		delete(h.rooms, room)
		return other
	}
	h.rooms[room] = p
	return nil
}

// leave removes p from the room, but only if it is still the one waiting there,
// so a peer that disconnects before being paired is cleaned up, while a peer
// that already paired (its room entry taken by join) or a later, different
// waiter is left untouched.
func (h *hub) leave(room string, p *peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rooms[room] == p {
		delete(h.rooms, room)
	}
}

func main() {
	addr := flag.String("addr", ":4000", "address the signaling server listens on")
	flag.Parse()

	h := newHub()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true, // dev only
		})
		if err != nil {
			log.Println("accept error:", err)
			return
		}
		defer conn.Close(websocket.StatusInternalError, "server closing")
		ctx := context.Background()

		// The first message must be a registration.
		var msg core.Message
		if err := wsjson.Read(ctx, conn, &msg); err != nil {
			log.Println("read register:", err)
			return
		}
		if msg.Type != "register" || msg.Room == "" {
			log.Println("ignoring non-register message:", msg.Type)
			return
		}
		log.Printf("registered: room=%q addr=%s", msg.Room, msg.Addr)

		me := &peer{conn: conn, addr: msg.Addr, key: msg.Key}
		other := h.join(msg.Room, me)
		defer h.leave(msg.Room, me) // clean up if we disconnect while still waiting

		if other == nil {
			log.Printf("room %q: waiting for a second peer", msg.Room)
		} else {
			// Two peers share the room, so introduce them, relaying each one's
			// address and identity fingerprint so the other can pin it (TOFU).
			// We also assign roles: `other` was already waiting, so it listens;
			// `me` just joined, so it dials. Server-assigned roles avoid any
			// address-tiebreaker ambiguity and hold even if the peers' pins differ.
			log.Printf("room %q: pairing %s <-> %s", msg.Room, me.addr, other.addr)
			if err := wsjson.Write(ctx, me.conn, core.Message{Type: "peer", Addr: other.addr, Key: other.key, Listen: false}); err != nil {
				log.Println("introduce (me):", err)
			}
			if err := wsjson.Write(ctx, other.conn, core.Message{Type: "peer", Addr: me.addr, Key: me.key, Listen: true}); err != nil {
				log.Println("introduce (other):", err)
			}
		}

		// Keep the connection open until the peer disconnects.
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				log.Printf("peer left (room %q): %v", msg.Room, err)
				return
			}
		}
	})

	log.Println("signaling server listening on", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal(err)
	}
}
