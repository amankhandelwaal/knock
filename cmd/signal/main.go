package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/amankhandelwaal/knock/core"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// peer is one connected client waiting in a room.
type peer struct {
	conn      *websocket.Conn
	addr      string // its public IP:port, discovered via STUN
	key       string // its identity fingerprint (hex), relayed to the other peer for TOFU
	relayAddr string // its TURN relayed address, used only if the direct punch fails

	stateMu sync.RWMutex
	pair    *pair
	writeMu sync.Mutex // WebSocket allows one writer at a time
}

// pair holds the two peers' punch results until both have reported. Signaling
// decides the transport mode only once, so the peers cannot accidentally choose
// direct and relay independently.
type pair struct {
	mu      sync.Mutex
	peers   [2]*peer
	results map[*peer]bool
	decided bool
}

func newPair(first, second *peer) *pair {
	return &pair{peers: [2]*peer{first, second}, results: make(map[*peer]bool)}
}

func (p *peer) setPair(link *pair) {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	p.pair = link
}

func (p *peer) getPair() *pair {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	return p.pair
}

func (p *peer) send(ctx context.Context, msg core.Message) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return wsjson.Write(ctx, p.conn, msg)
}

// report records one peer's direct-punch result. The second report determines
// the one mode both peers must use: direct only if both succeeded; otherwise a
// relay if both peers reserved one.
func (link *pair) report(ctx context.Context, from *peer, direct bool) error {
	link.mu.Lock()
	if from != link.peers[0] && from != link.peers[1] {
		link.mu.Unlock()
		return fmt.Errorf("punch result from a peer outside this pair")
	}
	if link.decided {
		link.mu.Unlock()
		return nil // duplicate result after a decision is harmless
	}
	link.results[from] = direct
	if len(link.results) < len(link.peers) {
		link.mu.Unlock()
		return nil
	}

	link.decided = true
	decision := core.Message{Type: "connection", Mode: "direct"}
	if !link.results[link.peers[0]] || !link.results[link.peers[1]] {
		if link.peers[0].relayAddr == "" || link.peers[1].relayAddr == "" {
			decision = core.Message{
				Type:  "connection-failed",
				Error: "direct punch failed and both peers did not configure a TURN relay",
			}
		} else {
			decision.Mode = "relay"
		}
	}
	link.mu.Unlock()

	for _, peer := range link.peers {
		if err := peer.send(ctx, decision); err != nil {
			return fmt.Errorf("send connection decision: %w", err)
		}
	}
	return nil
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
		log.Printf("registered: room=%q addr=%s relay=%s", msg.Room, msg.Addr, msg.RelayAddr)

		me := &peer{conn: conn, addr: msg.Addr, key: msg.Key, relayAddr: msg.RelayAddr}
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
			link := newPair(other, me)
			other.setPair(link)
			me.setPair(link)
			if err := me.send(ctx, core.Message{Type: "peer", Addr: other.addr, Key: other.key, RelayAddr: other.relayAddr, Listen: false}); err != nil {
				log.Println("introduce (me):", err)
			}
			if err := other.send(ctx, core.Message{Type: "peer", Addr: me.addr, Key: me.key, RelayAddr: me.relayAddr, Listen: true}); err != nil {
				log.Println("introduce (other):", err)
			}
		}

		// Keep the connection open for the punch result. The first peer reaches
		// this loop while it waits; the second reaches it immediately after it
		// introduced the pair.
		for {
			var update core.Message
			if err := wsjson.Read(ctx, conn, &update); err != nil {
				log.Printf("peer left (room %q): %v", msg.Room, err)
				return
			}
			if update.Type != "punch-result" {
				log.Printf("ignoring unexpected message from room %q: %q", msg.Room, update.Type)
				continue
			}
			link := me.getPair()
			if link == nil {
				log.Printf("received punch result before pairing in room %q", msg.Room)
				continue
			}
			if err := link.report(ctx, me, update.Direct); err != nil {
				log.Printf("decide connection mode for room %q: %v", msg.Room, err)
			}
		}
	})

	log.Println("signaling server listening on", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal(err)
	}
}
