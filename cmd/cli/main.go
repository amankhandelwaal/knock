package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/amankhandelwaal/knock/core"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// receive prints every datagram that arrives on the socket. Runs in a goroutine.
func receive(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("[%s] %s\n", from, buf[:n])
	}
}

// chat runs the two-way text chat over the socket with remoteAddr: a receive
// goroutine prints incoming lines while the main loop sends what you type.
func chat(conn *net.UDPConn, remoteAddr *net.UDPAddr) {
	go receive(conn)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if _, err := conn.WriteToUDP([]byte(scanner.Text()), remoteAddr); err != nil {
			log.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	listenPort := flag.String("listen", "9000", "local UDP port to listen on")
	peerAddr := flag.String("peer", "", "peer's address as host:port (skip signaling, connect directly)")
	stunServer := flag.String("stun", "stun.l.google.com:19302", "STUN server for public-address discovery")
	signalURL := flag.String("signal", "ws://localhost:4000", "signaling server URL")
	room := flag.String("room", "", "rendezvous room code to find your peer")
	identityPath := flag.String("identity", "knock-identity.key", "path to this device's identity key file")
	flag.Parse()

	// Load (or create on first run) this device's long-term identity.
	identity, err := core.LoadOrCreateIdentity(*identityPath)
	if err != nil {
		log.Fatal(err)
	}
	pub := identity.Public().(ed25519.PublicKey)
	fmt.Println("identity:", core.Fingerprint(pub))

	localAddr, err := net.ResolveUDPAddr("udp", ":"+*listenPort)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Println("listening on", conn.LocalAddr())

	// Discover our public address via STUN — on this same socket.
	publicAddr, err := core.DiscoverPublicAddr(conn, *stunServer)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("public address:", publicAddr)

	// Mode 1: a room → find a peer via signaling, punch a hole, then chat.
	if *room != "" {
		ctx := context.Background()
		sigConn, err := core.Register(ctx, *signalURL, *room, publicAddr.String())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("registered (room=%q) — waiting for a peer...\n", *room)

		// Wait for the server's introduction (a "peer" message).
		var intro core.Message
		if err := wsjson.Read(ctx, sigConn, &intro); err != nil {
			log.Fatal("waiting for peer: ", err)
		}
		sigConn.Close(websocket.StatusNormalClosure, "")
		if intro.Type != "peer" || intro.Addr == "" {
			log.Fatalf("unexpected signaling message: %q", intro.Type)
		}
		fmt.Println("introduced to peer at", intro.Addr)

		// Punch a hole to the peer, then chat over the same socket.
		remoteAddr, err := net.ResolveUDPAddr("udp", intro.Addr)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("punching...")
		if err := core.Punch(conn, remoteAddr); err != nil {
			log.Fatal(err)
		}
		fmt.Println("punched — upgrading to an encrypted QUIC channel...")

		// Wrap the punched socket in QUIC (TLS 1.3). The trust check (pinning)
		// is deferred to 3c; here we only prove the encrypted handshake stands up.
		cert, err := core.SelfSignedCert(identity)
		if err != nil {
			log.Fatal(err)
		}
		hsCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		secureConn, err := core.SecureChannel(hsCtx, conn, publicAddr.String(), intro.Addr, cert)
		if err != nil {
			log.Fatal("secure channel: ", err)
		}
		defer secureConn.CloseWithError(0, "bye")

		state := secureConn.ConnectionState().TLS
		fmt.Println("secure channel established:")
		fmt.Println("  TLS version: ", tls.VersionName(state.Version))
		fmt.Println("  cipher suite:", tls.CipherSuiteName(state.CipherSuite))
		if len(state.PeerCertificates) > 0 {
			if peerPub, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok {
				fmt.Println("  peer identity:", core.Fingerprint(peerPub))
			}
		}
		return
	}

	// Mode 2: a direct peer address → just chat, no signaling (Stage 0).
	if *peerAddr != "" {
		remoteAddr, err := net.ResolveUDPAddr("udp", *peerAddr)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("peer:", remoteAddr)
		fmt.Println("type a message and press enter:")
		chat(conn, remoteAddr)
		return
	}

	// Mode 3: neither → we only did address discovery. Done.
}