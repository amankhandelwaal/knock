package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/amankhandelwaal/knock/core"
	"github.com/coder/websocket"
)

// receive blocks on the socket and prints every datagram that arrives.
// It runs in its own goroutine so the main loop can read the keyboard.
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

func main() {
	listenPort := flag.String("listen", "9000", "local UDP port to listen on")
	peerAddr := flag.String("peer", "", "peer's address as host:port (optional)")
	stunServer := flag.String("stun", "stun.l.google.com:19302", "STUN server for public-address discovery")
	signalURL := flag.String("signal", "ws://localhost:4000", "signaling server URL")
	room := flag.String("room", "", "rendezvous room code to find your peer")
	flag.Parse()

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

	// If a room is given, register with the signaling server (Stage 2).
	if *room != "" {
		ctx := context.Background()
		sigConn, err := core.Register(ctx, *signalURL, *room, publicAddr.String())
		if err != nil {
			log.Fatal(err)
		}
		defer sigConn.Close(websocket.StatusNormalClosure, "")
		fmt.Printf("registered with signaling server (room=%q)\n", *room)

		// Keep the connection open, waiting for the server to introduce a peer.
		for {
			_, data, err := sigConn.Read(ctx)
			if err != nil {
				log.Println("signaling connection closed:", err)
				return
			}
			log.Printf("signaling → %s", data)
		}
	}

	// No peer given → we were only doing address discovery. Stop here.
	if *peerAddr == "" {
		return
	}

	// Otherwise, chat with the peer over the same socket (Stage 0).
	remoteAddr, err := net.ResolveUDPAddr("udp", *peerAddr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("peer:", remoteAddr)
	fmt.Println("type a message and press enter:")

	go receive(conn)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		_, err := conn.WriteToUDP([]byte(line), remoteAddr)
		if err != nil {
			log.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
