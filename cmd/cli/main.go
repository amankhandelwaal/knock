package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/amankhandelwaal/knock/core"
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
