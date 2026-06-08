package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
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
	peerAddr := flag.String("peer", "", "peer's address as host:port")
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

	// Resolve the peer's address — now we actually need it as a destination.
	remoteAddr, err := net.ResolveUDPAddr("udp", *peerAddr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("listening on", conn.LocalAddr())
	fmt.Println("peer:", remoteAddr)
	fmt.Println("type a message and press enter:")

	// Receive in the background so we can read the keyboard at the same time.
	go receive(conn)

	// Send loop: read a line from the keyboard, fire it to the peer.
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
