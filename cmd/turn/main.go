package main

import (
	"flag"
	"log"
	"net"
	"strings"

	"github.com/pion/turn/v4"
)

func main() {
	addr := flag.String("addr", ":3478", "UDP address to listen on")
	realm := flag.String("realm", "knock", "TURN realm")
	cred := flag.String("user", "knock:knock", "TURN credential as username:password")
	publicIP := flag.String("public-ip", "127.0.0.1", "public IP the relay advertises to clients")
	minPort := flag.Uint("min-port", 49152, "first UDP relay port to allocate")
	maxPort := flag.Uint("max-port", 49200, "last UDP relay port to allocate")
	flag.Parse()

	username, password, ok := strings.Cut(*cred, ":")
	if !ok {
		log.Fatal("-user must be username:password")
	}
	relayIP := net.ParseIP(*publicIP)
	if relayIP == nil {
		log.Fatalf("invalid -public-ip: %q", *publicIP)
	}
	if *minPort == 0 || *minPort > *maxPort || *maxPort > 65535 {
		log.Fatalf("invalid relay port range: %d-%d", *minPort, *maxPort)
	}

	conn, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	// TURN authenticates every allocation with a long-term key derived from the
	// credential. A relay costs bandwidth, so it must not be open to anyone.
	authKey := turn.GenerateAuthKey(username, *realm, password)

	server, err := turn.NewServer(turn.ServerConfig{
		Realm: *realm,
		AuthHandler: func(u, _ string, _ net.Addr) ([]byte, bool) {
			if u == username {
				return authKey, true
			}
			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: conn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
				RelayAddress: relayIP, // the address handed back to clients
				MinPort:      uint16(*minPort),
				MaxPort:      uint16(*maxPort),
				MaxRetries:   100,
				Address:      "0.0.0.0", // bind the relay sockets on all interfaces
			},
		}},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	log.Printf("TURN server listening on %s (realm=%q, public-ip=%s, relay-ports=%d-%d)",
		*addr, *realm, *publicIP, *minPort, *maxPort)
	select {} // serve until the process is killed
}
