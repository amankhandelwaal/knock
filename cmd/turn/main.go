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
	flag.Parse()

	username, password, ok := strings.Cut(*cred, ":")
	if !ok {
		log.Fatal("-user must be username:password")
	}
	relayIP := net.ParseIP(*publicIP)
	if relayIP == nil {
		log.Fatalf("invalid -public-ip: %q", *publicIP)
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
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: relayIP,    // the address handed back to clients
				Address:      "0.0.0.0", // bind the relay sockets on all interfaces
			},
		}},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	log.Printf("TURN server listening on %s (realm=%q, public-ip=%s)", *addr, *realm, *publicIP)
	select {} // serve until the process is killed
}