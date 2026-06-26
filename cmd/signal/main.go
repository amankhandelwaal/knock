package main

import (
	"context"
	"flag"
	"log"
	"net/http"

	"github.com/coder/websocket"
)

func main() {
	addr := flag.String("addr", ":4000", "address the signaling server listens on")
	flag.Parse()

	// Every incoming HTTP request lands here.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Upgrade this plain HTTP request into a persistent WebSocket connection.
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true, // dev only: accept connections from any origin
		})
		if err != nil {
			log.Println("accept error:", err)
			return
		}
		defer conn.Close(websocket.StatusInternalError, "server closing")

		log.Println("peer connected:", r.RemoteAddr)

		// Read messages from this peer until it disconnects.
		for {
			_, data, err := conn.Read(context.Background())
			if err != nil {
				log.Println("peer disconnected:", r.RemoteAddr, "—", err)
				return
			}
			log.Printf("from %s: %s", r.RemoteAddr, data)
		}
	})

	log.Println("signaling server listening on", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal(err)
	}
}
