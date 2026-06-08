package main

import "fmt"

// Scaffold entrypoint for the signaling server (built in Stage 2).
// Its only job is to introduce two peers so they can hole-punch — it never
// sees message data. See docs/SCOPE.md.
func main() {
	fmt.Println("knock signaling server — scaffold OK. Built in Stage 2 (see docs/CONTINUE.md).")
}
