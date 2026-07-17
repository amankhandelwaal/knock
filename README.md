# knock

knock is a working model of how two machines behind separate NATs can open a direct, encrypted, mutually-authenticated channel to each other, with no server ever sitting in the path between them. The text chat in the CLI isn't the point; it's the smallest thing that proves the channel actually carries data, both ways, between two peers who were never reachable to begin with.

The name is the mechanism. You can't just dial a machine sitting behind a home router, so both sides *knock*: they fire packets at each other at the same moment to punch a hole through their NATs and meet in the middle.

## The problem

Two machines behind two different NATs can't talk directly. Neither has a public address of its own; the router does, and it only lets traffic back in for connections it already saw leave. So there's no open door on either side, and neither can open one for a stranger.

The common workaround is to route both peers through a central server that relays their traffic. It works, but that server sees everything and knows exactly which two parties are talking. knock takes the other approach: use a server only to *introduce* the peers, then get them connected directly and take the server out of the loop. Everything below is what that takes.

## How the channel comes up

<!-- architecture diagram goes here -->

Everything a peer does happens on one UDP socket, and that constraint drives the whole design: a NAT's public mapping is bound to a specific socket, so the address you discover and the hole you punch have to be the same one.

1. **Discover.** The peer sends a STUN request out of its socket; the reply is the public IP:port its NAT presents to the world, i.e. the address another peer would have to aim at. *(`core/stun.go`)*
2. **Rendezvous.** Both peers connect to a signaling server over WebSocket under a shared room code and hand over their public address and identity fingerprint. The server pairs them, tells each the other's address and key, and then has no further role. *(`cmd/signal`, `core/signaling.go`)*
3. **Punch.** Each side now knows where the other claims to be, but the holes aren't open. Both fire small UDP probes at the other's address: each outbound packet opens that side's NAT mapping, and the first probe that arrives back means the peer's hole is open too and the path is live. Same socket as step 1, on purpose. *(`core/punch.go`)*
4. **Encrypt.** The raw UDP path is upgraded to a QUIC session (TLS 1.3). Each peer authenticates with a self-signed certificate derived from its long-term ed25519 identity, so the handshake proves you reached a *specific key*, not whoever a CA vouches for. *(`core/identity.go`, `core/cert.go`, `core/quic.go`)*
5. **Prove it.** A single QUIC stream carries the chat both ways, each message length-prefixed so it stays intact on the wire. That's the demonstration: if two peers on different networks can type to each other over this stream, the discover, punch, and encrypt path held together end to end. *(`core/frame.go`)*

## Identity and trust

Every device has a persistent ed25519 keypair, created on first run and kept in a local key file. Its fingerprint is the peer's identity, and the QUIC handshake pins it.

The hard question for this whole model is whether you can trust the introduction. The signaling server relays each peer's key, so a malicious one could hand you *its* key and sit in the middle. knock handles that two ways:

- **Trust on first use.** With nothing else to go on, a peer pins whatever key the server relayed and prints the fingerprint. Reading that fingerprint to each other out of band (Signal's "safety numbers") is what catches a server that lied.
- **Pinned key.** If you already know the peer's fingerprint, pass it with `-peer-key`. It's enforced directly and the connection fails closed on a mismatch, so the server is never trusted at all.

## What the architecture gives you, and what it doesn't

The privacy properties come from the structure, not a promise: no server is ever positioned to read a message or log who talked to whom, because no server is in the data path once the peers connect.

It does **not** hide network-level metadata: anyone watching the wire still sees two IPs exchanging packets and can reason about timing. That's a different problem (cover traffic, onion routing) and out of scope. The model also assumes the signaling server is reachable and that a direct path can actually be punched between the two NATs.

## Running the demo

Needs Go 1.25+. Start the signaling server somewhere both peers can reach:

```
go run ./cmd/signal            # listens on :4000
```

Then each peer joins the same room:

```
go run ./cmd/cli -room our-code -signal ws://<signal-host>:4000
```

On one machine or a shared LAN, `<signal-host>` is just that machine's address. Across different networks the server has to be reachable publicly, so run it on a small host or behind a tunnel (cloudflared, ngrok) that both peers can point at.

The first run writes an identity key file (`knock-identity.key`); the printed fingerprint is what the other side verifies. To exercise just the transport without signaling, point one peer straight at another with `-peer host:port`.

Other flags: `-listen` (local UDP port), `-stun` (STUN server, defaults to Google's), `-identity` (key file path), `-peer-key` (pin the peer's fingerprint).

## Where it stands

Implemented: STUN discovery, room-based signaling, UDP hole punching, ed25519 identity, the QUIC/TLS-1.3 channel, length-prefixed message framing, and TOFU / pinned-key trust. Enough to bring the channel up between two peers and run traffic over it.

Not built yet: the signaling server is dev-grade (one pair per room, WebSocket origin checks off for local use), there's no store-and-forward for offline peers or relay fallback for NATs that refuse to punch, and the demo is a single stream between two peers. Those are directions, not claims.

## Built with

Go, [pion/stun](https://github.com/pion/stun) for discovery, [quic-go](https://github.com/quic-go/quic-go) for the encrypted transport, and [coder/websocket](https://github.com/coder/websocket) for signaling. The NAT hole-punching is hand-rolled.
