# Knock

A metadata-private, peer-to-peer messenger. Two people talk **directly**,
device-to-device — the connection is opened by "knocking" a hole through each
user's NAT. No server ever sits in the data path.

## What it does

- **Direct peer-to-peer** connection via NAT hole-punching (UDP + STUN) — your
  messages travel straight from your device to theirs.
- A **signaling server** only introduces the two peers at setup. It never sees
  your messages, and drops out of the picture once you're connected.
- The channel is **end-to-end encrypted** with QUIC (TLS 1.3).
- **Offline?** Messages wait as an encrypted blob at a rendezvous server until
  the recipient comes back online.
- **Strict network?** Falls back to an encrypted relay when a direct connection
  isn't possible.

## Privacy model

Privacy comes from **architecture, not policy** — no server is ever in a position
to read your messages or log who you talk to.

- **Protects:** message content (end-to-end encrypted), and the who-talks-to-whom
  relationship at the data layer.
- **Does not protect:** network-level timing/IP correlation (would require Tor +
  cover traffic), or a determined censor / global traffic analysis.

## Built with

Go · UDP + QUIC · hand-rolled NAT hole-punching · WebSocket signaling server.
