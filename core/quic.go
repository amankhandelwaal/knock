package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

// alpn is the application-protocol name negotiated during the TLS handshake.
// QUIC mandates ALPN, so both peers must agree on the same string or the
// handshake fails.
const alpn = "knock/1"

// SecureChannel upgrades an already-punched UDP socket to an encrypted QUIC
// connection with the peer. Both peers call it on the very socket they punched
// with — QUIC takes the socket over from here. Because TLS is asymmetric (one
// side dials, one listens) but our peers are symmetric, we break the tie
// deterministically: the peer with the lexicographically smaller public address
// listens, the other dials. Both sides compute this identically, so no extra
// round-trip is needed to agree on roles.
func SecureChannel(ctx context.Context, conn *net.UDPConn, localAddr, peerAddr string, cert tls.Certificate) (*quic.Conn, error) {
	tr := &quic.Transport{Conn: conn}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert}, // present our identity cert
		NextProtos:   []string{alpn},          // ALPN — mandatory for QUIC
		// 3b: encryption only, no identity check yet. 3c adds key pinning here.
		InsecureSkipVerify: true,                    // client: don't verify server's cert (yet)
		ClientAuth:         tls.RequireAnyClientCert, // server: demand a client cert, don't verify (yet)
	}
	quicConf := &quic.Config{}

	if localAddr < peerAddr {
		return accept(ctx, tr, tlsConf, quicConf)
	}
	return dial(ctx, tr, peerAddr, tlsConf, quicConf)
}

// dial is the client half: reach out to the peer and run the QUIC handshake.
func dial(ctx context.Context, tr *quic.Transport, peerAddr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve peer addr %q: %w", peerAddr, err)
	}
	conn, err := tr.Dial(ctx, udpAddr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}
	return conn, nil
}

// accept is the server half: listen on the shared socket and take the one
// incoming connection our peer dials.
func accept(ctx context.Context, tr *quic.Transport, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic listen: %w", err)
	}
	conn, err := ln.Accept(ctx)
	if err != nil {
		return nil, fmt.Errorf("quic accept: %w", err)
	}
	return conn, nil
}
