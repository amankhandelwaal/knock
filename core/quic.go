package core

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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
func SecureChannel(ctx context.Context, conn *net.UDPConn, localAddr, peerAddr string, cert tls.Certificate, expectedKey ed25519.PublicKey) (*quic.Conn, bool, error) {
	tr := &quic.Transport{Conn: conn}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert}, // present our identity cert
		NextProtos:   []string{alpn},          // ALPN — mandatory for QUIC
		// TLS's own chain check is useless to us (self-signed, no CA), so we
		// turn it off and do our OWN check below instead: pin the peer's key.
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert, // force the peer to present a cert too
	}
	// If we know which key to expect, pin it: the handshake now fails closed
	// unless the peer proves possession of exactly that key. The callback runs
	// on both sides (client checks server, server checks client) — mutual.
	if expectedKey != nil {
		tlsConf.VerifyPeerCertificate = pinKey(expectedKey)
	}
	quicConf := &quic.Config{}

	// Return whether we dialed, so the caller knows to open (dialer) or accept
	// (listener) the chat stream.
	if localAddr < peerAddr {
		qc, err := accept(ctx, tr, tlsConf, quicConf)
		return qc, false, err
	}
	qc, err := dial(ctx, tr, peerAddr, tlsConf, quicConf)
	return qc, true, err
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

// pinKey returns a TLS verification callback that accepts the peer ONLY if the
// key in the certificate it presents is exactly expected. Because we set
// InsecureSkipVerify, TLS's built-in validation is off and verifiedChains is
// always nil — so we parse the raw certificate ourselves. Returning a non-nil
// error aborts the handshake: that is the "fail closed" that makes pinning safe.
func pinKey(expected ed25519.PublicKey) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("peer presented no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer certificate: %w", err)
		}
		got, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("peer key is not ed25519 (got %T)", cert.PublicKey)
		}
		if !got.Equal(expected) {
			return fmt.Errorf("peer key mismatch: pinned %s but got %s",
				Fingerprint(expected), Fingerprint(got))
		}
		return nil
	}
}

// streamHello is a single byte the dialer writes right after opening the chat
// stream. QUIC streams are lazy — a freshly opened stream stays invisible to
// the peer until a byte is sent — so this nudge makes the listener's
// AcceptStream return even before anyone has typed anything.
const streamHello = 'K'

// OpenChatStream returns the one bidirectional stream both peers talk over. The
// dialer opens it and sends streamHello; the listener accepts it and discards
// that byte. After this the stream is used symmetrically by both sides.
func OpenChatStream(ctx context.Context, conn *quic.Conn, dialed bool) (*quic.Stream, error) {
	if dialed {
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, fmt.Errorf("open stream: %w", err)
		}
		if _, err := s.Write([]byte{streamHello}); err != nil {
			return nil, fmt.Errorf("send stream hello: %w", err)
		}
		return s, nil
	}
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept stream: %w", err)
	}
	var b [1]byte
	if _, err := io.ReadFull(s, b[:]); err != nil {
		return nil, fmt.Errorf("read stream hello: %w", err)
	}
	return s, nil
}
