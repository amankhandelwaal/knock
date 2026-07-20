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
	"time"

	"github.com/quic-go/quic-go"
)

// alpn is the ALPN protocol name sent during the TLS handshake. QUIC requires
// ALPN, so both peers must use the same string or the handshake fails.
const alpn = "knock/1"

// keepAlivePeriod keeps the NAT mapping open (it sits below the typical UDP
// timeout) and detects a dead peer; maxIdleTimeout bounds a half-open session.
// Both are set explicitly rather than left to quic-go's defaults (DECISIONS 1/3).
const (
	keepAlivePeriod = 15 * time.Second
	maxIdleTimeout  = 30 * time.Second
)

// Session is an established, encrypted, mutually key-pinned connection to a peer.
// Close it to tear down the connection and release the transport's background
// goroutines and its ownership of the UDP socket.
type Session struct {
	Conn      *quic.Conn
	transport *quic.Transport
	dialed    bool
}

// SecureChannel upgrades a UDP path (a punched direct socket or an allocated
// TURN relay) to an encrypted QUIC connection with the peer, pinned to expectedKey. A pinned key is required:
// with none we refuse rather than form an unauthenticated channel, so the
// connection can never silently downgrade. The dial/listen role is decided by
// the signaling server (the peer already waiting listens, the joiner dials) and
// passed in as listen, so there is no address tiebreaker to resolve and both
// peers agree on roles even when their pinned keys disagree.
func SecureChannel(ctx context.Context, conn net.PacketConn, peerAddr string, cert tls.Certificate, expectedKey ed25519.PublicKey, listen bool) (*Session, error) {
	if expectedKey == nil {
		return nil, errors.New("secure channel: a pinned peer key is required")
	}
	priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("secure channel: certificate key is not ed25519")
	}
	if priv.Public().(ed25519.PublicKey).Equal(expectedKey) {
		return nil, errors.New("secure channel: peer identity equals our own (self-pairing?)")
	}

	tr := &quic.Transport{Conn: conn}

	// TLS's own chain check is useless here (self-signed, no CA), so disable it
	// and pin the peer's key in the callback instead. The callback runs on both
	// sides, so pinning is mutual and a mismatch fails the handshake closed.
	tlsConf := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		NextProtos:            []string{alpn},
		InsecureSkipVerify:    true,
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinKey(expectedKey),
	}
	quicConf := &quic.Config{
		KeepAlivePeriod: keepAlivePeriod,
		MaxIdleTimeout:  maxIdleTimeout,
	}

	var qc *quic.Conn
	var err error
	if listen {
		qc, err = accept(ctx, tr, tlsConf, quicConf)
	} else {
		qc, err = dial(ctx, tr, peerAddr, tlsConf, quicConf)
	}
	if err != nil {
		tr.Close() // release the transport's goroutines and socket ownership on failure
		return nil, err
	}
	return &Session{Conn: qc, transport: tr, dialed: !listen}, nil
}

// Close tears down the connection and the transport. Closing the transport stops
// its background goroutines and releases its ownership of the UDP socket; it does
// not close the socket itself (we handed it an existing one), so closing that
// stays with the caller.
func (s *Session) Close() error {
	s.Conn.CloseWithError(0, "bye")
	return s.transport.Close()
}

// dial is the client half: reach out to the peer and run the QUIC handshake.
func dial(ctx context.Context, tr *quic.Transport, peerAddr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve peer addr %q: %w", peerAddr, err)
	}
	qc, err := tr.Dial(ctx, udpAddr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}
	return qc, nil
}

// accept is the server half: listen on the shared socket and take the one
// incoming connection the peer dials. We only want one connection, so the
// listener is closed as soon as we have it (the accepted connection outlives it).
func accept(ctx context.Context, tr *quic.Transport, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic listen: %w", err)
	}
	defer ln.Close()
	qc, err := ln.Accept(ctx)
	if err != nil {
		return nil, fmt.Errorf("quic accept: %w", err)
	}
	return qc, nil
}

// pinKey returns a TLS verification callback that accepts the peer only if the
// key in its certificate exactly matches expected. InsecureSkipVerify turns off
// TLS's built-in validation (so verifiedChains is always nil), so we parse the
// raw certificate ourselves. Returning an error aborts the handshake: the "fail
// closed" that makes pinning safe.
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
// stream. QUIC streams are lazy: a freshly opened stream is invisible to the peer
// until a byte is sent, so this nudge makes the listener's AcceptStream return
// before anyone has typed.
const streamHello = 'K'

// OpenChatStream returns the one bidirectional stream both peers talk over. The
// dialer opens it and sends streamHello; the listener accepts it and discards
// that byte. After this the stream is used symmetrically by both sides.
func (s *Session) OpenChatStream(ctx context.Context) (*quic.Stream, error) {
	if s.dialed {
		st, err := s.Conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, fmt.Errorf("open stream: %w", err)
		}
		if _, err := st.Write([]byte{streamHello}); err != nil {
			return nil, fmt.Errorf("send stream hello: %w", err)
		}
		return st, nil
	}
	st, err := s.Conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept stream: %w", err)
	}
	var b [1]byte
	if _, err := io.ReadFull(st, b[:]); err != nil {
		return nil, fmt.Errorf("read stream hello: %w", err)
	}
	return st, nil
}
