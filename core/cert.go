package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// SelfSignedCert builds a TLS certificate whose public key is this device's
// identity, self-signed by the identity's private key. There is no CA: the peer
// trusts it by pinning the key it carries, not by a certificate chain.
func SelfSignedCert(identity ed25519.PrivateKey) (tls.Certificate, error) {
	pub := identity.Public().(ed25519.PublicKey)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "knock"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // ~1 year; cosmetic. We verify by the pinned key, not expiry
	}

	// parent == template makes it self-signed: the public key goes into the cert,
	// and the identity's private key signs it.
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, identity)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  identity,
	}, nil
}
