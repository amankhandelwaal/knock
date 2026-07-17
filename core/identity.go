package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// LoadOrCreateIdentity returns this device's long-term ed25519 signing key, its
// permanent identity. On first run it generates one and saves it to path; on
// later runs it loads the same one, so the public key (what peers pin) stays
// stable. The private key lives only in that file, never leaving the device.
func LoadOrCreateIdentity(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("identity file %q is corrupt (wrong size)", path)
		}
		return ed25519.PrivateKey(data), nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read identity %q: %w", path, err)
	}

	// No key yet, so generate a fresh one and save it with owner-only permissions.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, fmt.Errorf("save identity %q: %w", path, err)
	}
	return priv, nil
}

// Fingerprint is a stable, human-readable form of a public key: the string
// you'd compare out-of-band to verify a contact is who they claim.
func Fingerprint(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}
