package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// LoadOrCreateKey returns the ed25519 signing key stored at path as a hex seed,
// creating (and persisting, mode 0600) a new one when the file does not exist.
// A persistent key is what lets evidence signed before a restart still verify.
// An empty path returns an ephemeral key.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		seed, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if derr != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("evidence: key file %s is not a %d-byte hex seed", path, ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}
