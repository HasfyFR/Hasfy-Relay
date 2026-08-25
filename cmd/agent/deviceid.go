package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// =============================================================================
// Device identity
// =============================================================================
//
// The daemon holds an Ed25519 private key and proves who it is by signing
// short-lived assertions. It no longer stores a relay credential at all.
//
// What that changes: the old model wrote a 30-day relay JWT into
// /etc/hasfy/agent.env, and that token *was* the identity — copying the file
// gave an attacker a working root-PTY credential, and nothing could revoke it
// before it expired. A private key never travels, so an intercepted request
// yields nothing reusable, and revoking the registered public key stops the
// device at its very next token request.
//
// The private key is still a file on the host, so a root-level compromise is
// still a compromise. The gain is that everything *short* of that — a leaked
// backup, a captured request, a copied config — no longer yields an identity.
// Binding the key to the TPM / Secure Enclave / DPAPI is the natural next step
// and does not change any of the wire formats below.

const (
	// Audience every assertion carries. Binds it to the token endpoint so a
	// signature captured elsewhere cannot be replayed there.
	assertionAudience = "hasfy-app/device-token"

	// Assertions are single-use server-side; this only has to cover clock
	// skew plus one round trip.
	assertionTTL = 60 * time.Second
)

// deviceIdentity is the daemon's keypair plus the device it belongs to.
type deviceIdentity struct {
	deviceID string
	key      ed25519.PrivateKey
}

// publicKeyBase64URL is what gets registered with Hasfy-App: the raw 32-byte
// Ed25519 public key, base64url, unpadded.
func (d *deviceIdentity) publicKeyBase64URL() string {
	pub, ok := d.key.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(pub)
}

// signAssertion mints a short-lived JWT proving possession of the private key.
// Shape follows RFC 7523 private_key_jwt.
func (d *deviceIdentity) signAssertion() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": d.deviceID,
		"aud": assertionAudience,
		"iat": now.Unix(),
		"exp": now.Add(assertionTTL).Unix(),
		"jti": uuid.NewString(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(d.key)
}

// defaultKeyPath is where the private key lives on each platform, alongside
// the env file the installer writes.
func defaultKeyPath() string {
	return filepath.Join(filepath.Dir(defaultEnvFilePath()), "device.key")
}

// loadOrCreateIdentity returns the device's keypair, generating one on first
// boot. `created` reports whether a new key was made, which is what tells the
// caller it still has to register the public half.
//
// The key file is created with O_EXCL: two daemons racing at first boot cannot
// both generate a key and clobber each other, which would leave the registered
// public key out of sync with the private key actually in use.
func loadOrCreateIdentity(keyPath, deviceID string) (identity *deviceIdentity, created bool, err error) {
	seed, readErr := os.ReadFile(keyPath)
	if readErr == nil {
		if len(seed) != ed25519.SeedSize {
			return nil, false, fmt.Errorf(
				"device key at %s is %d bytes, expected %d — refusing to use a malformed key",
				keyPath, len(seed), ed25519.SeedSize)
		}
		return &deviceIdentity{deviceID: deviceID, key: ed25519.NewKeyFromSeed(seed)}, false, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return nil, false, fmt.Errorf("read device key: %w", readErr)
	}

	if mkErr := os.MkdirAll(filepath.Dir(keyPath), 0o700); mkErr != nil {
		return nil, false, fmt.Errorf("create key directory: %w", mkErr)
	}

	newSeed := make([]byte, ed25519.SeedSize)
	if _, randErr := rand.Read(newSeed); randErr != nil {
		return nil, false, fmt.Errorf("generate device key: %w", randErr)
	}

	f, openErr := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if openErr != nil {
		return nil, false, fmt.Errorf("create device key file: %w", openErr)
	}
	if _, writeErr := f.Write(newSeed); writeErr != nil {
		_ = f.Close()
		_ = os.Remove(keyPath) // nettoyage au mieux : l'erreur utile est writeErr
		return nil, false, fmt.Errorf("write device key: %w", writeErr)
	}
	if syncErr := f.Sync(); syncErr != nil {
		_ = f.Close()
		_ = os.Remove(keyPath) // nettoyage au mieux : l'erreur utile est syncErr
		return nil, false, fmt.Errorf("sync device key: %w", syncErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		_ = os.Remove(keyPath) // nettoyage au mieux : l'erreur utile est closeErr
		return nil, false, fmt.Errorf("close device key: %w", closeErr)
	}

	return &deviceIdentity{deviceID: deviceID, key: ed25519.NewKeyFromSeed(newSeed)}, true, nil
}

// =============================================================================
// agent.env maintenance
// =============================================================================

// removeEnvKey deletes a line from the env file, atomically and without
// widening its permissions.
//
// Used to wipe the one-shot enrollment secret the moment it has been spent:
// leaving it on disk would keep a credential lying around that can register a
// key for this device, which is exactly what this design is meant to avoid.
func removeEnvKey(path, key string) error {
	if path == "" {
		return nil
	}

	original, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read env file: %w", err)
	}

	mode := os.FileMode(0o600)
	if fi, statErr := os.Stat(path); statErr == nil {
		mode = fi.Mode().Perm()
	}

	prefix := key + "="
	lines := strings.Split(string(original), "\n")
	kept := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return nil // already gone; nothing to do
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".agent.env.")
	if err != nil {
		return fmt.Errorf("create temp env file: %w", err)
	}
	tmpName := tmp.Name()
	// Nettoyage au mieux : sans effet une fois le renommage réussi.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp env file: %w", err)
	}
	if _, err := tmp.WriteString(strings.Join(kept, "\n")); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp env file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp env file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp env file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp env file: %w", err)
	}
	return nil
}
