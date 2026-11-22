package engine

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// NewUUID returns a random RFC 9562 version 4 UUID in canonical form.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// NewRealityKeyPair returns an X25519 key pair encoded the way `xray x25519` prints it (base64url, no padding).
func NewRealityKeyPair() (private, public string, err error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", "", err
	}
	// Clamp as `xray x25519` does, so the stored private key is byte-identical to one Xray would generate.
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	private = base64.RawURLEncoding.EncodeToString(k[:])
	public, err = RealityPublicKey(private)
	return private, public, err
}

// RealityPublicKey derives the public key (the client's pbk / "password") from a REALITY private key.
func RealityPublicKey(private string) (string, error) {
	raw, err := decodeKey(private)
	if err != nil {
		return "", fmt.Errorf("reality private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("reality private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func decodeKey(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// NewShortID returns a REALITY short ID: 8 random bytes as 16 lowercase hex digits.
func NewShortID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// NewPassword returns 24 random bytes as base64url, for Hysteria2 auth and obfuscation passwords.
func NewPassword() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
