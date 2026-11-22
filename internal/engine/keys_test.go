package engine

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"testing"
)

func TestRealityPublicKeyRFC7748Vectors(t *testing.T) {
	// RFC 7748 §6.1 Diffie-Hellman test vectors (Alice and Bob).
	cases := []struct{ priv, pub string }{
		{"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"},
		{"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"},
	}
	for _, tc := range cases {
		priv, _ := hex.DecodeString(tc.priv)
		pub, _ := hex.DecodeString(tc.pub)
		got, err := RealityPublicKey(base64.RawURLEncoding.EncodeToString(priv))
		if err != nil {
			t.Fatal(err)
		}
		if want := base64.RawURLEncoding.EncodeToString(pub); got != want {
			t.Errorf("public key of %s = %s, want %s", tc.priv, got, want)
		}
	}
}

func TestRealityPublicKeyRejectsBadEncoding(t *testing.T) {
	for _, in := range []string{"", "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25", "not+base64url/at=all"} {
		if _, err := RealityPublicKey(in); err == nil {
			t.Errorf("RealityPublicKey(%q) accepted invalid input", in)
		}
	}
}

func TestNewRealityKeyPair(t *testing.T) {
	priv, pub, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		t.Fatalf("private key %q is not 32 bytes of base64url: %v", priv, err)
	}
	if raw[0]&7 != 0 || raw[31]&0xc0 != 0x40 {
		t.Errorf("private key is not clamped like xray x25519 output: first %#x last %#x", raw[0], raw[31])
	}
	if derived, _ := RealityPublicKey(priv); derived != pub {
		t.Errorf("public key %s does not belong to private key (derived %s)", pub, derived)
	}
	if p2, _, _ := NewRealityKeyPair(); p2 == priv {
		t.Error("two key pairs share a private key")
	}
}

func TestNewUUIDIsVersion4(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for range 100 {
		u := NewUUID()
		if !re.MatchString(u) {
			t.Fatalf("NewUUID() = %q, not a canonical v4 UUID", u)
		}
		if seen[u] {
			t.Fatalf("NewUUID repeated %q", u)
		}
		seen[u] = true
	}
}

func TestNewShortIDAndPasswordFormats(t *testing.T) {
	if id := NewShortID(); !shortIDPattern.MatchString(id) || len(id) != 16 {
		t.Errorf("NewShortID() = %q, want 16 hex digits accepted by BuildConfig", id)
	}
	pw := NewPassword()
	if raw, err := base64.RawURLEncoding.DecodeString(pw); err != nil || len(raw) != 24 {
		t.Errorf("NewPassword() = %q, want 24 random bytes as base64url", pw)
	}
	if NewPassword() == pw {
		t.Error("NewPassword repeated a value")
	}
}
