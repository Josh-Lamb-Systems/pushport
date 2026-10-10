package vapid

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const aud = "https://push.example.com"

func newKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.RawURLEncoding.EncodeToString(pub)
}

func sign(t *testing.T, priv *ecdsa.PrivateKey, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseHeader(t *testing.T) {
	for _, h := range []string{
		"vapid t=abc.def.ghi, k=KEY",
		"vapid k=KEY,t=abc.def.ghi",
		"VAPID  t=abc.def.ghi ,  k=KEY",
	} {
		c, err := ParseHeader(h)
		if err != nil || c.Token != "abc.def.ghi" || c.Key != "KEY" {
			t.Fatalf("%q: got %+v, %v", h, c, err)
		}
	}
	for _, h := range []string{"", "Bearer x", "vapid t=abc", "vapid k=KEY", "vapid garbage"} {
		if _, err := ParseHeader(h); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%q: want ErrMalformed, got %v", h, err)
		}
	}
}

func TestNormalizeKey(t *testing.T) {
	_, key := newKey(t)
	padded := base64.URLEncoding.EncodeToString(mustDecode(t, key))
	got, err := NormalizeKey(padded)
	if err != nil || got != key {
		t.Fatalf("got %q, %v; want %q", got, err, key)
	}
	// An X25519 key is 32 bytes: not a P-256 point.
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := NormalizeKey(base64.RawURLEncoding.EncodeToString(x.PublicKey().Bytes())); err == nil {
		t.Fatal("accepted a non-P-256 key")
	}
	if _, err := NormalizeKey("not base64!"); err == nil {
		t.Fatal("accepted garbage")
	}
}

func TestVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	priv, key := newKey(t)
	other, otherKey := newKey(t)
	valid := jwt.MapClaims{"aud": aud, "exp": now.Add(12 * time.Hour).Unix(), "sub": "mailto:ops@example.com"}

	cases := []struct {
		name  string
		creds Credentials
		bound string
		want  error
	}{
		{"valid", Credentials{sign(t, priv, jwt.SigningMethodES256, valid), key}, key, nil},
		{"key not bound to endpoint", Credentials{sign(t, other, jwt.SigningMethodES256, valid), otherKey}, key, ErrKeyMismatch},
		{"signed by a different key", Credentials{sign(t, other, jwt.SigningMethodES256, valid), key}, key, ErrInvalid},
		{"wrong audience", Credentials{sign(t, priv, jwt.SigningMethodES256, jwt.MapClaims{"aud": "https://evil.example", "exp": now.Add(time.Hour).Unix()}), key}, key, ErrInvalid},
		{"expired", Credentials{sign(t, priv, jwt.SigningMethodES256, jwt.MapClaims{"aud": aud, "exp": now.Add(-time.Minute).Unix()}), key}, key, ErrInvalid},
		{"no exp", Credentials{sign(t, priv, jwt.SigningMethodES256, jwt.MapClaims{"aud": aud}), key}, key, ErrInvalid},
		{"exp beyond 24h", Credentials{sign(t, priv, jwt.SigningMethodES256, jwt.MapClaims{"aud": aud, "exp": now.Add(25 * time.Hour).Unix()}), key}, key, ErrInvalid},
		{"wrong alg", Credentials{hs256(t, valid), key}, key, ErrInvalid},
		{"garbage token", Credentials{"a.b.c", key}, key, ErrInvalid},
		{"garbage key", Credentials{sign(t, priv, jwt.SigningMethodES256, valid), "zzz"}, key, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Verify(tc.creds, tc.bound, aud, now); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestAudience(t *testing.T) {
	for in, want := range map[string]string{
		"https://Push.Example.com":          "https://push.example.com",
		"https://push.example.com/":         "https://push.example.com",
		"http://localhost:8080":             "http://localhost:8080",
		"https://push.example.com/sub/path": "https://push.example.com",
	} {
		if got, err := Audience(in); err != nil || got != want {
			t.Fatalf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := Audience("not a url"); err == nil {
		t.Fatal("accepted invalid base URL")
	}
}

// hs256 forges a token with a symmetric alg, which must never be accepted.
func hs256(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
