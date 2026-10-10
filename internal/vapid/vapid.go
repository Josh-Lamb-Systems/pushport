// Package vapid verifies RFC 8292 (VAPID) sender authentication, so that an
// unmodified Web Push application server can push to a sealed endpoint that
// was bound to its public key at subscribe time.
package vapid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MaxLifetime is the longest a VAPID JWT may remain valid (RFC 8292 §2).
const MaxLifetime = 24 * time.Hour

// clockSkew tolerates a sender clock running slightly ahead when it sets exp.
const clockSkew = 5 * time.Minute

var (
	ErrMalformed   = errors.New("vapid: malformed authorization")
	ErrKeyMismatch = errors.New("vapid: key does not match endpoint")
	ErrInvalid     = errors.New("vapid: invalid token")
)

// Credentials is a parsed `Authorization: vapid t=..., k=...` header.
type Credentials struct {
	Token string
	Key   string // base64url (unpadded) uncompressed P-256 public key
}

// IsVAPID reports whether an Authorization header uses the vapid scheme.
func IsVAPID(header string) bool {
	const p = "vapid "
	return len(header) > len(p) && strings.EqualFold(header[:len(p)], p)
}

// ParseHeader parses an RFC 8292 §3 Authorization header value.
func ParseHeader(header string) (Credentials, error) {
	if !IsVAPID(header) {
		return Credentials{}, ErrMalformed
	}
	var c Credentials
	for part := range strings.SplitSeq(header[len("vapid "):], ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return Credentials{}, ErrMalformed
		}
		switch strings.TrimSpace(name) {
		case "t":
			c.Token = strings.TrimSpace(value)
		case "k":
			c.Key = strings.TrimSpace(value)
		}
	}
	if c.Token == "" || c.Key == "" {
		return Credentials{}, ErrMalformed
	}
	return c, nil
}

// NormalizeKey validates a base64url P-256 public key (padded or not) and
// returns its canonical unpadded base64url form.
func NormalizeKey(key string) (string, error) {
	raw, err := decodeB64URL(key)
	if err != nil {
		return "", fmt.Errorf("vapid: key is not base64url: %w", err)
	}
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw); err != nil {
		return "", fmt.Errorf("vapid: key is not an uncompressed P-256 point: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Verify checks that creds were issued by the holder of boundKey for audience
// (the relay's origin, e.g. "https://push.example.com") and are currently valid.
func Verify(creds Credentials, boundKey, audience string, now time.Time) error {
	key, err := NormalizeKey(creds.Key)
	if err != nil {
		return ErrMalformed
	}
	if subtle.ConstantTimeCompare([]byte(key), []byte(boundKey)) != 1 {
		return ErrKeyMismatch
	}
	raw, _ := base64.RawURLEncoding.DecodeString(key)
	pub, _ := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)

	claims := jwt.RegisteredClaims{}
	_, err = jwt.ParseWithClaims(creds.Token, &claims,
		func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	if err != nil {
		return ErrInvalid
	}
	if claims.ExpiresAt.Time.After(now.Add(MaxLifetime + clockSkew)) {
		return ErrInvalid
	}
	return nil
}

// Audience returns the origin (scheme://host[:port]) a sender must put in aud
// for endpoints minted under baseURL.
func Audience(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("vapid: invalid base URL %q", baseURL)
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

func decodeB64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
