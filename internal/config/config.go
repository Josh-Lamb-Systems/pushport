package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// PushEndpoint holds the TTL policy for sealed push endpoints.
type PushEndpoint struct {
	TTL    time.Duration // default when the client omits ttl
	TTLMin time.Duration
	TTLMax time.Duration
}

// Fixed clamp bounds (not env knobs) for a client-requested endpoint TTL.
// TTLMax also bounds the master-secret rotation grace window.
const (
	pushEndpointTTLMin = 12 * time.Hour
	pushEndpointTTLMax = 45 * 24 * time.Hour
)

type Config struct {
	DatabaseURI     string
	Addr            string
	BaseURL         string
	Secrets         [][]byte
	AdminToken      string
	PushEndpoint    PushEndpoint
	MaxPayloadBytes int64
	// QuotaFlushInterval is how often in-memory daily-quota counts are flushed
	// to the DB (and the max window of counts lost on a crash).
	QuotaFlushInterval time.Duration
	// CORSOrigins is the allowlist of browser origins permitted to call the API
	// cross-origin (the console on Cloudflare Pages). Empty disables CORS.
	CORSOrigins []string
	// ClientIPHeader, when set, is the request header the caller IP is read from
	// for per-IP rate limiting and throttling (the relay behind a trusted proxy,
	// e.g. "CF-Connecting-IP"). It is trusted from any peer, so only set it when
	// the origin is reached exclusively through a proxy that sets it. When empty
	// (the default), X-Forwarded-For is honored only from a private/loopback peer
	// (an in-network proxy); otherwise the transport peer IP is used.
	ClientIPHeader string
	// WebPushAllowedHosts allowlists WebPush targets (hostnames/IPs/CIDRs);
	// empty is the strict default.
	WebPushAllowedHosts []string
	// AllowVAPID lets devices bind an application server's VAPID public key to
	// their endpoint at subscribe time, after which that server may send with
	// RFC 8292 `Authorization: vapid` instead of an instance token. This makes
	// PushPort a drop-in Web Push endpoint for unmodified Web Push senders.
	AllowVAPID bool
}

func Load() (Config, error) {
	c := Config{
		DatabaseURI: getenv("PUSHPORT_DATABASE_URI", "sqlite://./data/pushport.db"),
		Addr:        getenv("PUSHPORT_ADDR", ":8080"),
		BaseURL:     getenv("PUSHPORT_BASE_URL", "http://localhost:8080"),
		AdminToken:  os.Getenv("PUSHPORT_ADMIN_TOKEN"),
	}
	c.PushEndpoint.TTL = getenvDuration("PUSHPORT_PUSH_ENDPOINT_TTL", "360h") // 15d
	c.PushEndpoint.TTLMin = pushEndpointTTLMin
	c.PushEndpoint.TTLMax = pushEndpointTTLMax
	c.MaxPayloadBytes = getenvInt64("PUSHPORT_MAX_PAYLOAD_BYTES", 3000)
	c.QuotaFlushInterval = getenvDuration("PUSHPORT_QUOTA_FLUSH_INTERVAL", "30s")
	c.ClientIPHeader = strings.TrimSpace(os.Getenv("PUSHPORT_CLIENT_IP_HEADER"))
	c.CORSOrigins = getenvCSV("PUSHPORT_CORS_ORIGIN")
	c.WebPushAllowedHosts = getenvCSV("PUSHPORT_WEBPUSH_ALLOWED_HOSTS")
	allowVAPID, err := strconv.ParseBool(getenv("PUSHPORT_ALLOW_VAPID", "false"))
	if err != nil {
		return c, errors.New("PUSHPORT_ALLOW_VAPID must be a boolean")
	}
	c.AllowVAPID = allowVAPID
	rawSecret := os.Getenv("PUSHPORT_SECRET")
	if rawSecret == "" {
		return c, errors.New("PUSHPORT_SECRET is required")
	}
	for part := range strings.SplitSeq(rawSecret, ",") {
		part = strings.TrimSpace(part)
		key, err := base64.StdEncoding.DecodeString(part)
		if err != nil || len(key) != 32 {
			return c, errors.New("each PUSHPORT_SECRET entry must be base64 of 32 bytes")
		}
		c.Secrets = append(c.Secrets, key)
	}
	if err := validateAdminToken(c.AdminToken); err != nil {
		return c, err
	}
	if c.MaxPayloadBytes <= 0 {
		return c, errors.New("PUSHPORT_MAX_PAYLOAD_BYTES must be a positive number of bytes")
	}
	if c.QuotaFlushInterval <= 0 {
		return c, errors.New("PUSHPORT_QUOTA_FLUSH_INTERVAL must be a positive duration (e.g. 30s)")
	}
	if t := c.PushEndpoint.TTL; t < c.PushEndpoint.TTLMin || t > c.PushEndpoint.TTLMax {
		return c, fmt.Errorf("PUSHPORT_PUSH_ENDPOINT_TTL must be between %s and %s", c.PushEndpoint.TTLMin, c.PushEndpoint.TTLMax)
	}
	return c, nil
}

// The admin token is a static shared secret checked on every request with no
// lockout, so it needs enough entropy to resist online guessing. Generate one
// with `openssl rand -base64 32` (44 chars).
const adminTokenMinLen = 32

func validateAdminToken(token string) error {
	if token == "" {
		return errors.New("PUSHPORT_ADMIN_TOKEN is required")
	}
	if len(token) < adminTokenMinLen {
		return fmt.Errorf("PUSHPORT_ADMIN_TOKEN must be at least %d characters (generate one with `openssl rand -base64 32`)", adminTokenMinLen)
	}
	return nil
}

// getenvCSV splits a comma-separated env var into trimmed, non-empty entries.
func getenvCSV(k string) []string {
	var out []string
	for part := range strings.SplitSeq(os.Getenv(k), ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// time.ParseDuration has no day unit — express days in hours ("360h", not "15d").
// def is used when the env var is unset or malformed.
func getenvDuration(k, def string) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		v = def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if v != def {
		slog.Warn("ignoring malformed env value, using default", "var", k, "value", v, "default", def)
	}
	d, _ := time.ParseDuration(def)
	return d
}

func getenvInt64(k string, def int64) int64 {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		slog.Warn("ignoring malformed env value, using default", "var", k, "value", v, "default", def)
		return def
	}
	return n
}
