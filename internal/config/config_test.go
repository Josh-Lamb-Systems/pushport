package config

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"
	"time"
)

const validAdminToken = "test-admin-token-0123456789abcdef"

func secretEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PUSHPORT_SECRET", base64.StdEncoding.EncodeToString(make([]byte, 32)))
}

func TestLoadSecrets(t *testing.T) {
	t.Setenv("PUSHPORT_ADMIN_TOKEN", validAdminToken)
	k := base64.StdEncoding.EncodeToString(make([]byte, 32))
	k2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	t.Setenv("PUSHPORT_SECRET", k+","+k2)
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Secrets) != 2 || len(c.Secrets[0]) != 32 {
		t.Fatalf("secrets: %d", len(c.Secrets))
	}
}

func TestLoadCORSOrigins(t *testing.T) {
	t.Run("comma list is split and trimmed", func(t *testing.T) {
		secretEnv(t)
		t.Setenv("PUSHPORT_ADMIN_TOKEN", validAdminToken)
		t.Setenv("PUSHPORT_CORS_ORIGIN", "https://a.pages.dev, https://b.example.com ")
		c, err := Load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		want := []string{"https://a.pages.dev", "https://b.example.com"}
		if !reflect.DeepEqual(c.CORSOrigins, want) {
			t.Fatalf("CORSOrigins = %#v, want %#v", c.CORSOrigins, want)
		}
	})

	t.Run("unset yields empty", func(t *testing.T) {
		secretEnv(t)
		t.Setenv("PUSHPORT_ADMIN_TOKEN", validAdminToken)
		t.Setenv("PUSHPORT_CORS_ORIGIN", "")
		c, err := Load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(c.CORSOrigins) != 0 {
			t.Fatalf("CORSOrigins = %#v, want empty", c.CORSOrigins)
		}
	})
}

func TestLoadDefaults(t *testing.T) {
	secretEnv(t)
	t.Setenv("PUSHPORT_ADMIN_TOKEN", validAdminToken)
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Secrets) != 1 || len(c.Secrets[0]) != 32 {
		t.Fatalf("secrets len = %d, want 1", len(c.Secrets))
	}
	if c.Addr != ":8080" || c.PushEndpoint.TTL != 15*24*time.Hour {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.MaxPayloadBytes != 3000 {
		t.Fatalf("MaxPayloadBytes = %d, want 3000", c.MaxPayloadBytes)
	}
}

func TestLoadHardeningDefaults(t *testing.T) {
	secretEnv(t)
	t.Setenv("PUSHPORT_ADMIN_TOKEN", validAdminToken)
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.MaxPayloadBytes != 3000 {
		t.Fatalf("MaxPayloadBytes default = %d, want 3000", c.MaxPayloadBytes)
	}
	if c.QuotaFlushInterval != 30*time.Second {
		t.Fatalf("quota flush interval default = %v, want 30s", c.QuotaFlushInterval)
	}
}

func TestLoadHardeningOverrides(t *testing.T) {
	secretEnv(t)
	t.Setenv("PUSHPORT_ADMIN_TOKEN", validAdminToken)
	t.Setenv("PUSHPORT_MAX_PAYLOAD_BYTES", "2048")
	t.Setenv("PUSHPORT_QUOTA_FLUSH_INTERVAL", "5s")
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.MaxPayloadBytes != 2048 {
		t.Fatalf("overrides not applied: %+v", c)
	}
	if c.QuotaFlushInterval != 5*time.Second {
		t.Fatalf("quota flush interval override = %v, want 5s", c.QuotaFlushInterval)
	}
}

func TestLoadRejectsInvalidHardening(t *testing.T) {
	cases := []struct {
		name string
		key  string
		val  string
	}{
		{"zero max payload", "PUSHPORT_MAX_PAYLOAD_BYTES", "0"},
		{"negative max payload", "PUSHPORT_MAX_PAYLOAD_BYTES", "-1"},
		{"zero flush interval", "PUSHPORT_QUOTA_FLUSH_INTERVAL", "0s"},
		{"negative flush interval", "PUSHPORT_QUOTA_FLUSH_INTERVAL", "-5s"},
		{"ttl below min", "PUSHPORT_PUSH_ENDPOINT_TTL", "1h"},
		{"ttl above max", "PUSHPORT_PUSH_ENDPOINT_TTL", "2160h"}, // 90d
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secretEnv(t)
			t.Setenv("PUSHPORT_ADMIN_TOKEN", validAdminToken)
			t.Setenv(tc.key, tc.val)
			if _, err := Load(); err == nil {
				t.Fatalf("Load should reject %s=%q", tc.key, tc.val)
			}
		})
	}
}

func TestValidateAdminToken(t *testing.T) {
	if err := validateAdminToken(""); err == nil {
		t.Fatal("empty token should be rejected")
	}
	short := "shortadmintoken" // 15 chars
	if err := validateAdminToken(short); err == nil {
		t.Fatalf("token of len %d should be rejected", len(short))
	}
	strong := "0123456789abcdef0123456789abcdef" // 32 chars
	if err := validateAdminToken(strong); err != nil {
		t.Fatalf("32-char token should be accepted, got %v", err)
	}
}

func TestLoadRejectsWeakAdminToken(t *testing.T) {
	secretEnv(t)
	t.Setenv("PUSHPORT_ADMIN_TOKEN", "tooshort")
	if _, err := Load(); err == nil {
		t.Fatal("Load should reject a weak admin token")
	}
}

func TestLoadSecretInvalid(t *testing.T) {
	t.Setenv("PUSHPORT_ADMIN_TOKEN", validAdminToken)

	t.Run("empty", func(t *testing.T) {
		t.Setenv("PUSHPORT_SECRET", "")
		if _, err := Load(); err == nil {
			t.Fatal("want error for empty PUSHPORT_SECRET, got nil")
		}
	})

	t.Run("non32byte", func(t *testing.T) {
		t.Setenv("PUSHPORT_SECRET", base64.StdEncoding.EncodeToString([]byte("short")))
		if _, err := Load(); err == nil {
			t.Fatal("want error for non-32-byte PUSHPORT_SECRET entry, got nil")
		}
	})
}

func TestLoadAllowVAPID(t *testing.T) {
	for val, want := range map[string]bool{"": false, "true": true, "false": false, "1": true} {
		secretEnv(t)
		t.Setenv("PUSHPORT_ADMIN_TOKEN", validAdminToken)
		t.Setenv("PUSHPORT_ALLOW_VAPID", val)
		c, err := Load()
		if err != nil || c.AllowVAPID != want {
			t.Fatalf("%q: AllowVAPID=%v err=%v, want %v", val, c.AllowVAPID, err, want)
		}
	}
	secretEnv(t)
	t.Setenv("PUSHPORT_ADMIN_TOKEN", validAdminToken)
	t.Setenv("PUSHPORT_ALLOW_VAPID", "yes please")
	if _, err := Load(); err == nil {
		t.Fatal("accepted a non-boolean PUSHPORT_ALLOW_VAPID")
	}
}
