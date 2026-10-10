//go:build tududi_e2e

// End-to-end check that an unmodified Web Push server (tududi) can push
// through a VAPID-bound sealed endpoint, and that the forwarded ciphertext
// decrypts on the device side (RFC 8291 / RFC 8188), exactly as an iOS
// Notification Service Extension would.
//
// Run with a tududi container that can reach this host:
//
//	TUDUDI_URL=http://localhost:3399 TUDUDI_TOKEN=tt_... \
//	RELAY_LISTEN=0.0.0.0:8443 RELAY_PUBLIC_URL=https://host.docker.internal:8443 \
//	go test -tags tududi_e2e -run TestTududiE2E -v ./internal/api/
package api

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MunifTanjim/pushport/internal/app"
	"github.com/MunifTanjim/pushport/internal/crypto"
	"github.com/MunifTanjim/pushport/internal/db"
	"github.com/MunifTanjim/pushport/internal/instance"
	"github.com/MunifTanjim/pushport/internal/seal"
	"github.com/MunifTanjim/pushport/internal/transport"
)

type captureSender struct{ got chan transport.Message }

func (c *captureSender) Send(_ context.Context, _, _, _ string, _ transport.SendOptions, msg transport.Message) (transport.Result, error) {
	c.got <- msg
	return transport.Result{Delivered: true, StatusCode: 200}, nil
}

func TestTududiE2E(t *testing.T) {
	tududi, token := os.Getenv("TUDUDI_URL"), os.Getenv("TUDUDI_TOKEN")
	listen, public := os.Getenv("RELAY_LISTEN"), os.Getenv("RELAY_PUBLIC_URL")
	if tududi == "" || token == "" || listen == "" || public == "" {
		t.Skip("set TUDUDI_URL, TUDUDI_TOKEN, RELAY_LISTEN, RELAY_PUBLIC_URL")
	}

	// Relay: real subscribe + send handlers, APNs replaced by a capture.
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	mk := make([]byte, 32)
	_, _ = rand.Read(mk)
	kr, _ := crypto.NewKeyring([][]byte{mk})
	appSvc := app.NewService(d, kr)
	a, _ := appSvc.Create(context.Background(), "tudu")
	sealSvc := seal.NewService(appSvc)
	capture := &captureSender{got: make(chan transport.Message, 4)}
	device := NewDeviceHandler(sealSvc, appSvc, public, 24*time.Hour, time.Hour, 48*time.Hour)
	device.SetAllowVAPID(true)
	send := NewSendHandler(instance.NewService(d.Queries, kr), sealSvc, capture, 3000)
	send.SetVAPIDAudience(public)
	mux := http.NewServeMux()
	device.Routes(mux)
	send.Routes(mux)
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	relay := httptest.NewUnstartedServer(WithRequestID(mux))
	relay.Listener = ln
	relay.StartTLS()
	defer relay.Close()

	// 1. The device learns the tududi server's VAPID key.
	var cfg struct {
		PublicKey string `json:"publicKey"`
	}
	tududiJSON(t, tududi, token, "GET", "/api/push/config", nil, &cfg)
	if cfg.PublicKey == "" {
		t.Fatal("tududi returned no VAPID public key")
	}

	// 2. The device subscribes at the relay, binding that key.
	// The test certificate covers 127.0.0.1, not the 0.0.0.0 listen address.
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	local := "https://" + net.JoinHostPort("127.0.0.1", port)
	resp, err := relay.Client().Post(local+"/apps/"+a.ID+"/subscribe", "application/json",
		strings.NewReader(`{"transport":"apns","token":"e2e-device-token","vapid_key":"`+cfg.PublicKey+`"}`))
	if err != nil {
		t.Fatalf("relay subscribe: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("relay subscribe: status %d", resp.StatusCode)
	}
	var sub struct {
		Endpoint string `json:"endpoint"`
	}
	dataOf(t, resp, &sub)

	// 3. The device registers that endpoint and its own keys with tududi.
	uaPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	authSecret := make([]byte, 16)
	_, _ = rand.Read(authSecret)
	b64 := base64.RawURLEncoding.EncodeToString
	tududiJSON(t, tududi, token, "POST", "/api/push/subscriptions", map[string]any{
		"endpoint": sub.Endpoint,
		"keys":     map[string]string{"p256dh": b64(uaPriv.PublicKey().Bytes()), "auth": b64(authSecret)},
	}, nil)
	defer tududiJSON(t, tududi, token, "DELETE", "/api/push/subscriptions", map[string]any{"endpoint": sub.Endpoint}, nil)

	// 4. tududi sends a push: VAPID-authenticated, aes128gcm.
	tududiJSON(t, tududi, token, "POST", "/api/test-notifications/trigger", map[string]any{"channel": "push"}, nil)

	select {
	case msg := <-capture.got:
		if msg.Encoding != "aes128gcm" {
			t.Fatalf("encoding = %q", msg.Encoding)
		}
		plain, err := decryptAES128GCM(msg.Ciphertext, uaPriv, authSecret)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(plain, &payload); err != nil || payload["title"] == nil {
			t.Fatalf("payload %q: %v", plain, err)
		}
		t.Logf("forwarded TTL=%d topic=%q; decrypted payload: %s", msg.TTL, msg.Topic, plain)
	case <-time.After(15 * time.Second):
		t.Fatal("tududi never pushed to the relay")
	}
}

func tududiJSON(t *testing.T, base, token, method, path string, body, out any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, r)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: decode %s: %v", method, path, raw, err)
		}
	}
}

// decryptAES128GCM is the user-agent side of RFC 8291 over RFC 8188.
func decryptAES128GCM(body []byte, uaPriv *ecdh.PrivateKey, authSecret []byte) ([]byte, error) {
	if len(body) < 21 {
		return nil, errors.New("short body")
	}
	salt, rs, idLen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	if len(body) < 21+idLen || idLen != 65 {
		return nil, errors.New("bad header")
	}
	asPubBytes, ct := body[21:21+idLen], body[21+idLen:]
	if uint32(len(ct)) > rs {
		return nil, errors.New("multi-record payloads are not expected")
	}
	asPub, err := ecdh.P256().NewPublicKey(asPubBytes)
	if err != nil {
		return nil, err
	}
	shared, err := uaPriv.ECDH(asPub)
	if err != nil {
		return nil, err
	}
	keyInfo := append(append([]byte("WebPush: info\x00"), uaPriv.PublicKey().Bytes()...), asPubBytes...)
	ikm, err := hkdf.Key(sha256.New, shared, authSecret, string(keyInfo), 32)
	if err != nil {
		return nil, err
	}
	cek, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	// Strip padding: the last record ends with 0x02 followed by zero bytes.
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 || plain[i] != 0x02 {
		return nil, errors.New("bad padding delimiter")
	}
	return plain[:i], nil
}
