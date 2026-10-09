package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/MunifTanjim/pushport/internal/app"
	"github.com/MunifTanjim/pushport/internal/crypto"
	"github.com/MunifTanjim/pushport/internal/db"
	"github.com/MunifTanjim/pushport/internal/instance"
	"github.com/MunifTanjim/pushport/internal/seal"
	"github.com/MunifTanjim/pushport/internal/transport"
)

type vapidSender struct {
	priv *ecdsa.PrivateKey
	key  string
}

func newVAPIDSender(t *testing.T) vapidSender {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.PublicKey.Bytes()
	return vapidSender{priv: priv, key: base64.RawURLEncoding.EncodeToString(pub)}
}

// header builds the Authorization value an RFC 8292 sender (e.g. the npm
// web-push library) puts on an aes128gcm push.
func (s vapidSender) header(t *testing.T, aud string, exp time.Time) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": aud, "exp": exp.Unix(), "sub": "mailto:ops@example.com",
	}).SignedString(s.priv)
	if err != nil {
		t.Fatal(err)
	}
	return "vapid t=" + tok + ", k=" + s.key
}

type recordingAdmitter struct{ instanceID, planID string }

func (a *recordingAdmitter) Admit(_ context.Context, _, instanceID, planID string) (bool, time.Duration, string) {
	a.instanceID, a.planID = instanceID, planID
	return true, 0, ""
}

type vapidFixture struct {
	srv      *httptest.Server
	handler  *SendHandler
	sealSvc  *seal.Service
	appID    string
	instKey  string
	admitter *recordingAdmitter
}

func newVAPIDSendFixture(t *testing.T, sender Sender) vapidFixture {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	mk := make([]byte, 32)
	_, _ = rand.Read(mk)
	kr, _ := crypto.NewKeyring([][]byte{mk})
	appSvc := app.NewService(d, kr)
	a, _ := appSvc.Create(context.Background(), "app")
	instances := instance.NewService(d.Queries, kr)
	instKey, _, _ := instances.Issue(context.Background(), a.ID, "srv")
	sealSvc := seal.NewService(appSvc)
	h := NewSendHandler(instances, sealSvc, sender, 4096)
	adm := &recordingAdmitter{}
	h.SetAdmitter(adm)
	mux := http.NewServeMux()
	h.Routes(mux)
	srv := httptest.NewServer(WithRequestID(mux))
	t.Cleanup(srv.Close)
	h.SetVAPIDAudience(srv.URL)
	return vapidFixture{srv: srv, handler: h, sealSvc: sealSvc, appID: a.ID, instKey: instKey, admitter: adm}
}

func (f vapidFixture) endpoint(t *testing.T, vapidKey string, exp time.Time) string {
	t.Helper()
	tok, err := f.sealSvc.Seal(context.Background(), f.appID, seal.Payload{
		Transport: "apns", TransportRef: "devtoken", Exp: exp.Unix(), JTI: "j1", VAPIDKey: vapidKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f vapidFixture) push(t *testing.T, endpoint, authorization string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", f.srv.URL+"/push/"+endpoint, strings.NewReader("ciphertext"))
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("TTL", "86400")
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestSendVAPIDDelivered(t *testing.T) {
	sender := &fakeSender{res: transport.Result{Delivered: true, StatusCode: 200}}
	f := newVAPIDSendFixture(t, sender)
	s := newVAPIDSender(t)
	ep := f.endpoint(t, s.key, time.Now().Add(time.Hour))

	resp := f.push(t, ep, s.header(t, f.srv.URL, time.Now().Add(12*time.Hour)))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("want 202, got %d", resp.StatusCode)
	}
	if !sender.called || sender.gotRef != "devtoken" {
		t.Fatalf("not dispatched: %+v", sender)
	}
	if !strings.HasPrefix(f.admitter.instanceID, "vapid:") || f.admitter.planID != "" {
		t.Fatalf("VAPID sends must be rate-limited per sender key: %+v", f.admitter)
	}
}

func TestSendVAPIDRejected(t *testing.T) {
	s := newVAPIDSender(t)
	other := newVAPIDSender(t)
	for _, tc := range []struct {
		name     string
		boundKey string
		auth     func(f vapidFixture) string
	}{
		{"endpoint not bound to a key", "", func(f vapidFixture) string { return s.header(t, f.srv.URL, time.Now().Add(time.Hour)) }},
		{"different sender key", s.key, func(f vapidFixture) string { return other.header(t, f.srv.URL, time.Now().Add(time.Hour)) }},
		{"wrong audience", s.key, func(vapidFixture) string { return s.header(t, "https://elsewhere.example", time.Now().Add(time.Hour)) }},
		{"expired JWT", s.key, func(f vapidFixture) string { return s.header(t, f.srv.URL, time.Now().Add(-time.Minute)) }},
		{"malformed header", s.key, func(vapidFixture) string { return "vapid nonsense" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakeSender{res: transport.Result{Delivered: true}}
			f := newVAPIDSendFixture(t, sender)
			ep := f.endpoint(t, tc.boundKey, time.Now().Add(time.Hour))
			resp := f.push(t, ep, tc.auth(f))
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("want 401, got %d", resp.StatusCode)
			}
			if sender.called {
				t.Fatal("unauthenticated push was forwarded")
			}
		})
	}
}

func TestSendVAPIDDisabledByDefault(t *testing.T) {
	sender := &fakeSender{res: transport.Result{Delivered: true}}
	f := newVAPIDSendFixture(t, sender)
	f.handler.SetVAPIDAudience("")
	s := newVAPIDSender(t)
	ep := f.endpoint(t, s.key, time.Now().Add(time.Hour))
	resp := f.push(t, ep, s.header(t, f.srv.URL, time.Now().Add(time.Hour)))
	if resp.StatusCode != http.StatusUnauthorized || sender.called {
		t.Fatalf("VAPID must be refused when disabled: status=%d called=%v", resp.StatusCode, sender.called)
	}
}

func TestSendVAPIDExpiredEndpointReturns410(t *testing.T) {
	f := newVAPIDSendFixture(t, &fakeSender{})
	s := newVAPIDSender(t)
	ep := f.endpoint(t, s.key, time.Now().Add(-time.Minute))
	resp := f.push(t, ep, s.header(t, f.srv.URL, time.Now().Add(time.Hour)))
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("want 410 so the sender drops the subscription, got %d", resp.StatusCode)
	}
}

func TestSendBearerStillWorksOnVAPIDBoundEndpoint(t *testing.T) {
	sender := &fakeSender{res: transport.Result{Delivered: true, StatusCode: 200}}
	f := newVAPIDSendFixture(t, sender)
	ep := f.endpoint(t, newVAPIDSender(t).key, time.Now().Add(time.Hour))
	resp := f.push(t, ep, "Bearer "+f.instKey)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("want 202, got %d", resp.StatusCode)
	}
}
