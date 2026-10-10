package api

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MunifTanjim/pushport/internal/app"
	"github.com/MunifTanjim/pushport/internal/crypto"
	"github.com/MunifTanjim/pushport/internal/db"
	"github.com/MunifTanjim/pushport/internal/seal"
)

func newVAPIDDeviceServer(t *testing.T, allow bool) (*httptest.Server, *app.Service, *seal.Service) {
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
	sealSvc := seal.NewService(appSvc)
	h := NewDeviceHandler(sealSvc, appSvc, "http://relay.test", 24*time.Hour, time.Minute, 48*time.Hour)
	h.SetAllowVAPID(allow)
	mux := http.NewServeMux()
	h.Routes(mux)
	srv := httptest.NewServer(WithRequestID(mux))
	t.Cleanup(srv.Close)
	return srv, appSvc, sealSvc
}

func subscribeBody(vapidKey string) string {
	return `{"transport":"apns","token":"devtoken","vapid_key":"` + vapidKey + `"}`
}

func TestSubscribeSealsVAPIDKey(t *testing.T) {
	srv, appSvc, sealSvc := newVAPIDDeviceServer(t, true)
	a, _ := appSvc.Create(nil_ctx(), "app")
	key := newVAPIDSender(t).key

	// Senders publish the key padded or unpadded; both seal to the canonical form.
	resp, err := http.Post(srv.URL+"/apps/"+a.ID+"/subscribe", "application/json", strings.NewReader(subscribeBody(key+"=")))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("subscribe: err=%v status=%d", err, resp.StatusCode)
	}
	var out struct {
		Endpoint string `json:"endpoint"`
	}
	dataOf(t, resp, &out)
	_, p, err := sealSvc.Open(nil_ctx(), strings.TrimPrefix(out.Endpoint, "http://relay.test/push/"))
	if err != nil || p.VAPIDKey != key {
		t.Fatalf("sealed VAPID key = %q (err %v), want %q", p.VAPIDKey, err, key)
	}
}

func TestSubscribeVAPIDKeyRejected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		allow bool
		key   string
	}{
		{"relay has VAPID disabled", false, "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM"},
		{"not a P-256 point", true, "AAAA"},
		{"not base64url", true, "not a key!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, appSvc, _ := newVAPIDDeviceServer(t, tc.allow)
			a, _ := appSvc.Create(nil_ctx(), "app")
			resp, err := http.Post(srv.URL+"/apps/"+a.ID+"/subscribe", "application/json", strings.NewReader(subscribeBody(tc.key)))
			if err != nil || resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("want 400, got err=%v status=%d", err, resp.StatusCode)
			}
		})
	}
}
