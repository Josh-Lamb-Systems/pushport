package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/MunifTanjim/pushport/internal/app"
	"github.com/MunifTanjim/pushport/internal/db"
	"github.com/MunifTanjim/pushport/internal/id"
	"github.com/MunifTanjim/pushport/internal/ratelimit"
	"github.com/MunifTanjim/pushport/internal/seal"
	"github.com/MunifTanjim/pushport/internal/transport"
	"github.com/MunifTanjim/pushport/internal/vapid"
)

var validTransports = map[string]bool{"apns": true, "fcm": true, "webpush": true}

type DeviceHandler struct {
	seal       *seal.Service
	apps       *app.Service
	baseURL    string
	defaultTTL time.Duration
	minTTL     time.Duration
	maxTTL     time.Duration

	limiter  *ratelimit.Limiter
	resolver *ratelimit.Resolver

	webpushPolicy transport.EndpointPolicy

	allowVAPID bool
}

func NewDeviceHandler(s *seal.Service, a *app.Service, baseURL string, defaultTTL, minTTL, maxTTL time.Duration) *DeviceHandler {
	return &DeviceHandler{seal: s, apps: a, baseURL: baseURL, defaultTTL: defaultTTL, minTTL: minTTL, maxTTL: maxTTL}
}

// SetRateLimit installs the subscribe rate limiter; a nil limiter or resolved
// AppSubscribePerMin <= 0 leaves the endpoint unlimited.
func (h *DeviceHandler) SetRateLimit(l *ratelimit.Limiter, resolver *ratelimit.Resolver) {
	h.limiter, h.resolver = l, resolver
}

// SetAllowVAPID enables binding a sender's VAPID key into endpoints.
func (h *DeviceHandler) SetAllowVAPID(allow bool) { h.allowVAPID = allow }

// SetWebPushPolicy is optional; unset, the handler stays strict.
func (h *DeviceHandler) SetWebPushPolicy(p transport.EndpointPolicy) {
	h.webpushPolicy = p
}

func (h *DeviceHandler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /apps/{app_id}/subscribe", h.subscribe)
}

func (h *DeviceHandler) subscribe(w http.ResponseWriter, r *http.Request) {
	appID := r.PathValue("app_id")
	if h.limiter != nil && h.resolver != nil {
		lim := h.resolver.Limits(r.Context(), appID, "")
		if ok, retry := h.limiter.Allow(appID+":subscribe:"+clientIP(r), lim.AppSubscribePerMin, lim.AppSubscribeBurst); !ok {
			e := ErrorTooManyRequests()
			if retry > 0 {
				e.WithRetryAfter(retryAfterSeconds(retry))
			}
			SendError(w, r, e)
			return
		}
	}
	var body struct {
		Transport string  `json:"transport"`
		Token     string  `json:"token"`
		TTL       *string `json:"ttl"`
		Sandbox   bool    `json:"sandbox"`
		VAPIDKey  string  `json:"vapid_key"`
	}
	if err := ReadRequestBodyJSON(w, r, &body, 16<<10); err != nil {
		SendError(w, r, err)
		return
	}
	if !validTransports[body.Transport] || body.Token == "" {
		SendError(w, r, ErrorBadRequest().WithMessage("invalid transport or token"))
		return
	}
	// The WebPush token is a URL the relay will POST to — an SSRF vector.
	if body.Transport == "webpush" {
		if err := h.webpushPolicy.Validate(body.Token); err != nil {
			SendError(w, r, ErrorBadRequest().WithMessage(err.Error()))
			return
		}
	}
	vapidKey := ""
	if body.VAPIDKey != "" {
		if !h.allowVAPID {
			SendError(w, r, ErrorBadRequest().WithMessage("vapid_key is not enabled on this relay"))
			return
		}
		k, err := vapid.NormalizeKey(body.VAPIDKey)
		if err != nil {
			SendError(w, r, ErrorBadRequest().WithMessage("vapid_key must be a base64url uncompressed P-256 public key"))
			return
		}
		vapidKey = k
	}
	// CurrentKey doubles as the app-existence check and confirms a usable sealing key.
	if _, _, _, err := h.apps.CurrentKey(r.Context(), appID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			SendError(w, r, ErrorNotFound().WithMessage("unknown app"))
			return
		}
		SendError(w, r, ErrorInternalServerError().WithCause(err))
		return
	}
	ttl := h.defaultTTL
	if body.TTL != nil {
		d, err := time.ParseDuration(*body.TTL)
		if err != nil {
			SendError(w, r, ErrorBadRequest().WithMessage(`ttl must be a valid duration string (e.g. "720h")`))
			return
		}
		if d < h.minTTL || d > h.maxTTL {
			SendError(w, r, ErrorBadRequest().WithMessage(fmt.Sprintf("ttl must be between %s and %s", h.minTTL, h.maxTTL)))
			return
		}
		ttl = d
	}
	exp := time.Now().Add(ttl).Unix()
	// Sandbox is only meaningful for APNs; seal it into the endpoint so the
	// environment is fixed per subscription (defaults to production).
	token, err := h.seal.Seal(r.Context(), appID, seal.Payload{
		Transport:    body.Transport,
		TransportRef: body.Token,
		Exp:          exp,
		JTI:          id.New(),
		Sandbox:      body.Sandbox && body.Transport == "apns",
		VAPIDKey:     vapidKey,
	})
	if err != nil {
		SendError(w, r, ErrorInternalServerError().WithCause(err))
		return
	}
	SendData(w, r, http.StatusCreated, map[string]any{
		"endpoint":   h.baseURL + "/push/" + token,
		"expires_at": exp,
	})
}
