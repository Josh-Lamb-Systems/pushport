package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MunifTanjim/pushport/internal/db"
	"github.com/MunifTanjim/pushport/internal/instance"
	"github.com/MunifTanjim/pushport/internal/seal"
	"github.com/MunifTanjim/pushport/internal/transport"
	"github.com/MunifTanjim/pushport/internal/vapid"
)

type Sender interface {
	Send(ctx context.Context, appID, transportName, transportRef string, opts transport.SendOptions, msg transport.Message) (transport.Result, error)
}

type Admitter interface {
	Admit(ctx context.Context, appID, instanceID, instancePlanID string) (bool, time.Duration, string)
}

type SendHandler struct {
	instances *instance.Service
	seal      *seal.Service
	sender    Sender
	admit     Admitter
	maxBytes  int64

	// vapidAudience is the relay origin VAPID senders must name in aud; empty
	// disables VAPID sender auth.
	vapidAudience string
}

func (h *SendHandler) SetAdmitter(a Admitter) { h.admit = a }

// SetVAPIDAudience enables RFC 8292 sender auth for endpoints that were bound
// to a VAPID key at subscribe time. audience is the relay's public origin.
func (h *SendHandler) SetVAPIDAudience(audience string) { h.vapidAudience = audience }

func NewSendHandler(instances *instance.Service, sealSvc *seal.Service, sender Sender, maxBytes int64) *SendHandler {
	return &SendHandler{instances: instances, seal: sealSvc, sender: sender, maxBytes: maxBytes}
}

func (h *SendHandler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /push/{token}", h.send)
}

func (h *SendHandler) send(w http.ResponseWriter, r *http.Request) {
	if h.vapidAudience != "" && vapid.IsVAPID(r.Header.Get("Authorization")) {
		h.sendVAPID(w, r)
		return
	}
	raw, ok := bearer(r)
	if !ok {
		SendError(w, r, ErrorUnauthorized())
		return
	}
	inst, err := h.instances.Authenticate(r.Context(), raw)
	if err != nil {
		if errors.Is(err, instance.ErrInvalid) {
			SendError(w, r, ErrorUnauthorized())
		} else {
			// A storage/infra error isn't an auth failure: 500 so it shows as a
			// 5xx and doesn't feed the per-IP auth-failure throttle.
			SendError(w, r, ErrorInternalServerError().WithCause(err))
		}
		return
	}

	tokenApp, payload, ok := h.openEndpoint(w, r)
	if !ok {
		return
	}
	if tokenApp != inst.AppID {
		SendError(w, r, ErrorForbidden())
		return
	}
	planID := ""
	if inst.UsagePlanID.Valid {
		planID = inst.UsagePlanID.String
	}
	h.deliver(w, r, tokenApp, inst.ID, planID, payload)
}

// sendVAPID authenticates an unmodified Web Push sender (RFC 8292) against the
// VAPID key sealed into the endpoint. The endpoint is opened before the sender
// is authenticated because the key to check against lives inside it; endpoint
// tokens are unguessable, so the 404/410 this can reveal leaks nothing useful.
func (h *SendHandler) sendVAPID(w http.ResponseWriter, r *http.Request) {
	creds, err := vapid.ParseHeader(r.Header.Get("Authorization"))
	if err != nil {
		SendError(w, r, ErrorUnauthorized())
		return
	}
	tokenApp, payload, ok := h.openEndpoint(w, r)
	if !ok {
		return
	}
	if payload.VAPIDKey == "" {
		SendError(w, r, ErrorUnauthorized())
		return
	}
	if err := vapid.Verify(creds, payload.VAPIDKey, h.vapidAudience, time.Now()); err != nil {
		SendError(w, r, ErrorUnauthorized())
		return
	}
	// VAPID senders have no instance row; rate-limit them per sender key under
	// the app's default instance plan.
	sum := sha256.Sum256([]byte(payload.VAPIDKey))
	h.deliver(w, r, tokenApp, "vapid:"+hex.EncodeToString(sum[:8]), "", payload)
}

func (h *SendHandler) openEndpoint(w http.ResponseWriter, r *http.Request) (string, seal.Payload, bool) {
	tokenApp, payload, err := h.seal.Open(r.Context(), r.PathValue("token"))
	if err != nil {
		switch {
		case errors.Is(err, seal.ErrExpired):
			SendError(w, r, ErrorGone().WithMessage("endpoint expired"))
		case errors.Is(err, seal.ErrMalformed), errors.Is(err, db.ErrNotFound):
			SendError(w, r, ErrorNotFound().WithMessage("unknown endpoint"))
		default:
			SendError(w, r, ErrorInternalServerError().WithCause(err))
		}
		return "", seal.Payload{}, false
	}
	return tokenApp, payload, true
}

func (h *SendHandler) deliver(w http.ResponseWriter, r *http.Request, tokenApp, senderID, planID string, payload seal.Payload) {
	// Read the body before charging quota; a 413/disconnect can't be refunded.
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBytes)
	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			SendError(w, r, ErrorPayloadTooLarge())
		} else {
			SendError(w, r, ErrorInternalServerError().WithCause(err))
		}
		return
	}

	encoding := r.Header.Get("Content-Encoding")
	if !transport.ValidEncoding(encoding) {
		SendError(w, r, ErrorBadRequest().WithMessage("unsupported content-encoding"))
		return
	}

	if h.admit != nil {
		if ok, retry, _ := h.admit.Admit(r.Context(), tokenApp, senderID, planID); !ok {
			e := ErrorTooManyRequests()
			if retry > 0 {
				e.WithRetryAfter(retryAfterSeconds(retry))
			}
			SendError(w, r, e)
			return
		}
	}

	msg := transport.Message{
		Ciphertext: ciphertext,
		Encoding:   encoding,
		TTL:        atoiDefault(r.Header.Get("TTL"), 0),
		Urgency:    r.Header.Get("Urgency"),
		Topic:      r.Header.Get("Topic"),
	}

	res, err := h.sender.Send(r.Context(), tokenApp, payload.Transport, payload.TransportRef, transport.SendOptions{Sandbox: payload.Sandbox}, msg)
	if err != nil {
		switch {
		case errors.Is(err, transport.ErrNotConfigured):
			SendError(w, r, ErrorServiceUnavailable().WithMessage("transport not configured"))
		case errors.Is(err, transport.ErrCredentialsInvalid):
			SendError(w, r, ErrorInternalServerError().WithMessage("credential configuration error"))
		default:
			SendError(w, r, ErrorBadGateway().WithMessage("upstream error").WithCause(err))
		}
		return
	}
	switch {
	case res.Permanent:
		SendError(w, r, ErrorGone().WithMessage("endpoint gone"))
	case res.Delivered:
		SendData(w, r, http.StatusAccepted, nil)
	case res.RetryAfter > 0 || res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusServiceUnavailable:
		e := ErrorServiceUnavailable().WithMessage("upstream unavailable")
		if res.RetryAfter > 0 {
			e.WithRetryAfter(retryAfterSeconds(res.RetryAfter))
		}
		SendError(w, r, e)
	default:
		SendError(w, r, ErrorBadGateway().WithMessage("upstream rejected"))
	}
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	return h[len(p):], true
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func retryAfterSeconds(d time.Duration) string {
	secs := max(int(math.Ceil(d.Seconds())), 1)
	return strconv.Itoa(secs)
}
