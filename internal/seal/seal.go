package seal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/MunifTanjim/pushport/internal/app"
	"github.com/MunifTanjim/pushport/internal/crypto"
)

var (
	ErrMalformed = errors.New("seal: malformed token")
	ErrExpired   = errors.New("seal: token expired")
)

type Payload struct {
	Transport    string `json:"t"`
	TransportRef string `json:"r"`
	Exp          int64  `json:"e"`
	JTI          string `json:"j"`
	Sandbox      bool   `json:"sb,omitempty"`
	// VAPIDKey, when set, is the canonical base64url P-256 public key of the
	// application server allowed to send to this endpoint with VAPID auth.
	VAPIDKey string `json:"vk,omitempty"`
}

type Service struct{ apps *app.Service }

func NewService(a *app.Service) *Service { return &Service{apps: a} }

func (svc *Service) Seal(ctx context.Context, appID string, p Payload) (string, error) {
	// A sealed push URL is a bearer credential: whoever holds it can send to that
	// device, so a positive expiry bounds a leaked URL's lifetime. Refuse to mint
	// a non-expiring token.
	if p.Exp <= 0 {
		return "", errors.New("seal: expiry required")
	}
	mkid, ver, key, err := svc.apps.CurrentKey(ctx, appID)
	if err != nil {
		return "", err
	}
	pt, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sealed, err := crypto.AEADSeal(key, pt, []byte(appID))
	if err != nil {
		return "", err
	}
	return appID + "." + mkid + "." + strconv.Itoa(ver) + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (svc *Service) Open(ctx context.Context, token string) (string, Payload, error) {
	parts := strings.SplitN(token, ".", 4)
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return "", Payload{}, ErrMalformed
	}
	appID, mkid := parts[0], parts[1]
	ver, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", Payload{}, ErrMalformed
	}
	sealed, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", Payload{}, ErrMalformed
	}
	key, err := svc.apps.SealingKey(ctx, appID, mkid, ver)
	if err != nil {
		if errors.Is(err, app.ErrKeyRevoked) || errors.Is(err, app.ErrUnknownKID) {
			return "", Payload{}, ErrExpired
		}
		return "", Payload{}, err
	}
	pt, err := crypto.AEADOpen(key, sealed, []byte(appID))
	if err != nil {
		return "", Payload{}, ErrMalformed
	}
	var p Payload
	if err := json.Unmarshal(pt, &p); err != nil {
		return "", Payload{}, ErrMalformed
	}
	// Fail closed: a missing/zero expiry (Exp <= 0) is treated as expired, never as
	// "never expires" — Seal refuses to mint such tokens, so this only ever rejects
	// a malformed or tampered one.
	if time.Now().Unix() > p.Exp {
		return "", Payload{}, ErrExpired
	}
	return appID, p, nil
}
