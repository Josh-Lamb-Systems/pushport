# Instances & Devices

Two kinds of clients connect to an app: **instances** (self-hosted backends
that send pushes) and **devices** (app installations that receive them).

## Registering an Instance

An instance is one self-hosted backend. Registration mints an **instance
token** with the `pit_` prefix, the only credential a backend needs to send
pushes. It is shown once; the backend should store it in its own secret
manager.

### By the App Owner

```sh
pushport instance create --label "alice's homelab"
# ID       TOKEN (shown once)
# d4e5...  pit_...
```

### Self-Registration

Public apps let anyone register a backend at:

```
GET /apps/{app_id}/instances/register
```

Opening it serves an HTML form (with a [Turnstile](#turnstile) widget when
configured); submitting it creates the instance and shows its `pit_` token once.
For programmatic registration, see the [API reference](/guide/api).

Self-registration is rate-limited per app and only works on
[public apps](/guide/apps#visibility-public-vs-private). Private apps accept
instance creation only from the admin or the app's own token.
Rate limits default to unlimited and are configured via
[usage plans](/guide/usage-plans).

## Managing Instances

Deleting an instance (or rotating its token with `pushport instance
rotate-token`) instantly revokes its send capability; that's your kill switch
for a misbehaving self-hoster. Instances can also carry a
[usage plan](/guide/usage-plans) for tighter limits than the app default. See
the [CLI reference](/guide/cli) for the full command set.

## Subscribing a Device

Devices never get accounts and never appear in the database. Instead, a device
**subscribes** and receives a sealed _push endpoint_: an unguessable URL
that self-describes where the push should go.

```
POST /apps/{app_id}/subscribe
Content-Type: application/json

{
  "transport": "apns" | "fcm" | "webpush",
  "token": "…",
  "ttl": "360h"
}
```

- **apns**: `token` is the APNs device token from the OS.
- **fcm**: `token` is the FCM registration token.
- **webpush**: `token` is the WebPush service endpoint URL from the
  Push API subscription.
- `ttl` is optional (a Go duration string). Default and bounds come from the
  relay config: default 15 days, clamped to 12 hours to 45 days.
- `sandbox` is optional (APNs only). Set it to `true` to route this endpoint
  through the APNs **sandbox** environment; the default is `false`
  (production). The flag is sealed into the endpoint, so it's fixed for the
  endpoint's lifetime. Sandbox builds of your app should subscribe with
  `sandbox: true`.
- `vapid_key` is optional and needs `PUSHPORT_ALLOW_VAPID=true` on the relay.
  It is the backend's VAPID public key (base64url, uncompressed P-256, as
  served by the backend's Web Push config). It is sealed into the endpoint,
  and that backend may then send with standard VAPID auth instead of an
  instance token. See [VAPID senders](/guide/sending#vapid-senders).

The response:

```json
{
  "request_id": "…",
  "data": {
    "endpoint": "https://push.example.com/push/a1b2c3…",
    "expires_at": 1795872000
  }
}
```

The endpoint URL is unguessable and self-contained: it cannot be enumerated, it
expires, and holding it is what lets a backend address that one device. Sending
through it still requires a valid instance token (see [Sending](/guide/sending)).

### Sharing the subscription with the backend

The device shares **three things** with the backend it trusts (via the app's
normal account-linking flow):

1. the `endpoint` URL
2. its `p256dh` public key
3. its `auth` secret

On web, the browser generates these keys; on iOS/Android the app generates a
P-256 keypair and stores the private key in Keychain/Keystore. **The private key
and `auth` secret never touch the relay**; encryption is end-to-end between
backend and device.

### Re-subscription

Endpoints expire (`expires_at`). Devices should re-register on app launch, on
a refresh timer, and before expiry; each registration returns a fresh
endpoint to re-share. When a send returns [`410 Gone`](/guide/sending#responses),
the backend should stop using that endpoint until the device re-registers.

## Turnstile

For public apps, [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
can gate self-registration to discourage bots:

```sh
pushport turnstile set \
  --site-key "0x4AAAA..." \
  --secret-key "0x4AAAA..."
pushport turnstile get
pushport turnstile rm
```

Once configured, the registration page renders the widget and
`POST /apps/{app_id}/instances` requires a valid `turnstile_token`. Missing or
failed challenges get `403`, and if Cloudflare itself is unreachable the relay
rejects the request with `503` rather than letting it through unverified.
