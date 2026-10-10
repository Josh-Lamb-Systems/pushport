# Sending Pushes

Sending a push is one POST: the encrypted payload goes to the device's push endpoint,
authenticated with your instance token. The payload uses `aes128gcm` content
encryption (RFC 8291/8188).

## Push Request

```
POST /push/{endpoint_token}
Authorization: Bearer pit_...
Content-Encoding: aes128gcm
TTL: 86400
Urgency: normal
Topic: chat-message

<binary ciphertext>
```

| Piece              | Meaning                                                                                                                                 |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| Endpoint URL       | The sealed endpoint the device shared with your backend.                                                              |
| `Authorization`    | Your instance token (`pit_…`) as a bearer token.                                                                                       |
| Body               | The encrypted payload.                                                                                                                  |
| `Content-Encoding` | Must be `aes128gcm`.                                                                                                                    |
| `TTL`              | Seconds the push stays relevant. Mapped to `apns-expiration` / FCM `ttl`.                                                               |
| `Urgency`          | `very-low` / `low` / `normal` / `high`. Mapped to `apns-priority` / FCM `priority`.                                                     |
| `Topic`            | Collapse key. Mapped to `apns-collapse-id` / FCM `collapse_key`.                                                                        |

The body is capped at `PUSHPORT_MAX_PAYLOAD_BYTES` (3000 bytes by default,
safely inside the 4 KB APNs payload limit).

## VAPID Senders

Many self-hosted backends already speak standard Web Push (RFC 8030) and
authenticate with VAPID (RFC 8292) rather than a relay-specific token. With
`PUSHPORT_ALLOW_VAPID=true`, such a backend can push to PushPort unmodified:

1. The device fetches the backend's VAPID public key and passes it as
   `vapid_key` when it [subscribes](/guide/instances#subscribing-a-device).
2. The device gives the backend the endpoint plus its `p256dh` and `auth` keys,
   exactly as a browser would.
3. The backend sends a normal Web Push request:

```
POST /push/{endpoint_token}
Authorization: vapid t=<JWT>, k=<backend VAPID public key>
Content-Encoding: aes128gcm
TTL: 86400

<binary ciphertext>
```

PushPort accepts it only when `k` equals the key sealed into that endpoint, the
JWT is ES256-signed by that key, its `aud` is this relay's origin (from
`PUSHPORT_BASE_URL`), and its `exp` is in the future and at most 24 hours
away. Anything else is `401`. Endpoints subscribed without `vapid_key` never
accept VAPID, and instance tokens keep working on every endpoint.

VAPID senders have no instance, so there is no per-backend kill switch: rate
limits and daily quotas apply per VAPID key under the app's default instance
plan, and their pushes count toward the app's totals in stats.

## Delivery Pipeline

1. **Authenticates** the instance token: `401` if invalid.
2. **Opens the sealed endpoint**: `404` unknown, `410` expired.
3. **Checks the app match**: `403` if the token belongs to another app.
4. **Enforces [usage plans](/guide/usage-plans)**: `429` with `Retry-After`
   when a per-min limit or daily quota is hit.
5. **Forwards** to the endpoint's platform with bounded retry + backoff on
   transient upstream errors (`5xx`, `429`).

Delivery is a synchronous forward. APNs, FCM, and WebPush services
already do store-and-forward for offline devices, so PushPort keeps no queue.

## Responses

Success is `202`. Errors use the standard [envelope](/guide/api#response-envelope)
and the shared [error codes](/guide/api#error-codes). Handle `410` specially: the
endpoint is permanently dead, so delete the subscription server-side and let the
device re-register on its next launch.
