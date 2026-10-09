# Configuration

PushPort is configured entirely through environment variables, with no config
file. Only two variables are required; the rest have defaults.

By default **nothing is rate-limited**: push, self-registration, and subscribe
limits are all unlimited until you set [usage plans](/guide/usage-plans).

## Reference

### Core

| Variable                | Default                       | Description                                          |
| ----------------------- | ----------------------------- | ---------------------------------------------------- |
| `PUSHPORT_ADDR`         | `:8080`                       | Listen address for the HTTP server.                  |
| `PUSHPORT_BASE_URL`     | `http://localhost:8080`       | Public base URL, baked into push endpoint URLs.      |
| `PUSHPORT_DATABASE_URI` | `sqlite://./data/pushport.db` | SQLite database URI.                                 |
| `PUSHPORT_ADMIN_TOKEN`  | **required**                  | Bearer token for admin API calls and CLI management. |
| `PUSHPORT_SECRET`       | **required**                  | Master secret: base64 of exactly 32 bytes.           |

### Networking & Proxy

| Variable                         | Default | Description                                                                                                                                                               |
| -------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PUSHPORT_CORS_ORIGIN`           | empty   | Comma-separated allowlist of browser origins permitted to call the API cross-origin.                                                                                      |
| `PUSHPORT_CLIENT_IP_HEADER`      | empty   | Header to read the client IP from for per-IP limits, e.g. `CF-Connecting-IP`. Trusted from any peer, so set it only when all traffic passes through a proxy that sets it. |
| `PUSHPORT_WEBPUSH_ALLOWED_HOSTS` | empty   | Comma-separated allowlist of WebPush endpoint targets (hostnames and/or IPs/CIDRs).                                                                                       |

The relay POSTs to the endpoint URL a WebPush subscription supplies, so by
default it only accepts **https** to **public** hosts (SSRF guard); private,
loopback, link-local, and metadata addresses are rejected, including hostnames
that resolve to them.

Set `PUSHPORT_WEBPUSH_ALLOWED_HOSTS` to allow your own internal/insecure endpoint
or local testing. Each entry is a hostname, IP, or CIDR, and bypasses both the
https and private-address checks — for example:

```
PUSHPORT_WEBPUSH_ALLOWED_HOSTS=localhost,127.0.0.1,::1
```

### Push Endpoints

| Variable                     | Default          | Description                                 |
| ---------------------------- | ---------------- | ------------------------------------------- |
| `PUSHPORT_PUSH_ENDPOINT_TTL` | `360h` (15 days) | Default lifetime of a sealed push endpoint. |
| `PUSHPORT_MAX_PAYLOAD_BYTES` | `3000`           | Maximum request body size for a push send.  |
| `PUSHPORT_ALLOW_VAPID`       | `false`          | Let devices bind a sender's VAPID key to their endpoint, so unmodified Web Push servers can send without an instance token. See [VAPID senders](/guide/sending#vapid-senders). |

Endpoint TTLs must fall within a fixed window of **12 hours to 45 days**: a
client requesting a TTL outside it is rejected, and `PUSHPORT_PUSH_ENDPOINT_TTL`
must also be within the window or the server refuses to start.

### Self-Registration and Subscribe Limits

These limits start at **0 (unlimited)**, so unless you set up a
[usage plan](/guide/usage-plans) nothing throttles sign-ups or device
subscribes. Retry and auth-failure limits keep their protective defaults either
way.

You set them through a usage plan, either over the API (`POST`/`PATCH
/usage-plans`) or with the CLI:

```sh
pushport usage-plan app update <plan_id> \
  --register-per-min 10 --register-burst 5 \
  --register-ip-per-min 5 --register-ip-burst 3 \
  --subscribe-per-min 30 --subscribe-burst 15
```

### Upstream Delivery

Retry and auth-failure limits are stored in the database and can be adjusted at runtime without restarting via `PATCH /settings` or the CLI:

```sh
pushport settings get
pushport settings set --auth-fail-ip-per-min 5 --auth-fail-ip-burst 5 \
  --retry-max-attempts 3 --retry-base-backoff 200ms --retry-max-backoff 5s
```

| Variable                        | Default | Description                             |
| ------------------------------- | ------- | --------------------------------------- |
| `PUSHPORT_QUOTA_FLUSH_INTERVAL` | `30s`   | How often quota counts flush to SQLite. |

## Secret Rotation

`PUSHPORT_SECRET` accepts a comma-separated list of 32-byte base64 keys. The
**first** key is the primary (it seals all new data); the remaining keys
are kept only to open existing blobs:

```sh
# 1. generate a new key once, and store it in your secret manager
openssl rand -base64 32

# 2. rotate: new key first, current key second
export PUSHPORT_SECRET="<new-key>,<current-key>"
```

Restart with the new list and everything is re-sealed transparently as data is
rewritten. Once you are confident no stale blobs remain, drop the old key.

Push endpoints additionally have their own per-app
[endpoint key](/guide/apps#rotating-the-endpoint-key) with a grace window, so
endpoint rotation does not require touching `PUSHPORT_SECRET` at all.
