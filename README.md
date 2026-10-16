# ocpp-auth-rs

A forward-auth service implementing the OCPP 2.0.1 Basic Authentication security
profile (Security Profile 1). It runs behind Traefik: the proxy sends every
`/ocpp/*` request to this service for an allow/deny decision before the WebSocket
connection reaches the charging-station backend. Credentials are not configured
here — they are streamed from a compacted Kafka topic maintained by the
charging-management system, so station onboarding, password rotation, and
decommissioning take effect without restarting or reconfiguring this service.

## Architecture

```
charging station ──> Traefik ──[auth request]──> ocpp-auth-rs
                        │                             │
                        │<──────── 200 / 401 ─────────´
                        ├── 200: forward to OCPP backend (WebSocket)
                        └── 401: reject

Kafka (compacted topic) ──> consumer thread ──> in-memory credential store
```

- Traefik's `forwardAuth` middleware calls this service on every request to the
  OCPP endpoint; a `200` lets the request through, a `401` (with
  `WWW-Authenticate: Basic realm="ocpp"`) makes Traefik reject it.
- The station id is taken from the request path `/ocpp/{stationId}`, or, when
  present, from the `X-Forwarded-Uri` header Traefik adds (query string is
  stripped). Anything that is not a two-segment `/ocpp/{id}` path is rejected.
- The `Authorization: Basic` username must equal the station id from the path;
  the password is verified against the stored bcrypt hash.
- Verifications run on blocking threads and are bounded by a semaphore
  (`BCRYPT_CONCURRENCY`) so a credential-stuffing flood cannot saturate the host
  with hashing work.

## Endpoints

| Port | Env var (default) | Route | Purpose |
| --- | --- | --- | --- |
| Auth | `PORT` (8080) | any request | Forward-auth check; fallback handler for the whole router. `200` allow, `401` deny, `429` rate-limited (`Retry-After: 1`). |
| Admin | `ADMIN_PORT` (8081) | `GET /healthz` | Liveness; `200` whenever the process is up. |
| Admin | | `GET /readyz` | Readiness; `200` once the initial read of the Kafka topic has been applied, `503` before. |
| Admin | | `GET /metrics` | Prometheus text-format metrics. |

The admin endpoints live on a separate port so they stay unreachable even when
the auth port is exposed directly.

## Configuration

All settings come from the environment and are parsed and validated once at
startup; invalid configuration aborts with an error.

| Variable | Default | Notes |
| --- | --- | --- |
| `KAFKA_BROKERS` | — | Comma-separated bootstrap servers. Required, non-empty. |
| `OCPP_AUTH_TOPIC` | — | Compacted topic carrying credential updates. Required, non-empty. |
| `PORT` | `8080` | Forward-auth listen port; must be a valid port number. |
| `ADMIN_PORT` | `8081` | Health/metrics listen port; must be a valid port number. |
| `RATE_LIMIT_PER_SECOND` | `2.0` | Auth token refill per second per station; non-negative finite number. |
| `RATE_LIMIT_BURST` | `10.0` | Auth token bucket capacity per station; at least `1.0` (below that every request would be rejected). |
| `RATE_LIMIT_IP_PER_SECOND` | `20.0` | Auth token refill per second per client IP; non-negative finite number. |
| `RATE_LIMIT_IP_BURST` | `50.0` | Auth token bucket capacity per client IP; at least `1.0`. |
| `BCRYPT_CONCURRENCY` | CPU count | Simultaneous bcrypt verifications; positive whole number, at least 1. |

Logging uses `tracing` with an `EnvFilter` from `RUST_LOG` (default `info`).

## Credential messages

The topic is compacted; each message's **key is the station id** and the value
is JSON:

```json
{"authenticationType": "BASIC", "password": "$2b$10$..."}
```

| `authenticationType` | Meaning at this service |
| --- | --- |
| `BASIC` | Verify the supplied password against the bcrypt hash in `password`. |
| `NONE` | Deny. Stations with no security profile are expected to be routed by the proxy *without* a forward-auth call; if such a request does reach this service, there is no credential to check, so it is rejected. |
| `FORBIDDEN` | Deny — an explicit block (e.g. decommissioned or suspended station). |

- A **tombstone** (null value) removes the station; subsequent requests for it
  are rejected as unknown.
- `password` must be a syntactically valid bcrypt hash
  (`$2$`/`$2a$`/`$2b$`/`$2y$`, two-digit cost, 53 salt+hash characters) with a
  **cost factor of at most 15** (`MAX_BCRYPT_COST`). Verification time doubles
  per increment, so an unbounded cost from a faulty or compromised producer
  could block a verification thread for minutes.
- Invalid messages — bad JSON, unknown `authenticationType`, `BASIC` without a
  password or with an invalid/too-expensive hash, missing or non-UTF-8 key —
  are skipped with a warning; the previous store entry is left untouched.
- Readiness flips once every assigned partition has been consumed to its high
  watermark. An empty assignment or an empty topic is **not** ready.

## Operational behaviour / runbook

**Startup.** The service binds both ports immediately, but `/readyz` returns
`503` until the initial topic read is applied — keep stations out of rotation
until the credential state is complete. An empty topic means the service never
becomes ready; check that `OCPP_AUTH_TOPIC` exists and is the right name.

**Kafka outage after ready.** The consumer retries; the credential store keeps
serving the last known state, so authentication continues on stale-but-valid
credentials. Alert on `ocpp_auth_kafka_errors_total` increasing and on
`ocpp_auth_kafka_last_message_timestamp_seconds` growing stale — with the caveat
that a compacted topic with no changes legitimately leaves the timestamp old.

**Shutdown.** SIGTERM or Ctrl-C triggers graceful shutdown: both listeners stop
accepting and drain in-flight requests, then the consumer thread is stopped.

**Rate limiting.** Token buckets per station (default 2/s, burst 10) and per
client IP (default 20/s, burst 50), keyed by the first entry of
`X-Forwarded-For`; requests without that header (direct dev calls) skip the IP
check. Exceeding either bucket returns `429` with `Retry-After: 1`. Buckets are
capped at 10 000 keys; idle-full buckets are evicted, and if every key is
active the limiter fails open (the bcrypt semaphore still bounds CPU).

## Metrics

| Metric | Meaning |
| --- | --- |
| `ocpp_auth_requests_total{result="success\|failure\|rate_limited"}` | Auth decisions by outcome. |
| `ocpp_auth_known_stations` | Stations currently present in the credential store. |
| `ocpp_auth_kafka_last_message_timestamp_seconds` | Unix seconds of the last consumed Kafka message; only advances when messages arrive. |
| `ocpp_auth_kafka_errors_total` | Kafka poll errors. |

## Security notes

- bcrypt cost is capped at 15 at ingestion, so no stored credential can make a
  verification arbitrarily expensive.
- Concurrent bcrypt work is bounded by `BCRYPT_CONCURRENCY`.
- Per-station and per-IP rate limits: one host cannot burn a known station's
  bucket to lock out its reconnects, and spraying random station ids exhausts
  the attacker's own IP bucket instead of the limiter's key budget.
- Every rejection path (unknown station, `NONE`, `FORBIDDEN`, username mismatch,
  malformed hash) runs a bcrypt verification against a dummy hash of the same
  cost, so responses take approximately the same time and attackers get no
  timing oracle to enumerate valid station ids.
- Passwords are only ever held as bcrypt hashes, in memory.

## Development

```sh
cargo test                       # unit tests + testcontainers integration (needs Docker)
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

CI (`.github/workflows/rust.yml`) runs build + tests, fmt/clippy, the E2E
suite, and `cargo audit`.

**E2E:** `bash e2e/run_e2e.sh` builds the image and brings up the full
docker-compose stack (Kafka, Traefik, a mock backend, this service), produces a
keyed credential message, and asserts 200/401 behaviour through Traefik, the
`WWW-Authenticate` header, and clean exit on SIGTERM.

**Load test (manual, not in CI):** `bash e2e/run_loadtest.sh` runs k6 against
the same stack through Traefik, measuring the accept path (correct password)
and the reject path (wrong password — still a full bcrypt verification).
Overrides: `LOADTEST_CONCURRENCY` (16), `LOADTEST_DURATION` (30s),
`LOADTEST_PASSWORD` (`loadtestpassword`), `LOADTEST_K6_IMAGE`. The script
raises the rate limits to effectively unlimited via the compose env passthrough
so the limiter does not mask raw throughput.

Reference numbers from a 2026-10 run on the dev machine (28 cores, stack
co-located, cost-10 bcrypt, 16 VUs, limits raised): ~16 req/s steady state,
p95 ~1.0 s, essentially identical for the accept and reject paths. These are
environment-dependent and dominated by bcrypt cost — treat them as an example,
not a target.

## Deployment

The `Dockerfile` is multi-stage (`rust:1.98` builder → `debian:trixie-slim`)
and exposes 8080 (auth) and 8081 (admin). Minimum runtime environment:

```sh
KAFKA_BROKERS=kafka:9092 OCPP_AUTH_TOPIC=ocpp-auth-stations ./ocpp-auth-rs
```

Expose only the auth port to the proxy; the admin port serves `/metrics` and
health state and must not be publicly reachable.
