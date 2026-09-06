#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/e2e/docker-compose.yml"

IMAGE="ocpp-auth-rs:e2e"
TOPIC="ocpp-auth-stations"
STATION_ID="AL1000"
PASSWORD="testpassword"
AUTH_URL="http://127.0.0.1:18080"
TRAEIFIK_URL="http://127.0.0.1:80"
TAB="$(printf '\t')"

cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  . "$HOME/.cargo/env"
fi

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*"
  exit 1
}

wait_for() {
  local timeout_seconds="$1"
  local description="$2"
  shift 2
  local deadline=$((SECONDS + timeout_seconds))
  while ! "$@"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "timed out after ${timeout_seconds}s waiting for: ${description}"
    fi
    sleep 2
  done
  echo "ok: ${description}"
}

kafka_is_healthy() {
  [ "$(docker inspect --format '{{.State.Health.Status}}' ocpp-e2e-kafka 2>/dev/null)" = "healthy" ]
}

auth_is_up() {
  curl -sf -o /dev/null "${AUTH_URL}/healthz"
}

traefik_is_up() {
  [ "$(curl -s -o /dev/null -w '%{http_code}' "${TRAEIFIK_URL}/" || true)" != "000" ]
}

station_is_known() {
  curl -sf "${AUTH_URL}/metrics" | grep -q '^ocpp_auth_known_stations 1$'
}

http_code() {
  curl -s -o /dev/null -w '%{http_code}' "$@" || true
}

FAILURES=0

check() {
  local description="$1"
  local expected="$2"
  local actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: ${description} (got ${actual})"
  else
    echo "FAIL: ${description} (expected ${expected}, got ${actual})"
    FAILURES=$((FAILURES + 1))
  fi
}

echo "==> Cleaning up any leftover E2E containers"
compose down -v --remove-orphans >/dev/null 2>&1 || true

echo "==> Building Docker image ${IMAGE}"
docker build -t "$IMAGE" .

echo "==> Starting E2E stack"
compose up -d

echo "==> Waiting for kafka to be healthy"
wait_for 240 "kafka broker to be healthy" kafka_is_healthy

echo "==> Waiting for ocpp-auth-rs /healthz"
wait_for 120 "ocpp-auth-rs /healthz to return 200" auth_is_up

echo "==> Waiting for traefik to answer on port 80"
wait_for 60 "traefik to answer on port 80" traefik_is_up

echo "==> Creating compacted topic ${TOPIC}"
docker exec ocpp-e2e-kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 \
  --create --topic "$TOPIC" --partitions 1 --replication-factor 1 \
  --config cleanup.policy=compact

echo "==> Computing bcrypt hash (cost 10) of the test password"
cargo build --release --manifest-path e2e/bcrypt-hash/Cargo.toml
BCRYPT_HASH="$(e2e/bcrypt-hash/target/release/bcrypt-hash "$PASSWORD")"

echo "==> Producing keyed credential message for station ${STATION_ID}"
VALUE="{\"authenticationType\":\"BASIC\",\"password\":\"${BCRYPT_HASH}\"}"
printf '%s\t%s\n' "$STATION_ID" "$VALUE" | docker exec -i ocpp-e2e-kafka /opt/kafka/bin/kafka-console-producer.sh \
  --bootstrap-server localhost:9092 \
  --topic "$TOPIC" \
  --property parse.key=true \
  --property "key.separator=${TAB}"

echo "==> Waiting for ocpp-auth-rs to pick up the credential"
wait_for 120 "ocpp_auth_known_stations to reach 1" station_is_known

echo "==> Running assertions against traefik at ${TRAEIFIK_URL}"
VALID_CODE="$(http_code -u "${STATION_ID}:${PASSWORD}" "${TRAEIFIK_URL}/ocpp/${STATION_ID}")"
check "valid credentials return 200" "200" "$VALID_CODE"
VALID_BODY="$(curl -s -u "${STATION_ID}:${PASSWORD}" "${TRAEIFIK_URL}/ocpp/${STATION_ID}" || true)"
check "valid credentials are forwarded to the mock backend" "backend-ok" "$VALID_BODY"

INVALID_CODE="$(http_code -u "${STATION_ID}:wrongpassword" "${TRAEIFIK_URL}/ocpp/${STATION_ID}")"
check "wrong password returns 401" "401" "$INVALID_CODE"
INVALID_HEADERS="$(curl -s -D - -o /dev/null -u "${STATION_ID}:wrongpassword" "${TRAEIFIK_URL}/ocpp/${STATION_ID}" || true)"
if printf '%s\n' "$INVALID_HEADERS" | grep -qi '^WWW-Authenticate:'; then
  echo "PASS: wrong password response includes WWW-Authenticate header"
else
  echo "FAIL: wrong password response includes WWW-Authenticate header"
  FAILURES=$((FAILURES + 1))
fi

UNKNOWN_CODE="$(http_code -u "ZZZZ:whatever" "${TRAEIFIK_URL}/ocpp/ZZZZ")"
check "unknown station returns 401" "401" "$UNKNOWN_CODE"

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "E2E RESULT: PASS (all assertions succeeded)"
else
  echo "E2E RESULT: FAIL (${FAILURES} assertion(s) failed)"
  exit 1
fi
