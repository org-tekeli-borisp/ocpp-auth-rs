#!/usr/bin/env bash
# MANUAL load test for the traefik + ocpp-auth-rs stack. NOT wired into CI.
#
# Measures auth throughput and latency through the full forward-auth path
# (traefik -> ocpp-auth-rs bcrypt verification -> mock backend) using k6,
# for two scenarios: correct password and wrong password (both exercise the
# bcrypt verify path, on acceptance and rejection respectively).
#
# Usage:
#   bash e2e/run_loadtest.sh
#
# Environment overrides:
#   LOADTEST_PASSWORD     password for station AL1000 (default: loadtestpassword)
#   LOADTEST_CONCURRENCY  k6 virtual users (default: 16)
#   LOADTEST_DURATION     k6 duration per scenario (default: 30s)
#   LOADTEST_K6_IMAGE     docker image running k6 (default: grafana/k6)
#
# The stack is started with very high rate-limiter values (passed through by
# docker-compose.yml) so the limiter does not mask raw auth throughput.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/e2e/docker-compose.yml"

IMAGE="ocpp-auth-rs:e2e"
TOPIC="ocpp-auth-stations"
STATION_ID="AL1000"
PASSWORD="${LOADTEST_PASSWORD:-loadtestpassword}"
WRONG_PASSWORD="wrong-${PASSWORD}"
ADMIN_URL="http://127.0.0.1:18081"
TRAEFIK_URL="http://127.0.0.1:80"
CONCURRENCY="${LOADTEST_CONCURRENCY:-16}"
DURATION="${LOADTEST_DURATION:-30s}"
K6_IMAGE="${LOADTEST_K6_IMAGE:-grafana/k6}"
TAB="$(printf '\t')"

# Start the service with limiters effectively switched off. The compose file
# interpolates these with the service's normal defaults, so only this script
# (and anyone exporting them manually) sees the high values.
export RATE_LIMIT_PER_SECOND=1000000
export RATE_LIMIT_BURST=1000000
export RATE_LIMIT_IP_PER_SECOND=1000000
export RATE_LIMIT_IP_BURST=1000000

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
  # stderr so the message survives command substitution around run_k6
  echo "FAIL: $*" >&2
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
  curl -sf -o /dev/null "${ADMIN_URL}/healthz"
}

auth_is_ready() {
  curl -sf -o /dev/null "${ADMIN_URL}/readyz"
}

traefik_is_up() {
  [ "$(curl -s -o /dev/null -w '%{http_code}' "${TRAEFIK_URL}/" || true)" != "000" ]
}

station_is_known() {
  curl -sf "${ADMIN_URL}/metrics" | grep -q '^ocpp_auth_known_stations 1$'
}

http_code() {
  curl -s -o /dev/null -w '%{http_code}' "$@" || true
}

echo "==> Load test configuration"
echo "    station=${STATION_ID} concurrency=${CONCURRENCY} duration=${DURATION}"
echo "    k6 image=${K6_IMAGE} target=${TRAEFIK_URL}/ocpp/${STATION_ID}"
echo "    rate limits raised to ${RATE_LIMIT_PER_SECOND}/s (burst ${RATE_LIMIT_BURST}) per station, ${RATE_LIMIT_IP_PER_SECOND}/s (burst ${RATE_LIMIT_IP_BURST}) per IP"

echo "==> Cleaning up any leftover E2E containers"
compose down -v --remove-orphans >/dev/null 2>&1 || true

echo "==> Building Docker image ${IMAGE}"
docker build -t "$IMAGE" .

echo "==> Building mock backend image"
compose build mock-backend

echo "==> Starting stack with high rate limits"
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

echo "==> Waiting for ocpp-auth-rs /readyz (initial topic read complete)"
wait_for 120 "ocpp-auth-rs /readyz to return 200" auth_is_ready

echo "==> Computing bcrypt hash (cost 10) of the load test password"
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

echo "==> Preflight: checking the two scenarios behave as expected"
PREFLIGHT_OK_CODE="$(http_code -u "${STATION_ID}:${PASSWORD}" "${TRAEFIK_URL}/ocpp/${STATION_ID}")"
[ "$PREFLIGHT_OK_CODE" = "200" ] || fail "preflight: expected 200 for correct password, got ${PREFLIGHT_OK_CODE}"
PREFLIGHT_BAD_CODE="$(http_code -u "${STATION_ID}:${WRONG_PASSWORD}" "${TRAEFIK_URL}/ocpp/${STATION_ID}")"
[ "$PREFLIGHT_BAD_CODE" = "401" ] || fail "preflight: expected 401 for wrong password, got ${PREFLIGHT_BAD_CODE}"
echo "ok: preflight (200 for correct password, 401 for wrong password)"

echo "==> Making sure the k6 image ${K6_IMAGE} is available"
if ! docker image inspect "$K6_IMAGE" >/dev/null 2>&1; then
  if ! docker pull "$K6_IMAGE"; then
    fail "could not pull k6 image '${K6_IMAGE}'; re-run with a working image via LOADTEST_K6_IMAGE"
  fi
fi

# NOTE: the hey docker images in circulation (e.g. williamyeh/hey) silently
# ignore -a and send no Authorization header (verified against a socket
# listener), so this script uses the official grafana/k6 image instead.
run_k6() {
  local description="$1"
  local password="$2"
  local expected_status="$3"
  local script
  local output
  script="$(mktemp "${TMPDIR:-/tmp}/loadtest-XXXXXX.js")"
  # The password is interpolated into a single-quoted JS string; keep test
  # passwords free of single quotes and backslashes.
  cat > "$script" <<EOF
import http from 'k6/http';
import encoding from 'k6/encoding';
import { check } from 'k6';

export const options = {
  vus: ${CONCURRENCY},
  duration: '${DURATION}',
};

const authorization = 'Basic ' + encoding.b64encode('${STATION_ID}:${password}');

export default function () {
  const response = http.get('${TRAEFIK_URL}/ocpp/${STATION_ID}', {
    headers: { Authorization: authorization },
  });
  check(response, { 'status is expected': (r) => r.status === ${expected_status} });
}
EOF
  # k6 reports failed checks in the summary; a missing summary means the run
  # itself broke (transport errors, bad script) and should abort the suite.
  output="$(docker run --rm --network host -i "$K6_IMAGE" run - < "$script" 2>&1 || true)"
  rm -f "$script"
  printf '%s\n' "$output" | grep -q 'http_reqs' \
    || fail "${description}: k6 produced no summary; output was: ${output}"
  printf '%s\n' "$output" | grep -E '^\s*(checks|http_req_duration|http_reqs)\b.*:' || true
  if printf '%s\n' "$output" | grep -qE '✗\s*[1-9]'; then
    echo "WARN: ${description}: some responses had an unexpected status (see checks above)"
  fi
}

echo
echo "======================================================================"
echo "Scenario A: correct password (bcrypt verify, acceptance path)"
echo "======================================================================"
run_k6 "Scenario A" "$PASSWORD" 200

echo
echo "======================================================================"
echo "Scenario B: wrong password (bcrypt verify, rejection path)"
echo "======================================================================"
run_k6 "Scenario B" "$WRONG_PASSWORD" 401

echo
echo "==> Service metrics after the load (cross-check against k6 totals)"
curl -sf "${ADMIN_URL}/metrics" | grep -E '^ocpp_auth_requests_total|^ocpp_auth_known_stations' || fail "could not read metrics from ${ADMIN_URL}/metrics"

echo
echo "==> Interpretation hints"
cat <<EOF
    * The expected bottleneck is bcrypt: each verification costs 2^cost rounds
      (cost 10 here) and at most BCRYPT_CONCURRENCY verifications run in
      parallel inside the container (default: the host CPU count, $(nproc) here).
      Expect throughput near BCRYPT_CONCURRENCY / single-verify-time, with
      latency growing as requests queue on that semaphore.
    * Scenario B should look similar to A: a wrong password still requires a
      full bcrypt verification before the 401.
    * Rate limiting was raised out of the way for this run; production traffic
      is limited to 2/s per station and 20/s per IP by default.
EOF

echo
echo "LOADTEST RESULT: DONE"
