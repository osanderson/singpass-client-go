#!/usr/bin/env bash
# Logs in with this library against a singpass-fake-server image, in each of
# docs/docker.md's setups, by running TestImage
# (cmd/singpass-fake-server/image_test.go):
#
#   1. from this machine, through the published ports
#   2. from a container sharing the fake server's network namespace, as the
#      Compose recipe does
#   3. by service name over HTTPS, trusting the fake server's test CA
#
# Each must report TestImage as passed — a skip fails, so a missing setting
# can't pass silently.
#
# Usage: scripts/fake-server-smoke.sh <image>
#
# Run it from the root of the source the image was built from, so the test
# matches the image. Needs Go and Docker, and ports 5156 and 5157 free.
set -euo pipefail

image=${1:?usage: fake-server-smoke.sh <image>}
work=$(mktemp -d)
export GOWORK=off

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    for c in fake-smoke fake-smoke-tls; do
      echo "--- docker logs $c"
      docker logs "$c" 2>&1 || true
    done
  fi
  docker rm -f fake-smoke fake-smoke-tls >/dev/null 2>&1 || true
  docker network rm fake-smoke-net >/dev/null 2>&1 || true
  docker volume rm fake-smoke-certs >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

# wait_healthy waits for container $1's health check to pass.
wait_healthy() {
  for _ in $(seq 60); do
    [[ $(docker inspect -f '{{.State.Health.Status}}' "$1") == healthy ]] && return 0
    sleep 1
  done
  echo "$1 never became healthy" >&2
  return 1
}

# expect_pass runs a TestImage command and fails unless it reports a pass.
expect_pass() {
  local out
  out=$("$@" 2>&1) || { echo "$out"; return 1; }
  echo "$out"
  grep -q -- '--- PASS: TestImage' <<<"$out" || { echo "TestImage didn't run" >&2; return 1; }
}

# The test binary for the containers: Linux, the Docker host's architecture.
case $(docker info -f '{{.Architecture}}') in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "unsupported Docker architecture" >&2; exit 1 ;;
esac
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -o "$work/smoke.test" ./cmd/singpass-fake-server
chmod 0755 "$work" "$work/smoke.test"

echo "=== 1. from this machine, through the published ports"
docker run -d --name fake-smoke -p 5156:5156 -p 5157:5157 "$image" >/dev/null
wait_healthy fake-smoke
SMOKE_SINGPASS_ISSUER=http://localhost:5156/fapi SMOKE_CORPPASS_ISSUER=http://localhost:5157 \
  expect_pass go test -count=1 -run '^TestImage$' -v ./cmd/singpass-fake-server

echo "=== 2. from a container sharing the fake server's network"
expect_pass docker run --rm --network container:fake-smoke -v "$work/smoke.test:/smoke.test:ro" \
  -e SMOKE_SINGPASS_ISSUER=http://localhost:5156/fapi -e SMOKE_CORPPASS_ISSUER=http://localhost:5157 \
  --entrypoint /smoke.test "$image" -test.run '^TestImage$' -test.v

echo "=== 3. by service name over HTTPS"
docker network create fake-smoke-net >/dev/null
docker volume create fake-smoke-certs >/dev/null
docker run -d --name fake-smoke-tls --network fake-smoke-net --network-alias singpass --network-alias corppass \
  -v fake-smoke-certs:/certs -e FAKE_TLS_CA_DIR=/certs \
  -e FAKE_SINGPASS_URL=https://singpass:5156 -e FAKE_CORPPASS_URL=https://corppass:5157 \
  "$image" >/dev/null
wait_healthy fake-smoke-tls
expect_pass docker run --rm --network fake-smoke-net -v fake-smoke-certs:/certs:ro -v "$work/smoke.test:/smoke.test:ro" \
  -e SMOKE_CA_FILE=/certs/ca.pem \
  -e SMOKE_SINGPASS_ISSUER=https://singpass:5156/fapi -e SMOKE_CORPPASS_ISSUER=https://corppass:5157 \
  --entrypoint /smoke.test "$image" -test.run '^TestImage$' -test.v

echo "=== all setups passed"
