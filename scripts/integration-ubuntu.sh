#!/bin/sh
set -eu

IMAGE=${1:-ubuntu:22.04}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARCH=$(docker image inspect --format '{{.Architecture}}' "$IMAGE")

case "$ARCH" in
  amd64|arm64) ;;
  *)
    echo "unsupported cached image architecture: $ARCH" >&2
    exit 1
    ;;
esac

mkdir -p "$ROOT/dist"
OUTPUT=$(mktemp -d "$ROOT/dist/ubuntu-integration.XXXXXX")

CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build \
  -trimpath -tags netgo,osusergo \
  -ldflags "-s -w -buildid= -X main.version=integration" \
  -o "$OUTPUT/procwire" "$ROOT/cmd/procwire"

CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build \
  -trimpath -tags netgo,osusergo \
  -ldflags "-s -w -buildid=" \
  -o "$OUTPUT/trafficgen" "$ROOT/integration/trafficgen"

docker run --rm --pull=never --platform "linux/$ARCH" --privileged --cgroupns=host --pid=host -t \
  -e TERM=xterm-256color \
  -v "/sys/fs/cgroup:/sys/fs/cgroup:rw" \
  -v "$OUTPUT:/work" \
  "$IMAGE" \
  /bin/sh -c '
    stty rows 36 cols 120
    rm -f /work/fixture.json /work/fixture.json.tmp
    LD_LIBRARY_PATH=/tmp/procwire-loader-check /work/trafficgen \
      --duration 9s \
      --activity-delay 6s \
      --manifest /work/fixture.json \
      --fixture-root / \
      --modify-package-file /lib/systemd/system/apt-daily.timer \
      --tcp-listeners 4 \
      --udp-listeners 3 &
    generator=$!
    attempts=0
    while [ ! -s /work/fixture.json ]; do
      if ! kill -0 "$generator" 2>/dev/null; then
        wait "$generator"
        exit $?
      fi
      attempts=$((attempts + 1))
      if [ "$attempts" -ge 100 ]; then
        echo "fixture generator did not become ready" >&2
        exit 1
      fi
      sleep 0.05
    done
    /work/procwire --duration 15s --interval 500ms --output /work/session.jsonl
    status=$?
    wait "$generator" || true
    exit "$status"
  '

go run "$ROOT/integration/verify" \
  --report "$OUTPUT/session.jsonl" \
  --binary "$OUTPUT/procwire" \
  --manifest "$OUTPUT/fixture.json"
echo "integration artifacts: $OUTPUT"
