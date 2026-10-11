#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for command in cargo curl docker jq sed; do
  if ! command -v "$command" >/dev/null; then
    echo "required command is unavailable: $command" >&2
    exit 1
  fi
done

run_id="${E_NAVIGATOR_PYROSCOPE_RUN_ID:-$$}"
container_name="e-navigator-pyroscope-otlp-${run_id}"
image_ref="${E_NAVIGATOR_PYROSCOPE_IMAGE:-grafana/pyroscope:1.20.3}"
tmp_dir="$(mktemp -d)"
created_container=false
evidence_dir="${E_NAVIGATOR_PYROSCOPE_EVIDENCE_DIR:-}"
if [[ -n "$evidence_dir" ]]; then
  # Refuse to replace previous execution evidence.
  mkdir "$evidence_dir"
fi

cleanup() {
  exit_status="$?"
  if [[ -n "$evidence_dir" ]]; then
    # Retain failed-run diagnostics too, before removing the isolated backend.
    for artifact in render.json e-navigator.log; do
      if [[ -f "$tmp_dir/$artifact" ]]; then
        cp "$tmp_dir/$artifact" "$evidence_dir/$artifact"
      fi
    done
    printf '%s\n' "$exit_status" >"$evidence_dir/exit-status.txt"
    if [[ "$created_container" == true ]]; then
      docker logs "$container_name" >"$evidence_dir/pyroscope.log" 2>&1 || true
    fi
  fi
  if [[ "$created_container" == true ]]; then
    docker rm --force "$container_name" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

if docker inspect "$container_name" >/dev/null 2>&1; then
  echo "refusing to reuse existing container: $container_name" >&2
  exit 1
fi

docker run --detach \
  --name "$container_name" \
  --publish 127.0.0.1::4040 \
  "$image_ref" >"$tmp_dir/container-id"
created_container=true

binding="$(docker port "$container_name" 4040/tcp)"
port="${binding##*:}"
base_url="http://127.0.0.1:${port}"

ready=false
for _ in $(seq 1 60); do
  if curl --fail --silent "${base_url}/ready" >/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "$ready" != true ]]; then
  docker logs "$container_name" >&2
  echo "Pyroscope did not become ready" >&2
  exit 1
fi

profiles_endpoint="${base_url}/v1development/profiles"
sed "s|__PROFILES_ENDPOINT__|${profiles_endpoint}|" \
  crates/e-navigator-cli/tests/fixtures/pyroscope-otlp-smoke.toml.in \
  >"$tmp_dir/e-navigator.toml"

CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" cargo run --locked -p e-navigator-cli -- \
  --source synthetic \
  --config "$tmp_dir/e-navigator.toml" \
  >"$tmp_dir/e-navigator.log" 2>&1

from_ms="$(( $(date +%s) * 1000 - 3600000 ))"
until_ms="$(( $(date +%s) * 1000 + 60000 ))"
curl --fail --silent --show-error --get "${base_url}/pyroscope/render" \
  --data-urlencode 'query=process_cpu:cpu:nanoseconds:cpu:nanoseconds{namespace="e-navigator-system",service_name="e-navigator-smoke",catalog_slug=""}' \
  --data-urlencode "from=${from_ms}" \
  --data-urlencode "until=${until_ms}" \
  --data-urlencode 'format=json' \
  >"$tmp_dir/render.json"

jq --exit-status '
  .flamebearer.numTicks > 0 and
  (.flamebearer.names | index("synthetic_api::checkout_handler") != null) and
  (.flamebearer.names | index("synthetic_api::deep_frame_0") != null)
' "$tmp_dir/render.json" >/dev/null

if docker logs "$container_name" 2>&1 | grep -Fq 'profile rejected'; then
  docker logs "$container_name" >&2
  echo "Pyroscope rejected an E-Navigator profile" >&2
  exit 1
fi

image_id="$(docker inspect "$container_name" --format '{{.Image}}')"
if [[ -n "$evidence_dir" ]]; then
  cp "$tmp_dir/render.json" "$evidence_dir/render.json"
  cp "$tmp_dir/e-navigator.log" "$evidence_dir/e-navigator.log"
  docker logs "$container_name" >"$evidence_dir/pyroscope.log" 2>&1
  docker image inspect "$image_id" --format '{{json .RepoDigests}}' >"$evidence_dir/image-digests.json"
  git rev-parse HEAD >"$evidence_dir/collector-commit.txt"
  date -u '+%Y-%m-%dT%H:%M:%SZ' >"$evidence_dir/executed-at.txt"
  jq --null-input --arg image_ref "$image_ref" --arg image_id "$image_id" \
    --arg from_ms "$from_ms" --arg until_ms "$until_ms" \
    '{image_ref:$image_ref,image_id:$image_id,from_ms:$from_ms,until_ms:$until_ms,query:"process_cpu:cpu:nanoseconds:cpu:nanoseconds{namespace=\"e-navigator-system\",service_name=\"e-navigator-smoke\",catalog_slug=\"\"}"}' \
    >"$evidence_dir/query.json"
fi
jq --null-input \
  --arg image_ref "$image_ref" \
  --arg image_id "$image_id" \
  --arg endpoint "$profiles_endpoint" \
  --argjson num_ticks "$(jq '.flamebearer.numTicks' "$tmp_dir/render.json")" \
  '{status:"passed", image_ref:$image_ref, image_id:$image_id, endpoint:$endpoint, num_ticks:$num_ticks}'
