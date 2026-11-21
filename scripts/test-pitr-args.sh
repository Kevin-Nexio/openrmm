#!/usr/bin/env bash
# Exercises the input checks of deploy/ops/restore-pitr.sh without Docker:
# every malformed value is refused before docker runs, since several of them
# end up in recovery settings that PostgreSQL executes (restore_command) or in
# volume names. A docker stand-in records each call; a request that passes the
# checks reaches it, so the refusals are not a blanket deny.
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
dir=$(mktemp -d "${TMPDIR:-/tmp}/rmm-pitr-args.XXXXXX")
trap 'rm -rf "$dir"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

mkdir "$dir/bin"
cat > "$dir/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_CALLS"
if [[ "$*" == *" config --format json" ]]; then
  cat "$COMPOSE_FIXTURE"
  exit
fi
exit 1
EOF
chmod +x "$dir/bin/docker"
cat > "$dir/compose.json" <<'EOF'
{
  "name": "pitr-layer",
  "services": {
    "postgres": {
      "volumes": [
        {"type": "volume", "source": "rmm_pgdata", "target": "/var/lib/postgresql/data"},
        {"type": "volume", "source": "rmm_pgwal", "target": "/var/lib/postgresql/wal-archive"}
      ]
    }
  },
  "volumes": {
    "rmm_pgdata": {"name": "pitr-layer_rmm_pgdata"},
    "rmm_pgwal": {"name": "pitr-layer_rmm_pgwal"}
  }
}
EOF
sed 's/"name": "pitr-layer_rmm_pgdata"/"name": "shared-data", "external": true/' \
  "$dir/compose.json" > "$dir/compose-external.json"
sed 's/"source": "rmm_pgdata"/"source": "rmm_pgdata", "volume": {"subpath": "db"}/' \
  "$dir/compose.json" > "$dir/compose-subpath.json"
printf 'not a real base backup\n' > "$dir/base.tar.gz"
(cd "$dir" && sha256sum base.tar.gz > base.tar.gz.sha256)
printf 'POSTGRES_USER=rmm\nPOSTGRES_DB=rmm\n' > "$dir/env"

# Runs restore-pitr.sh with a clean environment plus the given assignments;
# prints its stderr and leaves the docker calls in $dir/calls.
run() {
  : > "$dir/calls"
  env -i PATH="$dir/bin:/usr/bin:/bin" HOME="$dir" TMPDIR="$dir" DOCKER_CALLS="$dir/calls" COMPOSE_FIXTURE="$dir/compose.json" \
    ENV_FILE="$dir/env" RESTORE_CONFIRM=rmm "$@" \
    bash "$root/deploy/ops/restore-pitr.sh" "${archive:-$dir/base.tar.gz}" < /dev/null 2>&1 && return 1 || true
}
refused() {
  local want=$1 out; shift
  out=$(run "$@")
  [[ "$out" == *"$want"* ]] || fail "$* : got [$out], want [$want]"
  [[ ! -s "$dir/calls" ]] || fail "$* : docker ran before the refusal: $(cat "$dir/calls")"
}

refused 'PITR_TARGET_TIMELINE must be latest, current or a timeline number' PITR_TARGET_TIMELINE='1; DROP'
refused 'PITR_TARGET_TIMELINE must be latest, current or a timeline number' PITR_TARGET_TIMELINE=0
refused 'PITR_TARGET_TIMELINE must be latest, current or a timeline number' PITR_TARGET_TIMELINE="latest'"
refused "PITR_TARGET_TIME must look like" PITR_TARGET_TIME=yesterday
refused "PITR_TARGET_TIME must look like" PITR_TARGET_TIME="2026-07-27 03:20:00'; COPY x TO PROGRAM 'id'"
refused 'WAL_ARCHIVE_DIR must be an absolute path' WAL_ARCHIVE_DIR='/var/lib/wal archive'
refused 'WAL_ARCHIVE_DIR must be an absolute path' WAL_ARCHIVE_DIR="/x'; touch /tmp/pwned; '"
refused 'WAL_ARCHIVE_DIR must be an absolute path' WAL_ARCHIVE_DIR=relative/dir
refused 'invalid writer service' RESTORE_WRITER_SERVICES='server;rm'
refused 'RESTORE_WAIT_TIMEOUT must be a positive integer' RESTORE_WAIT_TIMEOUT=0
refused 'PITR_ARCHIVE_WAIT must be a positive integer' PITR_ARCHIVE_WAIT=soon
refused 'set RESTORE_CONFIRM=rmm' RESTORE_CONFIRM=
refused 'COMPOSE_PROJECT_NAME is not a valid Compose project name' COMPOSE_PROJECT_NAME='Bad Name'
refused 'COMPOSE_PROJECT_NAME is not a valid Compose project name' COMPOSE_PROJECT_NAME='../x'

printf 'tampered\n' >> "$dir/base.tar.gz"
refused 'checksum mismatch' PITR_TARGET_TIMELINE=latest
(cd "$dir" && sha256sum base.tar.gz > base.tar.gz.sha256)
ln -s "$dir/base.tar.gz" "$dir/link.tar.gz"
archive=$dir/link.tar.gz refused 'base backup must be a regular file' PITR_TARGET_TIMELINE=latest

# A valid request looks up the WAL volume in the project resolved by Compose.
out=$(run PITR_TARGET_TIME='2026-07-27 03:20:00+00' PITR_TARGET_TIMELINE=3 WAL_ARCHIVE_DIR=/var/lib/postgresql/wal-archive)
[[ "$out" == *"WAL archive volume pitr-layer_rmm_pgwal not found"* ]] || fail "a valid request did not reach the WAL volume check: $out"
grep -q '^volume inspect pitr-layer_rmm_pgwal$' "$dir/calls" || fail "a valid request did not look up the resolved WAL volume"

for layout in external subpath; do
  out=$(run COMPOSE_FIXTURE="$dir/compose-$layout.json")
  [[ "$out" == *"PITR needs project-local Compose volumes"* ]] || fail "$layout storage was not refused: $out"
  [[ "$(wc -l < "$dir/calls")" == 1 ]] || fail "$layout storage reached a volume operation"
  grep -q 'config --format json$' "$dir/calls" || fail "Compose storage was not resolved"
done

printf 'restore-pitr input checks: ok\n'
