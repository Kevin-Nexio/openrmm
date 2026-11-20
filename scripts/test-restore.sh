#!/usr/bin/env bash
# Exercises deploy/ops/backup.sh, verify-backup.sh and restore.sh end to end on
# a throwaway Compose project laid out like a QUICKSTART install: a base file
# where the writers are built from source, and a second file, listed after it
# in COMPOSE_FILE in the env file, that swaps the build for a ready image (as
# docker-compose.images.yml does). restore.sh must restart the writers from
# that image. The scripts used to read the base file alone, tried to build,
# and left the application stopped. The data comes back as it was at the
# backup. Needs Docker with Compose 2.24 or later (for !reset).
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ops=$root/deploy/ops
# shellcheck disable=SC2016 # a literal ${...} in docker-compose.prod.yml
image=$(sed -n 's/^.*&postgres-image \${POSTGRES_IMAGE:-\(.*\)}$/\1/p' "$root/deploy/docker-compose.prod.yml")
[[ -n "$image" ]] || { echo "FAIL: cannot read the postgres image from docker-compose.prod.yml" >&2; exit 1; }
dir=$(mktemp -d "${TMPDIR:-/tmp}/rmm-restore.XXXXXX")
project=rmm-restore-test-$$
env_file=$dir/env
unset COMPOSE_FILE COMPOSE_PATH_SEPARATOR COMPOSE_PROJECT_NAME
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
dc() { docker compose --env-file "$env_file" -f "$dir/base.yml" -f "$dir/images.yml" "$@"; }
cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$dir"
}
trap cleanup EXIT

# The base file builds the writers from a context that does not exist here,
# like docker-compose.prod.yml outside a source checkout.
cat > "$dir/base.yml" <<EOF
services:
  postgres:
    image: $image
    user: "70:70"
    environment:
      POSTGRES_USER: rmm
      POSTGRES_DB: rmm
      # No password: the project publishes no port.
      POSTGRES_HOST_AUTH_METHOD: trust
    volumes:
      - rmm_pgdata:/var/lib/postgresql/data
    tmpfs:
      - /var/run/postgresql:rw,uid=70,gid=70,mode=0770
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -q -U rmm -d rmm"]
      interval: 2s
      timeout: 3s
      retries: 30
  server: &writer
    build: ./no-source-here
    image: rmm-restore-test/server:from-source
  frontend:
    <<: *writer
    image: rmm-restore-test/frontend:from-source
volumes:
  rmm_pgdata:
EOF
# The images file swaps each build for a ready image.
cat > "$dir/images.yml" <<EOF
services:
  server: &ready
    build: !reset null
    image: $image
    user: "70:70"
    entrypoint: ["sleep", "infinity"]
    healthcheck:
      test: ["CMD", "true"]
      interval: 1s
  frontend: *ready
EOF
cat > "$env_file" <<EOF
COMPOSE_PROJECT_NAME=$project
COMPOSE_FILE=$dir/base.yml:$dir/images.yml
POSTGRES_USER=rmm
POSTGRES_DB=rmm
EOF
export ENV_FILE=$env_file BACKUP_DIR=$dir/backups BACKUP_REQUIRE_ENCRYPTION=false BACKUP_OFFSITE_REQUIRED=false \
  RESTORE_WAIT_TIMEOUT=120

sql() { dc exec -T postgres psql -U rmm -d rmm -X -At -v ON_ERROR_STOP=1 -c "$1"; }
rows() { sql "SELECT coalesce(string_agg(name, ',' ORDER BY name), '') FROM marks"; }

dc up -d --wait >/dev/null 2>&1 || fail "the test stack did not start"
# On its first start the postgres image runs a temporary server to create the
# database, which pg_isready already reports ready, then restarts it: wait for
# a query to succeed on the final one.
for _ in $(seq 1 60); do
  sql "SELECT 1" >/dev/null 2>&1 && sleep 2 && sql "SELECT 1" >/dev/null 2>&1 && break
  sleep 1
done
sql "CREATE TABLE marks (name text PRIMARY KEY)" >/dev/null
sql "INSERT INTO marks VALUES ('kept')" >/dev/null
"$ops/backup.sh" > "$dir/backup.log" 2>&1 || { cat "$dir/backup.log" >&2; fail "backup.sh"; }
dump=$(find "$BACKUP_DIR" -maxdepth 1 -name 'rmm-*.dump' | head -1)
[[ -n "$dump" ]] || fail "backup.sh wrote no dump"
"$ops/verify-backup.sh" "$dump" > "$dir/verify.log" 2>&1 || { cat "$dir/verify.log" >&2; fail "verify-backup.sh"; }

sql "INSERT INTO marks VALUES ('dropped')" >/dev/null
RESTORE_CONFIRM=rmm "$ops/restore.sh" "$dump" > "$dir/restore.log" 2>&1 || { cat "$dir/restore.log" >&2; fail "restore.sh"; }
grep -q 'restored and healthy' "$dir/restore.log" || fail "restore.sh did not report a healthy restore"
grep -qi 'failed to solve\|build' "$dir/restore.log" && { cat "$dir/restore.log" >&2; fail "restore.sh tried to build the writers"; }
[[ "$(rows)" == kept ]] || fail "after the restore the rows are [$(rows)], want [kept]"
for writer in server frontend; do
  id=$(dc ps --status running -q "$writer")
  [[ -n "$id" ]] || fail "$writer is not running after the restore"
  [[ "$(docker inspect -f '{{.Config.Image}}' "$id")" == "$image" ]] || fail "$writer does not run the images file's image"
done

printf 'backup and restore with layered compose files: ok\n'
