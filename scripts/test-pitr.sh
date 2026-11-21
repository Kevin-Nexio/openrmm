#!/usr/bin/env bash
# Exercises deploy/ops/restore-pitr.sh against a real PostgreSQL with WAL
# archiving (deploy/postgres/archive-wal.sh), in a throwaway Compose project:
#   - a recovery to a chosen time keeps the row written before it and drops the
#     one written after, although that last write was never archived by
#     archive_timeout (the script archives the segment in progress);
#   - repeating that recovery, with nothing written since, cannot reach the
#     target on the new timeline: it is refused after a rehearsal, with the data
#     volume, the postgres container and the writers as they were;
#   - a recovery leaves no recovery settings in postgresql.auto.conf, and one
#     from a base backup that still carries an older recovery's target (as
#     earlier versions of the script left them) recovers everything anyway;
#   - PITR_TARGET_TIMELINE picks the branch a previous recovery left behind;
#   - archiving that broke is a warning, not a refusal, when the target lies
#     in what was archived before;
#   - a base backup that logs only fatal messages, to files, still recovers;
#   - a malformed PITR_TARGET_TIMELINE is refused before anything happens.
# Needs Docker with Compose. The writers are stand-ins that never write.
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ops=$root/deploy/ops
# shellcheck disable=SC2016 # a literal ${...} in docker-compose.prod.yml
image=$(sed -n 's/^.*&postgres-image \${POSTGRES_IMAGE:-\(.*\)}$/\1/p' "$root/deploy/docker-compose.prod.yml")
[[ -n "$image" ]] || { echo "FAIL: cannot read the postgres image from docker-compose.prod.yml" >&2; exit 1; }
dir=$(mktemp -d "${TMPDIR:-/tmp}/rmm-pitr.XXXXXX")
project=rmm-pitr-test-$$
compose_file=$dir/compose.yml
compose_layer=$dir/project.yml
env_file=$dir/env
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
unset COMPOSE_FILE COMPOSE_PATH_SEPARATOR COMPOSE_PROJECT_NAME
dc() { docker compose --env-file "$env_file" -f "$compose_file" -f "$compose_layer" "$@"; }
cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$dir"
}
trap cleanup EXIT

# The effective project name comes from the layer, even without an env value.
printf 'name: %s\n' "$project" > "$compose_layer"
cat > "$compose_file" <<EOF
services:
  postgres-wal-init:
    image: $image
    user: "0:0"
    entrypoint: ["sh", "-c", "chmod 0700 /var/lib/postgresql/wal-archive && chown 70:70 /var/lib/postgresql/wal-archive"]
    volumes:
      - rmm_pgwal:/var/lib/postgresql/wal-archive
    restart: "no"
  postgres:
    image: $image
    user: "70:70"
    depends_on:
      postgres-wal-init:
        condition: service_completed_successfully
    environment:
      POSTGRES_USER: rmm
      POSTGRES_DB: rmm
      # No password: the project publishes no port, and the test connects
      # from inside the container.
      POSTGRES_HOST_AUTH_METHOD: trust
    command: ["postgres", "-c", "archive_mode=on", "-c", "archive_command=/usr/local/bin/archive-wal.sh %p %f", "-c", "archive_timeout=300", "-c", "wal_level=replica"]
    volumes:
      - rmm_pgdata:/var/lib/postgresql/data
      - rmm_pgwal:/var/lib/postgresql/wal-archive
      - $root/deploy/postgres/archive-wal.sh:/usr/local/bin/archive-wal.sh:ro
    tmpfs:
      - /var/run/postgresql:rw,uid=70,gid=70,mode=0770
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -q -U rmm -d rmm"]
      interval: 2s
      timeout: 3s
      retries: 30
  server: &writer
    image: $image
    user: "70:70"
    entrypoint: ["sleep", "infinity"]
    healthcheck:
      test: ["CMD", "true"]
      interval: 1s
  frontend: *writer
volumes:
  rmm_pgdata:
  rmm_pgwal:
EOF
cat > "$env_file" <<EOF
COMPOSE_FILE=$compose_file:$compose_layer
POSTGRES_USER=rmm
POSTGRES_DB=rmm
EOF
export ENV_FILE=$env_file BACKUP_DIR=$dir/backups BACKUP_REQUIRE_ENCRYPTION=false BACKUP_OFFSITE_REQUIRED=false \
  RESTORE_CONFIRM=rmm RESTORE_WAIT_TIMEOUT=120 BASEBACKUP_KEEP=0  # the cases reuse every base backup

sql() { dc exec -T postgres psql -U rmm -d rmm -X -At -v ON_ERROR_STOP=1 -c "$1"; }
marks() { sql "SELECT coalesce(string_agg(name, ',' ORDER BY at), '') FROM marks"; }
pitr() { "$ops/restore-pitr.sh" "$1" > "$dir/pitr.log" 2>&1; }
newest_base() { find "$BACKUP_DIR/base" -maxdepth 1 -name 'base-*.tar.gz' -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-; }
clean_conf() {
  ! dc exec -T postgres sh -c 'grep -Eq "^[[:space:]]*(restore_command|recovery_target)" /var/lib/postgresql/data/postgresql.auto.conf' \
    || fail "$1: recovery settings were left in postgresql.auto.conf"
}
expect_marks() { [[ "$(marks)" == "$1" ]] || fail "$2: rows are [$(marks)], want [$1]"; }

dc up -d --wait >/dev/null 2>&1
# On its first start the postgres image runs a temporary server to create the
# database, which pg_isready already reports ready, then restarts it: wait for
# a query to succeed on the final one.
for _ in $(seq 1 60); do
  sql "SELECT 1" >/dev/null 2>&1 && sleep 2 && sql "SELECT 1" >/dev/null 2>&1 && break
  sleep 1
done
sql "CREATE TABLE marks (name text PRIMARY KEY, at timestamptz NOT NULL DEFAULT clock_timestamp())" >/dev/null
"$ops/basebackup.sh" > "$dir/base.log" 2>&1 || { cat "$dir/base.log" >&2; fail "base backup"; }
base1=$(newest_base)

# A recovery to a time between two writes. The second write sits in the WAL
# segment in progress: only the script's own segment switch archives it, and
# PostgreSQL needs a commit past the target to know it got there.
sql "INSERT INTO marks VALUES ('before')" >/dev/null
sleep 2
target=$(sql "SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') || '+00'")
sleep 2
sql "INSERT INTO marks VALUES ('after')" >/dev/null
PITR_TARGET_TIME=$target pitr "$base1" || { cat "$dir/pitr.log" >&2; fail "recovery to $target"; }
expect_marks before "recovery to the time between the writes"
clean_conf "recovery to a time"

# The same recovery again. The new timeline has nothing written after the
# target, so PostgreSQL cannot reach it: refused, and nothing has changed.
container=$(docker inspect -f '{{.Id}}' "$(dc ps -q postgres)")
volume=$(docker volume inspect -f '{{.CreatedAt}}' "${project}_rmm_pgdata")
if PITR_TARGET_TIME=$target pitr "$base1"; then fail "a recovery to an unreachable target was accepted"; fi
grep -q 'Nothing was replaced' "$dir/pitr.log" || { cat "$dir/pitr.log" >&2; fail "the refusal does not say nothing was replaced"; }
grep -q 'recovery ended before configured recovery target was reached' "$dir/pitr.log" || fail "the refusal does not show PostgreSQL's reason"
grep -q 'last completed transaction was at log time' "$dir/pitr.log" || fail "the refusal does not say what the archive holds"
grep -q 'timeline 2 began on timeline 1' "$dir/pitr.log" || fail "the refusal does not list the timelines"
[[ "$(docker inspect -f '{{.Id}}' "$(dc ps -q postgres)")" == "$container" ]] || fail "postgres was replaced by a refused recovery"
[[ "$(docker volume inspect -f '{{.CreatedAt}}' "${project}_rmm_pgdata")" == "$volume" ]] || fail "the data volume was replaced by a refused recovery"
for writer in server frontend; do
  [[ "$(dc ps --status running -q "$writer")" != "" ]] || fail "$writer was not started again after the refusal"
done
docker volume ls -q | grep -q "${project}_pitr_rehearsal" && fail "the rehearsal volume was left behind"
expect_marks before "after a refused recovery"

# Everything the latest history holds, from a base backup that still carries an
# older recovery's target in postgresql.auto.conf, as earlier versions of the
# script left it. Recovering with no target must not stop at that one. The
# last write was never archived by archive_timeout.
sql "ALTER SYSTEM SET recovery_target_time = '$target'" >/dev/null
"$ops/basebackup.sh" > "$dir/base.log" 2>&1 || { cat "$dir/base.log" >&2; fail "second base backup"; }
base2=$(newest_base)
[[ "$base2" != "$base1" ]] || fail "the second base backup was not written"
sql "INSERT INTO marks VALUES ('last')" >/dev/null
pitr "$base2" || { cat "$dir/pitr.log" >&2; fail "recovery of everything"; }
expect_marks before,last "recovery of everything"
clean_conf "recovery of everything"

# The branch the first recovery left behind: timeline 1 still holds 'after'.
PITR_TARGET_TIMELINE=1 pitr "$base1" || { cat "$dir/pitr.log" >&2; fail "recovery of timeline 1"; }
expect_marks before,after "recovery of the abandoned timeline 1"

# Archiving broken (here the archive is made read-only for postgres): the
# segment in progress cannot be archived, which is only a warning, since the
# target lies in what was archived before.
wal_chmod() {
  docker run --rm --network none --user 0:0 -v "${project}_rmm_pgwal":/archive --entrypoint chmod "$image" "$1" /archive
}
wal_chmod 0500
sql "INSERT INTO marks VALUES ('unarchived')" >/dev/null
PITR_TARGET_TIME=$target PITR_ARCHIVE_WAIT=5 pitr "$base1" || { cat "$dir/pitr.log" >&2; wal_chmod 0700; fail "recovery with archiving broken"; }
wal_chmod 0700
grep -q 'warning: WAL segment .* was not archived' "$dir/pitr.log" || fail "no warning that the segment in progress was not archived"
expect_marks before "recovery to a time while archiving is broken"

# A base backup whose configuration hides the messages the rehearsal reads
# (fatal-only logging, to files): the rehearsal pins its own logging.
for setting in "log_min_messages = 'fatal'" "logging_collector = on"; do
  sql "ALTER SYSTEM SET $setting" >/dev/null
done
"$ops/basebackup.sh" > "$dir/base.log" 2>&1 || { cat "$dir/base.log" >&2; fail "third base backup"; }
base3=$(newest_base)
sql "INSERT INTO marks VALUES ('quiet')" >/dev/null
pitr "$base3" || { cat "$dir/pitr.log" >&2; fail "recovery from a base backup with quiet logging"; }
expect_marks before,quiet "recovery from a base backup with quiet logging"

# A malformed timeline is refused before anything runs.
if PITR_TARGET_TIMELINE='1; DROP' pitr "$base1"; then fail "a malformed PITR_TARGET_TIMELINE was accepted"; fi
grep -q 'PITR_TARGET_TIMELINE must be latest, current or a timeline number' "$dir/pitr.log" || fail "malformed timeline message"
grep -q 'stopping the writers' "$dir/pitr.log" && fail "the writers were stopped for a malformed request"

printf 'point-in-time recovery: ok\n'
