#!/usr/bin/env bash
# Destructive point-in-time recovery: restores a physical base backup and
# replays archived WAL up to a chosen instant.
#
# Use this when you need a recovery point closer than the last logical dump —
# a bad migration, a mistaken mass delete, a corrupt volume. For a clean
# single-database rollback, restore.sh is simpler and version-portable.
#
#   RESTORE_CONFIRM=rmm PITR_TARGET_TIME='2026-07-27 03:20:00+00' \
#     deploy/ops/restore-pitr.sh /var/backups/openrmm/base/base-TIMESTAMP.tar.gz.age
#
# Omit PITR_TARGET_TIME to replay everything available (recover as far forward
# as the archive allows).
#
# Nothing is replaced until the recovery has been rehearsed:
#   1. The writers stop, and the WAL segment in progress is archived, so the
#      replay can reach the last write.
#   2. The same recovery runs on a throwaway copy of the base backup.
#   3. Only when PostgreSQL reaches the target there does the stack go down and
#      the data volume get replaced.
# If the rehearsal fails, the database is untouched, the writers start again,
# and the error says what the archive holds.
#
# PITR_TARGET_TIMELINE picks the branch of history to replay: latest (the
# default), current (the base backup's) or a timeline number. Each recovery
# that ends starts a new timeline (deploy/README-production.md, section 7.1).
set -Eeuo pipefail
umask 077

# shellcheck source=deploy/ops/_common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/_common.sh"
load_env_file
require_command docker

[[ $# -eq 1 ]] || die "usage: $0 /path/to/base-TIMESTAMP.tar.gz[.age]"
archive=$1
[[ -f "$archive" && ! -L "$archive" ]] || die "base backup must be a regular file: $archive"
verify_checksum "$archive"

POSTGRES_DB=${POSTGRES_DB:-rmm}
POSTGRES_USER=${POSTGRES_USER:-rmm}
validate_identifier POSTGRES_DB "$POSTGRES_DB"
validate_identifier POSTGRES_USER "$POSTGRES_USER"
WAL_ARCHIVE_DIR=${WAL_ARCHIVE_DIR:-/var/lib/postgresql/wal-archive}
RESTORE_WAIT_TIMEOUT=${RESTORE_WAIT_TIMEOUT:-600}
PITR_TARGET_TIMELINE=${PITR_TARGET_TIMELINE:-latest}
PITR_ARCHIVE_WAIT=${PITR_ARCHIVE_WAIT:-120}
[[ "$RESTORE_WAIT_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "RESTORE_WAIT_TIMEOUT must be a positive integer"
[[ "$PITR_ARCHIVE_WAIT" =~ ^[1-9][0-9]*$ ]] || die "PITR_ARCHIVE_WAIT must be a positive integer"
[[ "$PITR_TARGET_TIMELINE" =~ ^(latest|current|[1-9][0-9]{0,8})$ ]] \
  || die "PITR_TARGET_TIMELINE must be latest, current or a timeline number"
[[ "$WAL_ARCHIVE_DIR" =~ ^/[A-Za-z0-9/._-]+$ ]] || die "WAL_ARCHIVE_DIR must be an absolute path"
read -r -a writer_services <<< "${RESTORE_WRITER_SERVICES:-frontend server}"
for service in "${writer_services[@]}"; do
  [[ "$service" =~ ^[A-Za-z0-9_-]+$ ]] || die "invalid writer service: $service"
done

if [[ -n "${PITR_TARGET_TIME:-}" ]]; then
  # Rejected early: a malformed target silently becomes "replay everything",
  # which is the opposite of what someone recovering from a bad write wants.
  [[ "$PITR_TARGET_TIME" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]T][0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?([+-][0-9]{2}(:?[0-9]{2})?|Z)?$ ]] \
    || die "PITR_TARGET_TIME must look like '2026-07-27 03:20:00+00'"
fi

if [[ "${RESTORE_CONFIRM:-}" != "$POSTGRES_DB" ]]; then
  [[ -t 0 ]] || die "set RESTORE_CONFIRM=$POSTGRES_DB for a non-interactive destructive restore"
  printf 'Type %s to REPLACE the entire cluster from %s: ' "$POSTGRES_DB" "$(basename "$archive")" >&2
  read -r confirmation
  [[ "$confirmation" == "$POSTGRES_DB" ]] || die "restore cancelled"
fi

# Resolve the project and check the storage layout before stopping the stack.
# A Compose layer can change either, including when the old container is gone.
if [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
  [[ "$COMPOSE_PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "COMPOSE_PROJECT_NAME is not a valid Compose project name"
fi
require_command python3
project=$(compose config --format json | python3 -c '
import json
import sys

try:
    config = json.load(sys.stdin)
    project = config["name"]
    mounts = config["services"]["postgres"]["volumes"]
    for key, target in (("rmm_pgdata", "/var/lib/postgresql/data"), ("rmm_pgwal", sys.argv[1])):
        matching = [mount for mount in mounts if mount["target"] == target]
        volume = config["volumes"][key]
        if (len(matching) != 1 or matching[0]["type"] != "volume"
                or matching[0].get("source") != key or matching[0].get("read_only")
                or (matching[0].get("volume") or {}).get("subpath")
                or volume["name"] != project + "_" + key or volume.get("external")
                or volume.get("driver", "local") != "local" or volume.get("driver_opts")):
            sys.exit(1)
except (ValueError, KeyError, TypeError):
    sys.exit(1)
print(project)
' "$WAL_ARCHIVE_DIR") || die "PITR needs project-local Compose volumes rmm_pgdata and rmm_pgwal mounted on postgres"
[[ "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "could not resolve the Compose project name"
export COMPOSE_PROJECT_NAME="$project"
data_volume=${project}_rmm_pgdata
# The WAL archive lives on its own volume and must survive this: it is what the
# replay reads. Only the data volume is replaced.
wal_volume=${project}_rmm_pgwal
docker volume inspect "$wal_volume" >/dev/null 2>&1 || die "WAL archive volume $wal_volume not found — PITR cannot replay without it"
image=$(postgres_image)

plain=$(mktemp "${TMPDIR:-/tmp}/rmm-base.XXXXXX")
# A fresh name each run: `docker volume create` would silently reuse a volume
# left by a run that was killed, and its files would mix into the rehearsal.
suffix=$$-$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')
rehearsal_volume=${project}_pitr_rehearsal_$suffix
rehearsal_container=${project}-pitr-rehearsal-$suffix
writers_stopped=false
replacing=false
cleanup() {
  local status=$?
  docker rm -f "$rehearsal_container" >/dev/null 2>&1 || true
  docker volume rm -f "$rehearsal_volume" >/dev/null 2>&1 || true
  rm -f "$plain"
  # Until the data volume is touched, any failure puts the application back.
  if ((status != 0)) && [[ "$writers_stopped" == true && "$replacing" == false ]]; then
    printf 'starting the writers again; the database was not changed\n' >&2
    compose up -d --wait --wait-timeout "$RESTORE_WAIT_TIMEOUT" "${writer_services[@]}" >&2 \
      || printf 'CRITICAL: the writers did not start again; start them by hand: compose up -d %s\n' "${writer_services[*]}" >&2
  fi
  return "$status"
}
trap cleanup EXIT
materialize_archive "$archive" "$plain"
gzip -t "$plain" 2>/dev/null || die "base backup failed gzip integrity check"

# The recovery settings: shutdown at the target for the rehearsal, promote
# for the real run.
recovery_settings() {
  printf "restore_command = 'cp %s/%%f %%p'\n" "$WAL_ARCHIVE_DIR"
  printf "recovery_target_timeline = '%s'\n" "$PITR_TARGET_TIMELINE"
  printf "recovery_target_action = '%s'\n" "$1"
  if [[ -n "${PITR_TARGET_TIME:-}" ]]; then
    printf "recovery_target_time = '%s'\n" "$PITR_TARGET_TIME"
  fi
}

# Unpacks the base backup into a volume and arms recovery, in a throwaway
# container, so file ownership matches the postgres image's uid without
# assuming host uids. A base backup of a cluster that was itself recovered
# carries that recovery's settings in postgresql.auto.conf (older versions of
# this script never removed them); they are dropped first, or a recovery with
# no target would stop at the previous one's.
unpack_base() {
  # shellcheck disable=SC2016 # expanded inside the container
  docker run --rm -i --network none \
    -e RECOVERY_SETTINGS="$(recovery_settings "$2")" \
    -v "$1":/var/lib/postgresql/data \
    --entrypoint sh "$image" -c '
      set -e
      tar -C /var/lib/postgresql/data -xzf -
      conf=/var/lib/postgresql/data/postgresql.auto.conf
      if [ -f "$conf" ]; then
        grep -Ev "^[[:space:]]*(restore_command|recovery_target[a-z_]*|recovery_end_command)[[:space:]]*=" "$conf" > "$conf.new" || true
        mv "$conf.new" "$conf"
      fi
      printf "%s\n" "$RECOVERY_SETTINGS" >> "$conf"
      touch /var/lib/postgresql/data/recovery.signal
      chown -R 70:70 /var/lib/postgresql/data
      chmod 0700 /var/lib/postgresql/data
    ' < "$plain"
}

live_sql() {
  compose exec -T postgres psql --username="$POSTGRES_USER" --dbname=postgres \
    --no-psqlrc --tuples-only --no-align --command="$1"
}

# 1. Stop writing, then archive the segment in progress. archive_timeout ships
#    a partial segment only every few minutes, so without this the last writes
#    before the stop would be missing from the archive the replay reads.
if ((${#writer_services[@]} > 0)); then
  printf 'stopping the writers: %s\n' "${writer_services[*]}" >&2
  writers_stopped=true
  compose stop "${writer_services[@]}"
fi
if [[ -n "$(compose ps --status running --quiet postgres 2>/dev/null)" ]] \
  && [[ "$(live_sql 'SELECT pg_is_in_recovery()' | tr -d '[:space:]')" == f ]]; then
  segment=$(live_sql 'SELECT pg_walfile_name(pg_switch_wal())' | tr -d '[:space:]')
  [[ "$segment" =~ ^[0-9A-F]{24}$ ]] || die "unexpected WAL segment name: $segment"
  printf 'archiving WAL up to %s\n' "$segment" >&2
  archived=f
  for ((i = 0; i < PITR_ARCHIVE_WAIT; i++)); do
    archived=$(live_sql "SELECT coalesce(last_archived_wal >= '$segment', false) FROM pg_stat_archiver" | tr -d '[:space:]')
    [[ "$archived" == t ]] && break
    sleep 1
  done
  if [[ "$archived" != t ]]; then
    # Not fatal: when archiving is what broke (a full archive volume, say), the
    # target can still lie in what was archived before. The rehearsal decides.
    printf 'warning: WAL segment %s was not archived within %ss (check archive_command: compose logs postgres);
' "$segment" "$PITR_ARCHIVE_WAIT" >&2
    printf '         writes after the last archived segment cannot be replayed
' >&2
  fi
else
  printf 'postgres is not running as a primary; replaying what was archived before it stopped\n' >&2
fi

# 2. Rehearse: the same base backup, archive and settings on a throwaway copy,
#    shutting down at the target instead of promoting. PostgreSQL itself
#    decides whether the target can be reached; nothing live has changed yet.
printf 'rehearsing the recovery on a throwaway copy\n' >&2
docker volume inspect "$rehearsal_volume" >/dev/null 2>&1 && die "volume $rehearsal_volume already exists"
docker volume create "$rehearsal_volume" >/dev/null
unpack_base "$rehearsal_volume" shutdown
# The decision reads the server's log, so the log is pinned whatever the base
# backup's configuration says: English messages, on stderr, at the default
# level. The limits are the postgres service's.
docker run -d --name "$rehearsal_container" --network none --user 70:70 \
  --memory "${POSTGRES_MEMORY_LIMIT:-2g}" --pids-limit "${POSTGRES_PIDS_LIMIT:-256}" \
  -v "$rehearsal_volume":/var/lib/postgresql/data \
  -v "$wal_volume":"$WAL_ARCHIVE_DIR":ro \
  --tmpfs /var/run/postgresql:rw,uid=70,gid=70,mode=0770 \
  --entrypoint postgres "$image" -D /var/lib/postgresql/data \
  -c archive_mode=off -c listen_addresses= -c lc_messages=C -c logging_collector=off \
  -c log_destination=stderr -c log_min_messages=warning >/dev/null
# With a target, the rehearsal server stops by itself: at the target ("recovery
# stopping ...") or on an error. Without one it replays everything, promotes and
# keeps running, which is the success to wait for.
outcome=timeout
log=
for ((i = 0; i < RESTORE_WAIT_TIMEOUT; i++)); do
  running=$(docker inspect -f '{{.State.Running}}' "$rehearsal_container" 2>/dev/null || echo false)
  log=$(docker logs "$rehearsal_container" 2>&1 || true)
  if [[ "$log" == *"FATAL:"* || "$log" == *"PANIC:"* ]]; then
    outcome=failed
  elif [[ -z "${PITR_TARGET_TIME:-}" && "$log" == *"database system is ready to accept connections"* ]]; then
    outcome=reached
  elif [[ "$running" != true ]]; then
    if [[ -n "${PITR_TARGET_TIME:-}" && "$log" == *"recovery stopping "* ]]; then outcome=reached; else outcome=failed; fi
  fi
  [[ "$outcome" == timeout ]] || break
  sleep 1
done
if [[ "$outcome" != reached ]]; then
  printf '\nThe recovery cannot reach %s on timeline %s. Nothing was replaced.\n' \
    "${PITR_TARGET_TIME:-the end of the archive}" "$PITR_TARGET_TIMELINE" >&2
  grep -E 'FATAL|PANIC|last completed transaction|starting point-in-time recovery|restored log file "[0-9A-F]{8}\.history"' <<< "$log" \
    | sed 's/^/  postgres: /' >&2 || true
  # Each NNNNNNNN.history file ends with the line that started timeline N:
  # its parent, the WAL position it branched at, and why.
  # shellcheck disable=SC2016 # expanded inside the container
  histories=$(docker run --rm --network none -v "$wal_volume":/archive:ro --entrypoint sh "$image" -c '
    for f in /archive/*.history; do
      [ -f "$f" ] || continue
      n=${f##*/}; n=${n%.history}
      tl=$(printf "%d" "0x$n")
      awk -v tl="$tl" "NF { last = \$0 } END { split(last, p, \"\t\"); printf \"  timeline %s began on timeline %s at %s (%s)\n\", tl, p[1], p[2], p[3] }" "$f"
    done' 2>/dev/null || true)
  if [[ -n "$histories" ]]; then
    printf 'Timelines in the archive:\n%s\n' "$histories" >&2
  fi
  cat >&2 <<'EOF'
Options:
  - a PITR_TARGET_TIME no later than the last completed transaction above: the
    history being replayed has nothing after it;
  - no PITR_TARGET_TIME, to recover everything that history holds;
  - PITR_TARGET_TIMELINE=<n> to replay another branch, for instance the one a
    previous recovery left behind (deploy/README-production.md, section 7.1).
EOF
  [[ "$outcome" == timeout ]] && die "the rehearsal did not finish within ${RESTORE_WAIT_TIMEOUT}s"
  die "point-in-time recovery refused"
fi
docker rm -f "$rehearsal_container" >/dev/null
docker volume rm -f "$rehearsal_volume" >/dev/null
printf 'the rehearsal reached %s\n' "${PITR_TARGET_TIME:-the end of the archive}" >&2

# 3. The real run: replace the data volume and recover, promoting at the target.
replacing=true
printf 'stopping the stack\n' >&2
compose down
printf 'replacing the data volume %s\n' "$data_volume" >&2
docker volume rm --force "$data_volume" >/dev/null
docker volume create "$data_volume" >/dev/null
unpack_base "$data_volume" promote

printf 'starting postgres for replay\n' >&2
compose up -d --wait --wait-timeout "$RESTORE_WAIT_TIMEOUT" postgres

# Recovery ends when the server leaves recovery mode; until then the app must
# stay down, or it will read a half-replayed database.
for _ in $(seq 1 "$RESTORE_WAIT_TIMEOUT"); do
  state=$(live_sql 'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d '[:space:]' || true)
  [[ "$state" == "f" ]] && break
  sleep 1
done
[[ "$state" == "f" ]] || die "cluster is still in recovery after ${RESTORE_WAIT_TIMEOUT}s — inspect: compose logs postgres"

# The recovery settings are spent. Left in postgresql.auto.conf they would ride
# along in every later base backup and steer the next recovery to this target.
# ALTER SYSTEM runs outside a transaction block, so one statement per call.
for setting in restore_command recovery_target_time recovery_target_timeline recovery_target_action; do
  live_sql "ALTER SYSTEM RESET $setting" >/dev/null
done

printf 'starting the rest of the stack\n' >&2
compose up -d --wait --wait-timeout "$RESTORE_WAIT_TIMEOUT"
printf 'recovered from %s%s\n' "$archive" "${PITR_TARGET_TIME:+ to $PITR_TARGET_TIME}"
