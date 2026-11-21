#!/usr/bin/env bash
# Exercises how the ops scripts choose their compose files (compose_files in
# deploy/ops/_common.sh). With no COMPOSE_FILE they use docker-compose.prod.yml.
# The layered list deploy/.env sets for the published images
# (deploy/QUICKSTART.md) becomes one -f per file, in order, relative to
# deploy/. The environment overrides deploy/.env, COMPOSE_PATH_SEPARATOR is
# honoured, empty entries are skipped, and a missing file is refused before
# docker runs. The restore scripts used to pass the whole list as one file,
# then rebuild the server from source and leave the application stopped.
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
deploy=$root/deploy
dir=$(mktemp -d "${TMPDIR:-/tmp}/rmm-compose-files.XXXXXX")
trap 'rm -rf "$dir"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Prints the file after each -f that `compose config` would pass to docker,
# for a deploy/.env holding $1 and the extra environment in the other args.
files() {
  local env_file=$dir/env.$RANDOM
  printf '%s\n' "$1" > "$env_file"
  shift
  # shellcheck disable=SC2016 # expanded by the inner shell
  env -u COMPOSE_FILE -u COMPOSE_PATH_SEPARATOR "$@" ENV_FILE="$env_file" bash -c '
    set -Eeuo pipefail
    source "$1/deploy/ops/_common.sh"
    load_env_file
    docker() { local a; for a in "$@"; do printf "%s\n" "$a"; done; }
    compose config' _ "$root" | awk 'previous == "-f" { print } { previous = $0 }'
}
expect() {
  local what=$1 got=$2; shift 2
  local want
  want=$(printf '%s\n' "$@")
  [[ "$got" == "$want" ]] || fail "$what: got [$got], want [$want]"
}

expect "no COMPOSE_FILE" "$(files 'POSTGRES_USER=rmm')" "$deploy/docker-compose.prod.yml"
expect "the published-images layering in deploy/.env" \
  "$(files 'COMPOSE_FILE=docker-compose.prod.yml:docker-compose.images.yml:docker-compose.caddy.yml')" \
  "$deploy/docker-compose.prod.yml" "$deploy/docker-compose.images.yml" "$deploy/docker-compose.caddy.yml"
expect "a quoted value" "$(files 'COMPOSE_FILE="docker-compose.prod.yml:docker-compose.images.yml"')" \
  "$deploy/docker-compose.prod.yml" "$deploy/docker-compose.images.yml"
expect "the environment overrides deploy/.env" \
  "$(files 'COMPOSE_FILE=docker-compose.prod.yml:docker-compose.images.yml' COMPOSE_FILE="$deploy/docker-compose.prod.yml")" \
  "$deploy/docker-compose.prod.yml"
expect "COMPOSE_PATH_SEPARATOR" \
  "$(files 'COMPOSE_FILE=docker-compose.prod.yml,docker-compose.standby.yml' COMPOSE_PATH_SEPARATOR=,)" \
  "$deploy/docker-compose.prod.yml" "$deploy/docker-compose.standby.yml"
expect "an empty entry" "$(files 'COMPOSE_FILE=docker-compose.prod.yml::docker-compose.images.yml')" \
  "$deploy/docker-compose.prod.yml" "$deploy/docker-compose.images.yml"

# A file that does not exist stops the script before docker runs.
if out=$(files 'COMPOSE_FILE=docker-compose.prod.yml:docker-compose.nope.yml' 2>&1); then
  fail "a missing compose file was accepted: $out"
fi
[[ "$out" != *"config"* ]] || fail "docker ran although a compose file is missing"
# shellcheck disable=SC2016 # expanded by the inner shell
err=$(env -u COMPOSE_FILE ENV_FILE=/dev/null COMPOSE_FILE=docker-compose.nope.yml bash -c \
  'source "$1/deploy/ops/_common.sh"; docker() { :; }; compose config' _ "$root" 2>&1 || true)
[[ "$err" == *"compose file not found: $deploy/docker-compose.nope.yml"* ]] || fail "missing file error: $err"

printf 'ops compose files: ok\n'
