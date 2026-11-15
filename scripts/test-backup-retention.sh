#!/usr/bin/env bash
# Exercises prune_backups (deploy/ops/_common.sh) on a throwaway directory: the
# newest KEEP archives stay with their sidecars, older ones go with theirs,
# encrypted and plain archives count together, in-flight temporaries and
# unrelated files are never touched, KEEP=0 keeps everything, and a bad KEEP
# is refused before anything is deleted.
set -Eeuo pipefail
# shellcheck source=deploy/ops/_common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/../deploy/ops/_common.sh"

dir=$(mktemp -d "${TMPDIR:-/tmp}/rmm-retention.XXXXXX")
trap 'rm -rf "$dir"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
make() { for f in "$@"; do : > "$dir/$f"; done; }
present() { [[ -e "$dir/$1" ]] || fail "$1 was removed"; }
absent() { [[ ! -e "$dir/$1" ]] || fail "$1 was kept"; }

# Base backups: three archives (one encrypted), sidecars, a temporary from a
# run in progress, and an unrelated file.
make base-20261101T021500Z.tar.gz base-20261101T021500Z.tar.gz.sha256 base-20261101T021500Z.tar.gz.startwal \
  base-20261108T021500Z.tar.gz.age base-20261108T021500Z.tar.gz.age.sha256 base-20261108T021500Z.tar.gz.age.startwal \
  base-20261115T021500Z.tar.gz base-20261115T021500Z.tar.gz.sha256 base-20261115T021500Z.tar.gz.startwal \
  .base-20261115T030000Z.Ab12Cd base-20261115T030000Z.tar.gz.age.tmp.4242 notes.txt
prune_backups "$dir" 'base-*.tar.gz*' 2 2>/dev/null
absent base-20261101T021500Z.tar.gz
absent base-20261101T021500Z.tar.gz.sha256
absent base-20261101T021500Z.tar.gz.startwal
for f in base-20261108T021500Z.tar.gz.age base-20261108T021500Z.tar.gz.age.sha256 base-20261108T021500Z.tar.gz.age.startwal \
  base-20261115T021500Z.tar.gz base-20261115T021500Z.tar.gz.sha256 base-20261115T021500Z.tar.gz.startwal \
  .base-20261115T030000Z.Ab12Cd base-20261115T030000Z.tar.gz.age.tmp.4242 notes.txt; do
  present "$f"
done

# Logical dumps keep the newest one; a leading zero is a decimal count.
make rmm-20261113T031500Z-a1.dump rmm-20261113T031500Z-a1.dump.sha256 \
  rmm-20261114T031500Z-b2.dump.age rmm-20261114T031500Z-b2.dump.age.sha256
prune_backups "$dir" 'rmm-*.dump*' 01 2>/dev/null
absent rmm-20261113T031500Z-a1.dump
absent rmm-20261113T031500Z-a1.dump.sha256
present rmm-20261114T031500Z-b2.dump.age
present rmm-20261114T031500Z-b2.dump.age.sha256

# KEEP=0 keeps everything.
make rmm-20261101T031500Z-c3.dump
prune_backups "$dir" 'rmm-*.dump*' 0
present rmm-20261101T031500Z-c3.dump

# A bad KEEP stops the run and deletes nothing.
if (prune_backups "$dir" 'rmm-*.dump*' 'two' 2>/dev/null); then fail "a bad KEEP was accepted"; fi
present rmm-20261101T031500Z-c3.dump
present rmm-20261114T031500Z-b2.dump.age

printf 'backup retention: ok\n'
