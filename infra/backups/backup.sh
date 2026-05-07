#!/usr/bin/env bash
# Daily encrypted Postgres backup for JTransfer.
# Pipes pg_dump output through age and uploads to a remote via rclone.
#
# Required environment (typically loaded from /etc/jtransfer/backup.env):
#   DATABASE_URL           Postgres connection URL.
#   AGE_RECIPIENTS_FILE    Path to a file with one age recipient public key per line.
#   RCLONE_CONFIG          Path to the rclone config file.
#   RCLONE_REMOTE          rclone remote and path, e.g. hetzner-storagebox:jtransfer-backups
#
# Optional:
#   RETENTION_DAYS         Defaults to 30. Older backups are deleted from the remote.

set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${AGE_RECIPIENTS_FILE:?AGE_RECIPIENTS_FILE is required}"
: "${RCLONE_CONFIG:?RCLONE_CONFIG is required}"
: "${RCLONE_REMOTE:?RCLONE_REMOTE is required}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

export RCLONE_CONFIG

if [[ ! -r "$AGE_RECIPIENTS_FILE" ]]; then
  echo "age recipients file not readable: $AGE_RECIPIENTS_FILE" >&2
  exit 1
fi

if ! grep -q '^age1' "$AGE_RECIPIENTS_FILE"; then
  echo "age recipients file contains no age1... recipient line" >&2
  exit 1
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
outfile="jtransfer-${stamp}.dump.age"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
local_path="$tmpdir/$outfile"

echo "[backup] dumping database"
set -o pipefail
pg_dump --format=custom --no-owner --no-privileges "$DATABASE_URL" \
  | age --recipients-file "$AGE_RECIPIENTS_FILE" --output "$local_path"

dump_size=$(wc -c < "$local_path")
echo "[backup] encrypted dump size: ${dump_size} bytes"

if [[ "$dump_size" -lt 1024 ]]; then
  echo "[backup] suspiciously small dump (<1 KiB) — aborting" >&2
  exit 1
fi

echo "[backup] uploading to $RCLONE_REMOTE"
rclone copy --no-traverse "$local_path" "$RCLONE_REMOTE"

echo "[backup] pruning remote files older than ${RETENTION_DAYS}d"
rclone delete --min-age "${RETENTION_DAYS}d" "$RCLONE_REMOTE"

echo "[backup] done: $outfile"
