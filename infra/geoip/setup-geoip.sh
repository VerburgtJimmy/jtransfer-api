#!/usr/bin/env bash
# Weekly refresh of the MaxMind GeoLite2 MMDB files used for IP minimization
# (audit doc 19, ADR-0002). Downloads Country, ASN, and City editions and
# atomically swaps them into $GEOIP_DIR so an in-flight lookup never sees a
# half-written file.
#
# This script does not signal the API. The API reopens its MMDB readers
# lazily when the file mtime changes (see src/utils/ipContext.ts), so a
# successful refresh is picked up on the next IP-context resolution.
#
# Required environment (typically /etc/tessil/geoip.env):
#   MAXMIND_ACCOUNT_ID
#   MAXMIND_LICENSE_KEY
#   GEOIP_DIR                  # default /var/lib/geoip

set -euo pipefail

: "${MAXMIND_ACCOUNT_ID:?MAXMIND_ACCOUNT_ID is required}"
: "${MAXMIND_LICENSE_KEY:?MAXMIND_LICENSE_KEY is required}"
GEOIP_DIR="${GEOIP_DIR:-/var/lib/geoip}"

mkdir -p "$GEOIP_DIR"

editions=(GeoLite2-Country GeoLite2-ASN GeoLite2-City)

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

base="https://download.maxmind.com/geoip/databases"

for edition in "${editions[@]}"; do
  echo "[geoip] refreshing $edition"

  tarball="$tmpdir/$edition.tar.gz"
  sha_file="$tmpdir/$edition.tar.gz.sha256"

  # MaxMind 302-redirects to a presigned R2 URL after auth; -L follows it.
  # Auth is basic with $account_id:$license_key on the maxmind.com host only;
  # curl strips the header on the cross-host redirect to R2 by default.
  curl -sSfL -u "$MAXMIND_ACCOUNT_ID:$MAXMIND_LICENSE_KEY" \
    -o "$tarball" \
    "$base/$edition/download?suffix=tar.gz"

  curl -sSfL -u "$MAXMIND_ACCOUNT_ID:$MAXMIND_LICENSE_KEY" \
    -o "$sha_file" \
    "$base/$edition/download?suffix=tar.gz.sha256"

  # MaxMind's .sha256 file is `<hash>  <filename>` with the upstream
  # filename. Replace the filename component with our local path so
  # `sha256sum -c` matches against the tarball we just wrote.
  expected_hash="$(awk '{print $1}' "$sha_file")"
  echo "$expected_hash  $tarball" > "$sha_file"
  sha256sum -c "$sha_file"

  # The .mmdb lives inside a dated directory: GeoLite2-XXX_YYYYMMDD/GeoLite2-XXX.mmdb
  tar -xzf "$tarball" -C "$tmpdir"
  mmdb_path="$(find "$tmpdir" -name "$edition.mmdb" -type f | head -n1)"
  if [[ -z "$mmdb_path" ]]; then
    echo "[geoip] $edition.mmdb not found in tarball" >&2
    exit 1
  fi

  # Atomic replace — install writes to a temp file in the destination dir
  # and renames it, which is atomic on the same filesystem.
  install -m 0644 "$mmdb_path" "$GEOIP_DIR/$edition.mmdb"

  size=$(wc -c < "$GEOIP_DIR/$edition.mmdb")
  echo "[geoip] $edition.mmdb installed (${size} bytes)"
done

echo "[geoip] refresh complete"
