# GeoIP refresh

Weekly job that refreshes the MaxMind GeoLite2 Country / ASN / City MMDB
files used for IP minimization (audit doc 19, ADR-0002). The running API
reads these files from `GEOIP_DIR`; this job is the only thing that
writes them.

The API never persists a raw client IP. Country + ASN come from
Cloudflare headers when present (`CF-IPCountry`, `CF-IPASN`); the MMDB
files are the fallback when the API is hit directly. City is read from
the MMDB only — Cloudflare's `CF-IPCity` is enterprise-tier only and not
relied on. See `src/utils/ipContext.ts`.

## Attribution

MaxMind requires attribution for GeoLite2 usage. The `/security` page
includes the required notice:

> This product includes GeoLite2 data created by MaxMind, available from
> [https://www.maxmind.com](https://www.maxmind.com).

Do not remove that notice from `/security` without removing the MMDB
dependency too.

## One-time setup (VPS)

### 1. MaxMind account + license key

Register at https://www.maxmind.com/en/geolite2/signup (free, GeoLite2
tier). In **Manage License Keys**, generate a new key scoped to "GeoIP
Update". Save the account ID + license key to the password manager.

### 2. Install the env file

```bash
sudo cp infra/geoip/geoip.env.example /etc/jtransfer/geoip.env
sudo chmod 600 /etc/jtransfer/geoip.env
sudo $EDITOR /etc/jtransfer/geoip.env
```

Fill in `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY`.

### 3. Install the script

```bash
sudo install -d -m 0755 /opt/jtransfer
sudo install -m 0755 infra/geoip/setup-geoip.sh /opt/jtransfer/setup-geoip.sh
sudo install -d -m 0755 /var/lib/geoip
```

### 4. Install the systemd service and timer

```bash
sudo install -m 0644 infra/geoip/jtransfer-geoip-refresh.service /etc/systemd/system/
sudo install -m 0644 infra/geoip/jtransfer-geoip-refresh.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jtransfer-geoip-refresh.timer
```

### 5. Run once to seed the MMDB files

```bash
sudo systemctl start jtransfer-geoip-refresh.service
sudo journalctl -u jtransfer-geoip-refresh.service -n 50 --no-pager
ls -lh /var/lib/geoip/
```

You should see three files:

- `GeoLite2-Country.mmdb` (~6 MB)
- `GeoLite2-ASN.mmdb` (~10 MB)
- `GeoLite2-City.mmdb` (~70 MB)

## Operations

- **Schedule:** weekly, Wednesday 04:00 UTC + 0–30 min jitter. MaxMind
  ships GeoLite2 updates on Tuesdays.
- **Atomicity:** the script downloads to a temp dir, verifies SHA256,
  extracts, and uses `install` (rename) to swap each `.mmdb` into place.
  An in-flight reader never sees a half-written file.
- **Reader reopen:** the API stats each MMDB before lookup and reopens
  the reader if `mtime` changed. No restart is needed after a refresh.
- **Failure visibility:** systemd exit code drives journald. Probe with
  `systemctl is-failed jtransfer-geoip-refresh.service` or
  `journalctl --identifier=jtransfer-geoip-refresh`.
- **License rotation:** see `docs/runbooks/secrets.md` →
  "MaxMind license key".

## What happens if the MMDB files go stale or are missing

The API falls back to Cloudflare headers (`CF-IPCountry`, `CF-IPASN`)
when present. When the API is hit directly without those headers and
the MMDB files are missing/unreadable, IP context resolves to
`country: 'unknown'`, `asn: null`. The session-anomaly check tolerates
this — a mismatch on `unknown` is not raised as an anomaly.

`ENABLE_IP_DERIVATION=false` disables derivation entirely (debugging
only) — every request resolves to `country: 'unknown'`, `asn: null`.
