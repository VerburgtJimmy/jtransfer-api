# JTransfer Postgres Backups

Daily off-VPS Postgres backups, encrypted at rest with [age](https://age-encryption.org)
and pushed to a [Hetzner Storage Box](https://www.hetzner.com/storage/storage-box) over
SFTP via [rclone](https://rclone.org).

The Postgres database holds transfer metadata only (encrypted file blobs live in R2,
keyed by data the database knows about). Losing this database means losing the index
needed to look up, expire, and serve every active transfer.

## Threat model

- Encrypted dumps are uploaded to a third-party Storage Box. Hetzner can read the
  ciphertext but not the plaintext (age recipient is a key Hetzner does not hold).
- The age private key is held by the operator only. If the private key is lost,
  every backup becomes unreadable. Treat its loss as equivalent to losing the
  database.

## One-time setup

### 1. Generate the age keypair (operator workstation, not the VPS)

On your laptop:

```bash
mkdir -p ~/.config/age
age-keygen -o ~/.config/age/jtransfer-backup.key
chmod 600 ~/.config/age/jtransfer-backup.key
```

`age-keygen` prints the public key (`age1...`) on stderr. Copy it.

Save the contents of `~/.config/age/jtransfer-backup.key` to a password manager
(it contains the private key). Keep the file on disk only as long as you need it
for restore drills.

### 2. Commit the public key

Replace the placeholder in `age-recipients.txt` with the line printed by
`age-keygen`. Commit and push.

### 3. Provision the Storage Box

Order a Storage Box in the Hetzner Robot panel. Note:

- Username (e.g. `u123456`)
- Hostname (e.g. `u123456.your-storagebox.de`)
- SSH/SFTP password
- Port `23` for SSH/SFTP

Optional but recommended: enable SSH key access in the Storage Box panel and add
the VPS's SSH public key. Password auth still works as fallback.

### 4. Install prerequisites on the VPS

```bash
sudo apt update
sudo apt install -y age rclone postgresql-client
```

(Adjust for the VPS distro. `age` is in Debian 12+ and Ubuntu 22.04+; on older
systems install via the official release.)

### 5. Configure rclone on the VPS

```bash
sudo mkdir -p /etc/jtransfer
sudo cp infra/backups/rclone.conf.example /etc/jtransfer/rclone.conf
sudo chmod 600 /etc/jtransfer/rclone.conf
sudo $EDITOR /etc/jtransfer/rclone.conf
```

Fill in the Storage Box host, user, and credentials. Test:

```bash
sudo rclone --config /etc/jtransfer/rclone.conf lsd hetzner-storagebox:
```

### 6. Drop the env file

```bash
sudo cp infra/backups/backup.env.example /etc/jtransfer/backup.env
sudo chmod 600 /etc/jtransfer/backup.env
sudo $EDITOR /etc/jtransfer/backup.env
```

Fill in `DATABASE_URL` and confirm the other values.

### 7. Install the script and the age recipients

```bash
sudo install -d -m 0755 /opt/jtransfer
sudo install -m 0755 infra/backups/backup.sh /opt/jtransfer/backup.sh
sudo install -m 0644 infra/backups/age-recipients.txt /etc/jtransfer/age-recipients.txt
```

### 8. Install the systemd service and timer

```bash
sudo install -m 0644 infra/backups/jtransfer-backup.service /etc/systemd/system/
sudo install -m 0644 infra/backups/jtransfer-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jtransfer-backup.timer
```

Confirm the timer is scheduled:

```bash
systemctl list-timers jtransfer-backup.timer
```

### 9. Run once manually to validate

```bash
sudo systemctl start jtransfer-backup.service
sudo journalctl -u jtransfer-backup.service -n 100 --no-pager
sudo rclone --config /etc/jtransfer/rclone.conf ls hetzner-storagebox:jtransfer-backups
```

You should see a new `jtransfer-YYYYMMDDTHHMMSSZ.dump.age` object.

## Restore drill

Run periodically (target: monthly) to verify backups are usable.

```bash
# 1. Pull a recent backup
rclone --config /etc/jtransfer/rclone.conf copy \
  hetzner-storagebox:jtransfer-backups/jtransfer-<stamp>.dump.age ./

# 2. Decrypt
age -d -i ~/.config/age/jtransfer-backup.key \
  jtransfer-<stamp>.dump.age > restored.dump

# 3. Restore into a scratch database
createdb jtransfer_restore_test
pg_restore --clean --if-exists --no-owner --no-privileges \
  --dbname "postgres://...jtransfer_restore_test" restored.dump

# 4. Spot-check tables
psql "postgres://...jtransfer_restore_test" -c "\dt"
psql "postgres://...jtransfer_restore_test" -c "SELECT count(*) FROM transfers;"

# 5. Drop the scratch database
dropdb jtransfer_restore_test
```

## Operations

- **Schedule:** 03:00 UTC daily, with a 5-minute randomized delay.
- **Retention:** 30 days on the Storage Box (configurable via `RETENTION_DAYS`).
- **Failure visibility:** the systemd unit's exit code drives journald. Hook
  monitoring to `journalctl --identifier=jtransfer-backup` or to
  `systemctl is-failed jtransfer-backup.service` from a probe.
- **Key rotation:** generate a new keypair, append the new public key to
  `age-recipients.txt` (keeping the old one for a transition window so old
  backups stay decryptable), redeploy, then drop the old recipient after the
  retention window passes.
