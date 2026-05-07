# JTransfer Postgres Backups

Daily off-VPS Postgres backups, encrypted at rest with [age](https://age-encryption.org)
and pushed to a [Scaleway Object Storage](https://www.scaleway.com/en/object-storage/)
bucket via [rclone](https://rclone.org).

The Postgres database holds transfer metadata only (encrypted file blobs live in R2,
keyed by data the database knows about). Losing this database means losing the index
needed to look up, expire, and serve every active transfer.

## Threat model

- Encrypted dumps are uploaded to a third-party object store. Scaleway can read the
  ciphertext but not the plaintext (age recipient is a key Scaleway does not hold).
- The age private key is held by the operator only. If the private key is lost,
  every backup becomes unreadable. Treat its loss as equivalent to losing the
  database.
- Bucket-level Object Lock + versioning prevent accidental or malicious deletion
  within the retention window even if rclone credentials leak.

## Bucket configuration (Scaleway console)

Set up once, in the Scaleway console:

- **Region:** Amsterdam (`nl-ams`).
- **Storage class:** Standard Multi-AZ.
- **Visibility:** Private.
- **Versioning:** enabled.
- **Bucket encryption:** SSE-ONE.
- **Object Lock:** enabled at bucket creation (governance or compliance mode).
- **Lifecycle rules:**
  - Expire current versions after 30 days.
  - Expire non-current versions 30 days after they become non-current.
  - Abort incomplete multipart uploads after 7 days.

Total time from upload to actual purge ≈ 60 days, which is the recovery window
if a malicious or accidental deletion is noticed late.

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

### 3. Generate Scaleway API credentials

In the Scaleway console: **IAM → API keys → Generate new API key**.

- Scope to a dedicated application or user that only has access to the backup
  bucket. Avoid using your main account API key.
- Save the access key (starts with `SCW...`) and secret key.
- These go into `/etc/jtransfer/rclone.conf` on the VPS.

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

Paste in the access key and secret key from step 3. Test connectivity:

```bash
sudo rclone --config /etc/jtransfer/rclone.conf lsd scaleway-backups:
```

You should see your bucket listed.

### 6. Drop the env file

```bash
sudo cp infra/backups/backup.env.example /etc/jtransfer/backup.env
sudo chmod 600 /etc/jtransfer/backup.env
sudo $EDITOR /etc/jtransfer/backup.env
```

Fill in `DATABASE_URL` and `RCLONE_REMOTE` (set this to
`scaleway-backups:<your-bucket-name>`).

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
sudo rclone --config /etc/jtransfer/rclone.conf ls scaleway-backups:<your-bucket-name>
```

You should see a new `jtransfer-YYYYMMDDTHHMMSSZ.dump.age` object.

## Restore drill

Run periodically (target: monthly) to verify backups are usable.

```bash
# 1. Pull a recent backup
rclone --config /etc/jtransfer/rclone.conf copy \
  scaleway-backups:<bucket>/jtransfer-<stamp>.dump.age ./

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
- **Retention:** enforced by the bucket's lifecycle policy (30 days current +
  30 days non-current). The script does not delete objects.
- **Failure visibility:** the systemd unit's exit code drives journald. Hook
  monitoring to `journalctl --identifier=jtransfer-backup` or to
  `systemctl is-failed jtransfer-backup.service` from a probe.
- **Key rotation:** generate a new keypair, append the new public key to
  `age-recipients.txt` (keeping the old one for a transition window so old
  backups stay decryptable), redeploy, then drop the old recipient after the
  retention window passes.
