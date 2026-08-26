#!/usr/bin/env bash
# Nightly backup: dumps Postgres and archives uploaded images, keeps the
# last KEEP_DAYS locally. Self-hosting means you no longer get Supabase's
# automatic backups, so this (plus copying backups off this machine) is
# what replaces that. Run this daily via cron.
#
# Requires a ~/.pgpass entry for the app user so pg_dump doesn't need a
# password on the command line, e.g. one line in /home/rgcapp/.pgpass:
#   localhost:5432:rgc:rgc:your-db-password
# then: chmod 600 /home/rgcapp/.pgpass
set -euo pipefail

APP_DIR="/opt/rgcdoortodoor"
BACKUP_DIR="/opt/rgcdoortodoor/backups"
DB_NAME="rgc"
DB_USER="rgc"
KEEP_DAYS=14
STAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$BACKUP_DIR"

pg_dump -h 127.0.0.1 -U "$DB_USER" "$DB_NAME" | gzip > "$BACKUP_DIR/db-$STAMP.sql.gz"

if [[ -d "$APP_DIR/static/uploads" || -d "$APP_DIR/static/branding" ]]; then
    tar -czf "$BACKUP_DIR/uploads-$STAMP.tar.gz" -C "$APP_DIR/static" \
        $(cd "$APP_DIR/static" && ls -d uploads branding 2>/dev/null)
fi

find "$BACKUP_DIR" -type f -mtime +"$KEEP_DAYS" -delete

# IMPORTANT: the two lines above only protect you from a bad deploy or a
# fat-fingered delete — they still live on the same disk as everything
# else. For real protection against this machine dying (power supply,
# drive failure, house fire), copy the newest backup files somewhere else
# too, e.g. with rclone to a free-tier cloud storage account:
#   rclone copy "$BACKUP_DIR/db-$STAMP.sql.gz" remote:rgc-backups/
#   rclone copy "$BACKUP_DIR/uploads-$STAMP.tar.gz" remote:rgc-backups/

echo "$(date -Is) Backup complete: db-$STAMP.sql.gz$( [[ -f "$BACKUP_DIR/uploads-$STAMP.tar.gz" ]] && echo ", uploads-$STAMP.tar.gz" )"
