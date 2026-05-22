#!/usr/bin/env bash
set -euo pipefail

echo "[entrypoint] applying migrations..."
python manage.py migrate --noinput

# Idempotent superuser bootstrap. Only acts on first deploy when the user
# doesn't exist; subsequent deploys skip silently. Driven by env vars:
#   DJANGO_SUPERUSER_USERNAME, DJANGO_SUPERUSER_EMAIL, DJANGO_SUPERUSER_PASSWORD
if [[ -n "${DJANGO_SUPERUSER_USERNAME:-}" && -n "${DJANGO_SUPERUSER_PASSWORD:-}" ]]; then
    echo "[entrypoint] ensuring superuser '${DJANGO_SUPERUSER_USERNAME}' exists..."
    python manage.py createsuperuser --no-input 2>&1 \
        | grep -v "already exists" \
        || echo "[entrypoint] superuser already exists; skipping"
fi

if [[ -n "${MAXMIND_LICENSE_KEY:-}" ]]; then
    # Refresh MMDBs only if missing (weekly cron in prod should keep them current)
    if [[ ! -f "${MAXMIND_DB_DIR:-./geoip}/GeoLite2-City.mmdb" ]]; then
        echo "[entrypoint] downloading MaxMind GeoLite2 databases..."
        python manage.py update_geoip || echo "[entrypoint] update_geoip failed — continuing"
    else
        echo "[entrypoint] MaxMind MMDBs already present; skipping download"
    fi
else
    echo "[entrypoint] MAXMIND_LICENSE_KEY not set — skipping MMDB download"
fi

echo "[entrypoint] starting gunicorn..."
exec gunicorn \
    --bind "0.0.0.0:${PORT:-8000}" \
    --workers "${GUNICORN_WORKERS:-2}" \
    --threads "${GUNICORN_THREADS:-4}" \
    --timeout "${GUNICORN_TIMEOUT:-120}" \
    --access-logfile - \
    --error-logfile - \
    domain_infra.wsgi:application
