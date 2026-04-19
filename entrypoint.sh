#!/usr/bin/env bash
set -euo pipefail

echo "[entrypoint] applying migrations..."
python manage.py migrate --noinput

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
