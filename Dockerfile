# ----------------------------------------------------------------------
# Build image: Python 3.13 slim (3.14 support across extensions is still
# uneven in containers; 3.13 is faster + more reliable for prod).
# ----------------------------------------------------------------------
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# System deps: build toolchain for psycopg/lxml, curl for healthchecks + MMDB download
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

# Static files collection (no-op for API-only today; future-proofs for admin assets)
RUN python manage.py collectstatic --noinput || echo "collectstatic: skipped"

EXPOSE 8000

# Entrypoint: migrate + refresh MaxMind MMDBs (idempotent) + launch gunicorn.
# Wrapped so the container handles schema drift + GeoIP refresh on every deploy.
COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
