# Deploying domain-infra to Railway

This repo is configured for one-click Railway deploy from `Dockerfile` + `railway.json`.

## One-time setup

1. **Create the Railway project**
   - Go to [railway.app/new](https://railway.app/new) → **Deploy from GitHub repo** → pick `naanyas/domain-infra`.
   - Railway auto-detects the `Dockerfile` and `railway.json`.

2. **Add a Postgres database**
   - In the project, click **+ New** → **Database** → **Postgres**.
   - Railway provisions it and exposes `DATABASE_URL` and the discrete `PG*` vars to the service.

3. **Set environment variables on the web service**
   Click into the `domain-infra` service → **Variables** tab → add:

   ```
   DJANGO_SECRET_KEY=<generate a long random string>
   DJANGO_DEBUG=false
   DJANGO_ALLOWED_HOSTS=<your-railway-app>.up.railway.app
   DJANGO_LOG_LEVEL=INFO

   POSTGRES_DB=${{ Postgres.PGDATABASE }}
   POSTGRES_USER=${{ Postgres.PGUSER }}
   POSTGRES_PASSWORD=${{ Postgres.PGPASSWORD }}
   POSTGRES_HOST=${{ Postgres.PGHOST }}
   POSTGRES_PORT=${{ Postgres.PGPORT }}
   POSTGRES_SSLMODE=require
   ```

   For the analyzer's enrichment vendors (optional — the analyzer degrades gracefully if missing):

   ```
   IPQS_API_KEY=
   MAXMIND_LICENSE_KEY=
   MAXMIND_ACCOUNT_ID=
   VIRUSTOTAL_API_KEY=
   ```

4. **Generate a public URL**
   - Service → **Settings** → **Networking** → **Generate Domain**.
   - Add that domain to `DJANGO_ALLOWED_HOSTS`.

5. **Deploy**
   - Railway redeploys on every push to `main` (auto-deploy is on by default).
   - First deploy runs `entrypoint.sh`: migrations → optional GeoIP refresh → gunicorn.

## Verifying the deploy

Once live:

```bash
curl -sI https://<your-app>.up.railway.app/admin/login/
# expect HTTP 200 with HTML response
```

To seed an org + API key for using the API:

```bash
# In Railway service → "Deployments" → click the running deploy → Shell tab
python manage.py shell
>>> from apps.organizations.models import Organization, ApiKey
>>> org = Organization.objects.create(name="Demo")
>>> key = ApiKey.objects.create(organization=org, name="demo-key")
>>> print(key.raw_key)  # save this — it's hashed in DB
```

Test the endpoint:

```bash
curl -X POST https://<your-app>.up.railway.app/api/v1/submissions?wait=true \
  -H "Authorization: ApiKey <your-key>" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## Cost

- **Hobby plan**: $5/month base credit. Postgres + a small web service = ~$5–10/month depending on traffic.
- The Dockerfile uses `python:3.13-slim`; idle memory is well under the free-tier ceiling.
