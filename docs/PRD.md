# domain-infra — Product Requirements Document

**Status:** Living document. Updated as decisions land.
**Last updated:** 2026-04-19
**Owner:** Jenna Webb

---

## 1. Executive Summary

**domain-infra** is a multi-tenant fraud-detection API that evaluates *signup submissions* — the full packet of signals a bad actor provides when registering on a platform (domain, contact email, contact name, contact phone, submitter IP, device fingerprint). Customers POST a submission and receive a structured verdict (`approve` / `deny` / `review`) with reason codes, underlying signals, and cross-customer reputation context.

The product is modeled on eHawk and extends it with:

- **Submission-event coverage** — we evaluate the whole signup, not just the domain
- **Fingerprint reputation network** — cross-customer pattern matching (exact + fuzzy)
- **Community feedback loop** — customers teach the system when it's wrong
- **Risk profiles** — per-customer policy for how signals map to decisions
- **API-first** — built to be embedded in automated signup flows, not a human-analyst console

Customers are Trust & Safety / fraud teams at marketplaces, fintech, SaaS platforms, and any company with a signup surface where bad actors apply. The product IS the decision — not a review-queue tool.

---

## 2. Problem Statements & Resolutions

### P1. Signals are evaluated in isolation

**Problem.** When a user signs up, fraud teams check the domain *or* the email *or* the IP separately — with different tools, different dashboards, and no unified scoring. A submission where *every individual signal looks fine* but the *combination* is suspicious (e.g. a clean domain + disposable email + VPN IP) slips through.

**Resolution.** A single `POST /submissions` endpoint accepts the full signup packet and evaluates every signal in one pass, returning a verdict that aggregates all of them. Customers don't have to integrate five tools and do their own scoring.

### P2. No cross-customer pattern sharing

**Problem.** A fraud ring registers 80 domains across 12 different customers using the same registrar, nameserver set, and email pattern. Each customer discovers this independently, weeks or months apart. The reputation a bad actor builds up with Customer A is invisible to Customer B.

**Resolution.** Normalized entity tables (IPs, nameservers, registrars, ASNs, certificates, MX hosts, contact emails, contact names, contact phones, submitter IPs) are shared across tenants. Every entity carries a cross-customer reputation counter — "this nameserver has been flagged 17 times across our network in the last 90 days." Customer data stays isolated; entity-level patterns become a shared intelligence layer.

### P3. Manual review doesn't scale, and isn't defensible

**Problem.** Existing tools surface signals and push the decision onto a human analyst. Review queues balloon during growth events. Decisions aren't reproducible — two analysts looking at the same submission may decide differently.

**Resolution.** The system makes the decision. Every verdict is reproducible: it snapshots the exact risk profile + signals that produced it, so the decision can be replayed and audited. Customers CAN override manually, but that's an optional workflow on top — not the primary mode.

### P4. Existing tools are analyst consoles, not API primitives

**Problem.** Domain intelligence products are built for humans to log into and search. Embedding them in a real-time signup flow means scraping HTML or building brittle automation on top of tools that weren't designed for it.

**Resolution.** API-first from day 1. Synchronous endpoint for fastest per-submission latency (`POST /submissions?wait=true`), async endpoints planned for bulk/high-volume. Clean JSON contract. Console is a Phase 3 layer on top, not the primary product.

### P5. Feedback loops are broken

**Problem.** When an automated decision is wrong (false positive locks out a good customer; false negative lets a scammer through), there's no way to tell the system. Customers work around it with internal rules; the underlying intelligence never improves.

**Resolution.** `POST /submissions/{id}/feedback` accepts structured corrections (`false_positive` / `false_negative` / `confirmed`) with reason codes and notes. Feedback updates fingerprint reputation in real time and feeds the ML training corpus. The customer who reports feedback benefits first, but the whole network benefits eventually.

### P6. Ephemeral infrastructure evades exact-match reputation

**Problem.** Sophisticated actors rotate one signal (swap the IP, change the registrar) to evade reputation systems that rely on exact matching. You see the same bad actor 20 times and treat each as a new domain.

**Resolution.** Two fingerprint types per submission:
1. **Exact** — SHA hash of canonical signal set. Fast lookup for ring members who reuse infrastructure.
2. **Fuzzy** — MinHash / SimHash of feature vector. Surfaces the 20 nearest-neighbor submissions. Catches actors who vary 1–2 signals.

### P7. Customers have different threat models, same tool shouldn't score the same way

**Problem.** A dating app and a B2B SaaS have completely different fraud surfaces — the dating app cares deeply about phone-number authenticity, the SaaS cares about domain age. A one-size-fits-all scoring model underserves both.

**Resolution.** **Risk profiles** — org-scoped policy objects defining thresholds, per-signal weight overrides, and rule-based overrides ("if VPN AND email disposable → deny regardless of score"). Each submission snapshots the active profile at evaluation time for reproducibility.

---

## 3. User Personas

| Persona | Role | What they care about |
|---|---|---|
| **Taylor** — Trust & Safety Engineer | Integrates domain-infra into the signup flow | API reliability, latency, clean JSON contract, good docs |
| **Morgan** — Fraud Analyst | Investigates incidents, provides feedback | History search, entity drill-down, reason-code clarity, appeal-proof audit trail |
| **Priya** — Platform PM | Evaluates / buys the product | Time-to-first-value, pricing transparency, case studies, network effect story |
| **Dana** — CISO / Compliance | Signs off on the integration | Data residency, access logs, SOC2, GDPR posture, customer-data isolation |

---

## 4. User Stories

### Phase 1 (core API + history)

- **US-1.1** — As Taylor, I want to POST a signup submission and receive a verdict within 30 seconds, so that I can block fraud at the point of signup without adding latency users will notice.
- **US-1.2** — As Taylor, I want org-scoped API keys with prefix-visible identifiers (e.g. `di_a4f2…`), so that I can rotate and revoke access without downtime.
- **US-1.3** — As Morgan, I want to GET a list of every submission my org has made with their verdicts, timestamps, and the signals that drove each decision, so that I can audit and appeal.
- **US-1.4** — As Morgan, I want to see the full normalized signal set behind each verdict (resolving IPs, nameservers, registrar, contact email reputation, submitter IP geolocation), so that I can explain a denial to a customer.
- **US-1.5** — As Taylor, I want to include an `external_ref` on each submission that maps to my internal user ID, so I can correlate verdicts with my system.

### Phase 2 (reputation + feedback + risk profiles + enrichment)

- **US-2.1** — As Morgan, I want to see "this nameserver has been flagged 17 times across 4 other customers in the last 90 days" attached to a verdict, so that I can trust the denial without re-investigating from scratch.
- **US-2.2** — As Morgan, I want to POST feedback when a verdict is wrong (false positive / false negative / confirmed), so that the system learns and future submissions are more accurate — and I get credit in the network for improving it.
- **US-2.3** — As Taylor, I want to configure a risk profile that weights contact email disposability and submitter IP VPN status higher than domain age, so that the verdict reflects my product's threat model.
- **US-2.4** — As Taylor, I want a rule in my risk profile that says "if submission IP is Tor AND contact email is disposable, always deny," so that I can encode non-negotiable policy regardless of the overall score.
- **US-2.5** — As Morgan, I want fuzzy fingerprint match results in every verdict ("20 similar submissions in network, 14 denied"), so that I catch actors who rotate one signal to evade exact matches.
- **US-2.6** — As Morgan, I want email-level enrichment (disposable flag, breach count, gravatar presence), so I can spot throwaway accounts without running separate tools.
- **US-2.7** — As Morgan, I want submitter-IP enrichment (geolocation, VPN/proxy/Tor/datacenter flags), so I can flag high-risk network origins at submission time.

### Phase 3 (console / dashboards)

- **US-3.1** — As Morgan, I want a web console where I can search submissions by email, domain, IP, or fingerprint, so I can investigate incidents visually without building my own UI.
- **US-3.2** — As Morgan, I want an entity detail page showing every submission involving that entity across our org, with timestamps and verdicts, so I can see fraud ring activity.
- **US-3.3** — As Priya, I want a dashboard showing approval / denial / review rates over time and top flagged entity types, so I can measure fraud pressure and present it to leadership.

### Phase 4 (ML layer)

- **US-4.1** — As Taylor, I want the system to flag submissions matching novel fraud patterns that don't trip any explicit rule, so that I catch emerging attacks before I've written a rule for them.
- **US-4.2** — As Morgan, I want confidence scores on every verdict (not just approve/deny), so I can prioritize my review queue by risk level.

---

## 5. Customer Journey

### 5.1 Discovery
A T&S engineer is losing to a new fraud pattern — signups with clean domains but suspicious email / IP combos. Their existing domain-only tool misses these. They search for "submission-level fraud API" or hear about domain-infra from a peer.

### 5.2 Evaluation (day 1)
Taylor signs up, receives API credentials for a sandbox org, and hits `POST /submissions?wait=true` with a known-bad test case from their own incident history. Verdict comes back with `deny` + specific reason codes + visible cross-customer reputation hits. They're convinced.

### 5.3 Onboarding (week 1)
Taylor's team wires the API into their signup flow. They start with the sync endpoint (`?wait=true`) for simplicity. A fraud analyst (Morgan) gets access to the admin console to browse submission history.

### 5.4 First Value (weeks 1–4)
Real submissions start flowing. The first time domain-infra blocks a fraud ring that would have cost them money, Priya asks Taylor to pull the verdict details for the post-mortem. The reasons + entity reputation data speak for themselves.

### 5.5 Expansion (months 1–3)
- Morgan notices a specific false-positive pattern and starts POSTing feedback. The false-positive rate drops week-over-week.
- Taylor configures a custom risk profile that weights email disposability higher (they're a consumer product).
- They migrate from sync-only to the async endpoint + webhook flow for their high-volume signup page.

### 5.6 Advocacy (months 3+)
- Priya presents results to leadership — X% fraud reduction, Y% false-positive reduction.
- They integrate with a second product surface (API access application workflow).
- They refer another company in their industry. The network grows. That referred customer's feedback further improves the reputation data for everyone — including the original referrer.

---

## 6. Functional Requirements (Phase 1)

### 6.1 API endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/submissions` | Create a submission. Returns `{submission_id, status: queued}` immediately. |
| `POST` | `/api/v1/submissions?wait=true` | Create a submission and block until complete (up to `SUBMISSION_SYNC_TIMEOUT_SECONDS`, default 60). Returns full verdict inline. |
| `GET` | `/api/v1/submissions/{id}` | Retrieve a submission with its verdict and underlying signals. |
| `GET` | `/api/v1/submissions` | List an org's submissions with pagination and filters (status, decision, date range, external_ref). |

### 6.2 Submission input schema

```json
{
  "domain": "example.com",
  "contact_email": "jane@example.com",
  "contact_name": "Jane Doe",
  "contact_phone": "+15555551212",
  "submitter_ip": "203.0.113.42",
  "device_fingerprint": "dfp_abc123",
  "external_ref": "customer-signup-id-12345",
  "metadata": { "arbitrary": "customer context" },
  "risk_profile_id": null
}
```

All fields except at least one signal are optional. A submission with no signals is rejected.

### 6.3 Submission output schema

```json
{
  "submission_id": "uuid",
  "status": "complete",
  "organization_id": "uuid",
  "verdict": {
    "decision": "deny",
    "score": 82,
    "summary": "...",
    "reasons": [
      {"code": "DOMAIN_NO_AUTH", "description": "No SPF/DKIM/DMARC configured", "weight": 15},
      {"code": "DOMAIN_YOUNG", "description": "Registered 3 days ago", "weight": 20}
    ]
  },
  "signals": {
    "domain": { /* DomainScan.raw_result — full analyzer output */ },
    "contact_email": { /* Phase 2 */ },
    "contact_phone": { /* Phase 2 */ },
    "submitter_ip": { /* Phase 2 */ }
  },
  "network_matches": { /* Phase 2: entity + fingerprint reputation hits */ },
  "created_at": "...",
  "completed_at": "..."
}
```

### 6.4 Authentication
- `Authorization: Bearer <api_key>` OR `X-API-Key: <api_key>` header.
- Keys are hashed (SHA-256) at rest. Only the 8-char prefix is stored cleartext for display.
- Keys can be revoked; revoked keys fail auth with a clear error.

### 6.5 Multi-tenancy
- Every persisted row is scoped to an `organization_id`.
- Entity rows (IPs, nameservers, etc.) are global but the join tables linking them to submissions are org-scoped.
- Cross-org queries are internal-only and surfaced back to customers as *aggregated* reputation counters ("flagged N times"), never as raw lists of other customers' submissions.

---

## 7. Data Model Overview

High-level (see `docs/SCHEMA.md` once generated from migrations):

- **organizations** — customer tenants
- **api_keys** — hashed, org-scoped
- **submissions** — top-level fraud-eval unit (domain + contacts + IP bundle)
- **domain_scans** — analyzer result, 0..1 per submission
- **verdicts** — system decision, 1 per submission, with optional human override
- **entities** (normalized, cross-tenant): `ip_addresses`, `nameservers`, `mx_hosts`, `registrars`, `asns`, `certificates`, `contact_emails`, `contact_names`, `contact_phones`, `submitter_ips`
- **join tables**: `domain_scan_ips`, `domain_scan_nameservers`, `domain_scan_mx_hosts`, `domain_scan_certificates` (submission↔entity for contact side is direct FK since a submission has one of each)
- **fingerprints** + `submission_fingerprints` + `fingerprint_reputations` — Phase 1 schema, Phase 2 logic
- **risk_profiles** — Phase 1 schema, Phase 2 engine
- **feedback** — Phase 1 schema, Phase 2 endpoint + reputation updates

---

## 8. Non-Functional Requirements

- **Latency.** Sync `POST /submissions?wait=true` returns within 60s. Median target: 10–15s (dominated by analyzer DNS/HTTP/WHOIS lookups).
- **Availability.** 99.5% Phase 1, 99.9% by end of Phase 2.
- **Security.** API keys hashed at rest. TLS everywhere. Audit log on all verdict reads + feedback submissions.
- **Data residency.** US-only region for launch. EU region plan in Phase 3.
- **Compliance.** SOC2 Type I targeted end of Phase 2. GDPR posture required if EU customers sign before Phase 3.
- **Tenant isolation.** Cross-tenant data leakage is the #1 product risk. Every API view + queryset must filter by `request.user.organization`.

---

## 9. Phasing

| Phase | Scope | Deliverables |
|---|---|---|
| **Phase 1** — Foundation | Schema + API + analyzer wrap | Django + Postgres scaffold. All tables migrated (including Phase 2 schema placeholders — no logic). `POST/GET /submissions` wrapping SDAT analyzer. API-key auth. Django admin. |
| **Phase 2** — Intelligence | Enrichment + fingerprinting + feedback + rules | Email/phone/IP enrichment vendors wired in. Fingerprint hashing + MinHash similarity search. Feedback endpoint. Risk profile rules engine. Cross-org entity reputation surfaced in verdicts. |
| **Phase 3** — Console | Customer-facing web UI | React/Next.js console: submission search, entity drill-down, reputation graph, dashboards. |
| **Phase 4** — Learning | ML layer | Supervised classifier trained on (signals, verdict, feedback) tuples. Unsupervised clustering for novel-pattern flagging. |

---

## 10. Phase 2 Enrichment Vendors (to evaluate)

| Signal | Candidates |
|---|---|
| Email validity + disposable + breach | Emailable, Kickbox, ZeroBounce, HaveIBeenPwned |
| Phone validity + carrier + line type | Twilio Lookup, Telesign, NumVerify |
| IP geolocation + VPN/proxy/Tor | MaxMind GeoIP2, IPinfo, IPQualityScore |
| Name / people enrichment | FullContact, People Data Labs |

Criteria: API quality, latency (need sub-2s responses), pricing per-lookup, data freshness, TOS compatibility with our use case.

---

## 11. Open Decisions

- [ ] Pricing model — per submission, tiered volume, or volume commit? (Target: before Phase 2 ships.)
- [ ] Hosting target — AWS? Render? Fly.io? (Target: before Phase 1 ships to the first real customer.)
- [ ] Async endpoint shape — polling (`GET /submissions/{id}`) only, or webhooks too? (Target: Phase 2.)
- [ ] Data retention — how long do we keep raw submission inputs vs derived signals? (Target: before first customer.)
- [ ] Python version — stay on 3.14.2 or fall back to 3.13 if compatibility issues arise? (Monitor during Phase 1.)

---

## 12. Decision Log

| Date | Decision | Rationale |
|---|---|---|
| 2026-04-19 | Stack: **Django + Postgres** wrapping existing Python analyzer; NOT Rails/Node. | Analyzer is 400KB of working Python. Rewriting wastes effort. Django gives Rails-feel in same language as engine. |
| 2026-04-19 | Repo name: **`domain-infra`**. | Descriptive, not marketing-locked. Can rename the product later without repo churn. |
| 2026-04-19 | **Multi-tenant from day 1.** Org + ApiKey scoping all persistence. | Adding later = painful migration. Selling to companies requires it. |
| 2026-04-19 | **Sync-first API** (`POST /submissions?wait=true`), async shape designed but deferred. | Fastest per-submission latency. Customers expect sync for simple integrations. Response shape forward-compatible with async. |
| 2026-04-19 | **Cross-org entity + fingerprint linking is a product feature**, not internal-only. Aggregated counters surfaced to customers. Raw lists never surfaced. | This is the moat. Community signal is what makes the product stick. |
| 2026-04-19 | **Scope is submission events**, not just domain scans. Domain is one signal among: email, name, phone, submitter IP, device fingerprint. | A domain looking clean while email+IP combo is fraudulent is the common miss pattern. |
| 2026-04-19 | **Risk profiles** (org-scoped policy + rules engine) in schema from Phase 1. | Every customer has a different threat model. One-size scoring underserves everyone. |
| 2026-04-19 | **Phase 2 schema lives in Phase 1** (fingerprints, feedback, risk_profiles, contact entities). Logic deferred; tables migrated. | Avoids painful migrations when Phase 2 ships. |
| 2026-04-19 | **System decision, not human review.** Human override is an optional workflow on top. | Customers buy this to automate, not to staff review queues. |
| 2026-04-19 | **Phase 1 code complete, migrations generated, validated.** 24 models across 6 apps. Django 5.2.13 on Python 3.14.2 — no compat issues. Analyzer vendored + patched to relative imports and imports cleanly as `from analyzer import analyze_domain` (v8.0.0). | Unblocks Postgres install + migrate + end-to-end smoke test. |
| 2026-04-19 | **Database lives on Neon (managed serverless Postgres), not on developer laptops.** Added `POSTGRES_SSLMODE` env var (default `prefer`; Neon uses `require`). Local Postgres is stopped; full uninstall pending. | Cleaner dev setup, shared DB for future collaborators, no data on personal laptops. Free tier sufficient for Phase 1 dev. |
| 2026-04-19 | **End-to-end verified against Neon.** `example.com` → submission UUID → analyzer runs in ~20s → verdict `approve` / score 0 / full signal set persisted. Same result as local run. | Phase 1 is live-and-working. Unblocks Phase 2 work (enrichment, fingerprints, feedback, rules engine). |
| 2026-04-19 | **Phase 3 console: everything tunable via UI.** Scoring weights, thresholds, rule conditions, reason-code taxonomy, reputation lookback windows, risk-profile assignment — all editable from the console with no JSON-editing required. Schema for these objects must be structured (enumerated signal names + operators) so a UI can render them as dropdowns/sliders. NOT configurable per customer: the canonical fingerprint formula (signal set + hashing) — stays global so cross-org reputation remains comparable across all tenants. | Direct customer ask (2026-04-19). Shapes A3 rules-engine schema and all Phase 3 UI work. |
| 2026-04-19 | **Phase 2 Part B — free-only enrichment complete.** Budget constraint: no paid vendors or trials. Added local email enricher (`disposable-email-domains` bundled blocklist for `is_disposable`; curated role-handle list for `is_role_account`; `dnspython` MX lookup for `mx_reachable`; Gravatar HEAD request for `has_gravatar`) and local phone enricher (`phonenumbers` bundled data for `country_code` / `line_type` / `carrier`). Verified: `admin@mailinator.com` → disposable=True + role=True + mx=True + gravatar=True; `alice@gmail.com` → all-false + mx_reachable=True; UK `+442079460958` → fixed_line. Paid enrichers (HIBP, Emailable, Twilio, PDL) intentionally deferred — same enricher-module pattern makes them drop-in later. |
| 2026-04-19 | **Phase 2 Part B — IP enrichment shipped (IPQS + MaxMind GeoLite2).** IPQS covers VPN/proxy/Tor flags on free tier; `connection_type` (datacenter) + `abuse_events` are premium-gated. MaxMind GeoLite2 downloaded locally (City 62MB + ASN 11MB + Country 9MB MMDBs at `<repo>/geoip/`) covers country/region/city/ASN for free with sub-ms local lookups, refreshed via `python manage.py update_geoip`. Pipeline order: MaxMind first (authoritative geo/ASN), IPQS second (VPN/proxy/Tor flags). Verified live: Hetzner IP `5.9.33.17` → `country=DE, city=Falkenstein, asn=AS24940 Hetzner Online GmbH, is_vpn=True, is_proxy=True`. | Unblocks risk-profile rules that key off `submitter_ip.is_vpn`, `submitter_ip.country`, etc. — all signals in the catalog now populate for real traffic. |
| 2026-04-19 | **Phase 2 Part A shipped end-to-end.** A1 fingerprinting + A2 feedback + A3 rules engine + A4 entity reputation. Pipeline is now: materialize contacts → run analyzer → compute+link fingerprints (no rep bump yet) → build signals dict → load active risk profile → evaluate rules (override baseline decision if matched) → persist verdict with risk-profile snapshot → bump fingerprint + entity reputation with final decision. Verified live: rule-match flips `approve` → `review` with full rule metadata in reasons; disable rule → reverts to baseline; `risk_profile_snapshot` captures rules + thresholds + eval timestamp for reproducibility; entity reputation (IPs, nameservers, contact emails) bumps correctly. Also fixed Phase 1 bug: `ns_records` analyzer field wasn't being extracted (was looking for `nameservers`). | Phase 2 Part A done without vendor signups. Unblocks Part B (enrichment) and Phase 3 (console UI against the signal-catalog endpoint). |
| 2026-04-19 | **Phase 2 A1 (Fingerprinting) shipped.** Two fingerprint kinds per submission: `infrastructure` (sha256 of NS set + MX set + resolving IPs + registrar + ASN + SPF qualifier + DMARC policy + TLS issuer) and `actor` (sha256 of email domain + phone country code (via `phonenumbers`) + name phonetic hash (jellyfish Metaphone) + device fingerprint). MinHash (`datasketch`, 128 permutations) feature vector stored alongside exact hash for fuzzy similarity. Naive nearest-neighbor Jaccard over recent 2000 fingerprints; swap for MinHashLSH or pgvector once volume forces it. Reputation counters (`flagged`/`approved`/`review` + normalized `reputation_score` in [-1, 1]) bump on every verdict. `network_matches` block in API responses surfaces primary fingerprint + exact-match count + aggregated reputation + top-20 fuzzy neighbors. Verified live: 3rd submission of `example.com` returned `exact_match_count=1`, `network_approved_count=2`, `reputation_score=1.0`; `iana.org` landed as a distinct infra fingerprint with no false fuzzy matches. | A1 was the leading-value piece of Phase 2 and the foundation for the community-signal moat. |

---

## 13. Local Setup & Smoke Test (Phase 1)

One-time local setup:

```bash
# 1. Install Postgres (macOS)
brew install postgresql@16
brew services start postgresql@16

# 2. Create the DB + user (one-liner, postgresql@16 exposes psql on path)
/opt/homebrew/opt/postgresql@16/bin/createuser -s domain_infra 2>/dev/null || true
/opt/homebrew/opt/postgresql@16/bin/createdb -O domain_infra domain_infra

# 3. Project setup (from repo root)
cd /Users/jennawebbpersonal/Documents/domain-infra
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edit Postgres password if not default
```

First run:

```bash
# 4. Migrate the schema
python manage.py makemigrations
python manage.py migrate

# 5. Seed a test org + API key (prints a raw key — copy it)
python manage.py bootstrap

# 6. (optional) admin user for the Django admin at /admin
python manage.py createsuperuser

# 7. Start the server
python manage.py runserver
```

Smoke test the API (sync mode returns the full verdict inline):

```bash
curl -sS -X POST "http://localhost:8000/api/v1/submissions?wait=true" \
  -H "X-API-Key: <paste the key from step 5>" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}' | python -m json.tool
```

Expected response shape: `{submission_id, status: "complete", verdict: {decision, score, summary, ...}, domain_scan: {recommendation, risk_score, raw_result: {...}}, ...}`.

List your org's submissions:

```bash
curl -sS "http://localhost:8000/api/v1/submissions" \
  -H "X-API-Key: <same key>" | python -m json.tool
```

Retrieve a single submission by id:

```bash
curl -sS "http://localhost:8000/api/v1/submissions/<uuid>" \
  -H "X-API-Key: <same key>" | python -m json.tool
```

---

## 14. Production Deploy (Render blueprint)

The repo ships a `Dockerfile`, `entrypoint.sh`, and `render.yaml` so the whole
service boots from a single blueprint.

**One-time steps (manual, ~10 minutes total):**

1. **Create a GitHub repo.** From a browser: [github.com/new](https://github.com/new) — suggested name `domain-infra`, visibility `Private`.
2. **Push the local repo up:**
   ```bash
   cd /Users/jennawebbpersonal/Documents/domain-infra
   git init && git add -A && git commit -m "Initial Phase 1 + Phase 2"
   git branch -M main
   git remote add origin git@github.com:<your-username>/domain-infra.git
   git push -u origin main
   ```
3. **Sign up at [render.com](https://render.com)** (free — GitHub OAuth is simplest).
4. **Create a Blueprint:** Render dashboard → **New** → **Blueprint** → pick your `domain-infra` repo → Render auto-detects `render.yaml` and proposes the service.
5. **Fill in the `sync: false` secrets** when prompted (Render won't let you skip):
   * `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_HOST` — from your Neon dashboard
   * `IPQS_API_KEY` / `MAXMIND_LICENSE_KEY` / `MAXMIND_ACCOUNT_ID` — from your respective vendor accounts
6. **Apply** the Blueprint. Render builds the Docker image (~3 min), runs migrations via `entrypoint.sh`, downloads MaxMind MMDBs into the container, and starts gunicorn.
7. **Test:**
   ```bash
   curl -X POST "https://<your-service>.onrender.com/api/v1/submissions?wait=true" \
     -H "X-API-Key: <same key>" -H "Content-Type: application/json" \
     -d '{"domain":"example.com"}'
   ```

**Plan notes:**

* `render.yaml` defaults to the `starter` plan ($7/mo). Change to `free` for zero-cost with 15-minute auto-sleep (fine for demos; painful for production).
* Neon's free tier is separate — the DB stays with Neon regardless of Render plan.
* Render persistent disk is not enabled; MaxMind MMDBs are re-downloaded on each container spin-up (fast over AWS backbone, but adds ~15s to cold start). Add a persistent disk + scheduled `update_geoip` job when you're ready for production SLAs.

**Ops cheat sheet:**

```bash
# Refresh MaxMind GeoLite2 databases (runs inside the container)
python manage.py update_geoip

# Backfill enrichment on rows that missed their first pass (e.g. after adding a new enricher)
python manage.py backfill_enrichment

# Create / refresh an API key for an org
python manage.py bootstrap --slug acme --name "Acme Corp" --label "prod"
```

---

## 15. Competitive / Reference Landscape

- **eHawk** — closest conceptual analog. Submission-event evaluation, community feedback, device/activity linking. We borrow the model and extend with: richer domain intelligence (from SDAT's analyzer), customer-configurable risk profiles, API-first positioning.
- **Sift / Signifyd / Arkose** — general fraud platforms. More focused on transaction fraud (payment / account takeover) than signup-surface domain/email/IP triangulation.
- **MaxMind minFraud** — overlaps on IP + email + device but no domain infrastructure depth.

Differentiator: deep domain infrastructure signals (from SDAT) + submission-event coverage + cross-customer reputation, sold as a clean API primitive.
