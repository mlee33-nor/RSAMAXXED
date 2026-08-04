# RSAMAXXED Cloud

The marketing site and customer dashboard for the RSAMAXXED / RSAMAXXED desktop app.
FastAPI + Postgres + server-rendered Jinja. No JS framework, no CDN — the charts
are inline SVG generated in Python.

```
web/
  app/
    main.py        FastAPI app, middleware, security headers
    config.py      env-driven settings
    db.py          engine/session (Postgres, SQLite fallback)
    models.py      User, Device, PairingCode, Trade, HoldingSnapshot
    types.py       UtcDateTime — aware UTC on every backend
    security.py    scrypt passwords, bearer tokens, pairing codes, CSRF
    analytics.py   realized P/L, mirrored from app.py:3048
    charts.py      inline-SVG chart generation
    routes/        site, auth, dashboard, api
    templates/     Jinja
    static/css/
  tests/
```

## How a customer's desktop app reaches their account

One EXE for everybody. No secrets are baked into the build — only the public
API URL (`cloud_sync.DEFAULT_BASE_URL`, overridable with `RSAMAXXED_CLOUD_URL`).

```
desktop                          server                        browser
   |  POST /devices/pair/start      |                              |
   |------------------------------->|  invents code K7M2QX         |
   |<-- {code, poll_token} ---------|  (server-side, so it's        |
   |                                |   verifiable)                |
   |  shows K7M2QX                  |                              |
   |  POST /pair/poll  (every 3s)   |                              |
   |<-- {status: pending} ----------|                              |
   |                                |<--- user types K7M2QX -------|
   |                                |     while logged in           |
   |                                |  binds pairing -> user_id     |
   |                                |  mints device_token           |
   |  POST /pair/poll               |                              |
   |<-- {status: claimed, token} ---|  (single pickup, then cleared)|
   |                                |                              |
   |  POST /sync/trades             |                              |
   |    Authorization: Bearer ...   |  token -> device -> user_id   |
   |                                |  every row written scoped     |
```

The device token is the *only* thing that identifies a customer's data. It is
stored as a SHA-256 digest; the plaintext exists on the customer's machine in
`cloud_state.json` and nowhere else. Revoking a device on the Devices page makes
its token 401 immediately.

**Broker credentials never leave the customer's computer.** `cloud_sync.py` does
not import any broker module and never reads `.env` or `sessions/`. Uploaded
fields are whitelisted in `cloud_sync._ALLOWED`.

## The one invariant

`app/analytics.py` is a line-for-line mirror of `App._portfolio_summary()` in
`app.py:3048`. If you change the P/L math in one, change it in the other.
`tests/test_analytics.py` keeps a verbatim copy of the desktop function and
fails the build if the two ever disagree — including against the real
`trades.json` when one is present.

Realized-only, per symbol, all-time basis:

```
avg_buy  = total buy cost / total buy qty
avg_sell = total sell rev / total sell qty
profit   = (avg_sell - avg_buy) * total sell qty
```

A buy recorded with `fill_price: null` gets a $0 basis, so its sell books the
full proceeds as profit. The dashboard flags those symbols rather than hiding
or dropping them.

## Local development

```bash
cd web
pip install -r requirements.txt
export SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
uvicorn app.main:app --reload
```

With no `DATABASE_URL`, it creates `web/local.db` (SQLite). Open
http://127.0.0.1:8000.

To pair a locally-running desktop app against it:

```bash
RSAMAXXED_CLOUD_URL=http://127.0.0.1:8000 python app.py
```

Tests:

```bash
cd web && python -m pytest tests/ -q
```

## Deploying to Railway

1. **New Project → Deploy from GitHub repo** → `mlee33-nor/RSAMAXXED`.
2. In the service's **Settings → Source**, set **Root Directory** to `web`.
   Railway then sees `web/requirements.txt` and `web/railway.json` and ignores
   the desktop app's heavy broker dependencies.
3. **Add a Postgres database** to the project (`+ New → Database → Postgres`).
   Railway injects `DATABASE_URL` into the web service automatically.
4. Set service **Variables**:

   | Variable | Value |
   |---|---|
   | `SECRET_KEY` | `python -c "import secrets;print(secrets.token_urlsafe(48))"` |
   | `ENV` | `production` |
   | `PUBLIC_BASE_URL` | your Railway domain, e.g. `https://rsamaxxed.up.railway.app` |
   | `OPEN_SIGNUP` | `1` while testing; `0` + `INVITE_CODE` to lock signups |

   `SECRET_KEY` is mandatory in production — the app refuses to boot without it,
   because an ephemeral key would forge-able across restarts and log everyone
   out on each deploy. Rotating it invalidates all sessions.
5. **Settings → Networking → Generate Domain**.
6. Put that domain in `cloud_sync.DEFAULT_BASE_URL` (repo root), commit, and
   rebuild the EXE so customers point at the live API.

Health check is at `/healthz`.

### Schema changes

`init_db()` runs `create_all()` on startup, which creates missing tables but
never alters existing ones. That's fine for a single service. Before the first
schema *change* on live customer data, switch to Alembic — `create_all` will
silently do nothing and you'll debug a phantom column.

## Security posture

- scrypt password hashing (n=2^15, r=8), with an explicit `maxmem` because
  OpenSSL caps scrypt at 32 MB by default and n=2^15 needs more.
- Login is constant-time with respect to whether the email exists.
- Session fixation defeated by clearing the session on login/signup.
- CSRF token on every state-changing form.
- Bearer tokens and pairing codes stored only as SHA-256 digests.
- Pairing codes: 30-symbol alphabet minus look-alikes, 6 chars (729M), 10-minute
  TTL, single use, 5 failed claims per user per 15 minutes.
- `SameSite=Lax`, `HttpOnly`, `Secure` (in prod) session cookie.
- CSP with no external origins, `frame-ancestors 'none'`, HSTS in prod.
- Every customer-data query filters on `user_id`; `tests/test_e2e.py` asserts a
  second account sees an empty dashboard.
