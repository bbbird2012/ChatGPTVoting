# ChatGPT Voting API

Small FastAPI service for an internal-only GPT voting flow. It enforces one vote per user via OIDC token verification and a unique vote per user in Postgres.

## Endpoints

- `GET /submissions` list all submission links
- `POST /vote` cast a vote (requires `Authorization: Bearer <token>`)
- `GET /results` returns totals after voting closes
- `POST /admin/close` closes voting (requires `x-admin-secret` header)
- `GET /health` basic health check

## Environment variables

- `DATABASE_URL` Postgres connection string (Railway provides this)
- `JWT_ISSUER` OIDC issuer (ex: Azure AD or Google Workspace issuer)
- `JWT_AUDIENCE` OAuth client ID / audience
- `JWKS_URL` issuer JWKS URL
- `ADMIN_SECRET` shared secret for admin close

## Database setup

The app auto-creates the required tables on startup.

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=sqlite:///./dev.db
export JWT_ISSUER=https://...
export JWT_AUDIENCE=...
export JWKS_URL=https://.../jwks.json
export ADMIN_SECRET=change-me
uvicorn main:app --reload
```

## Local development notes

- A local `.env` file is loaded automatically (if present).
- If `DATABASE_URL` is not set, the app defaults to `sqlite:///./dev.db`.

## GPT Actions notes

- Use OAuth for Actions so user identity is available.
- Configure your GPT instructions to call `GET /submissions` at session start, accept a single vote, then call `POST /vote`.
- Hide results until `POST /admin/close` flips voting to closed.
