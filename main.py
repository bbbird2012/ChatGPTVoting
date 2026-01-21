import os
import smtplib
import time
from typing import Any, Dict, Optional
from email.message import EmailMessage

import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.openapi.utils import get_openapi
from fastapi.security import APIKeyHeader
from jose import jwt
from pydantic import BaseModel
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError

# Load environment variables from .env if present.
load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")
JWT_ISSUER = os.environ.get("JWT_ISSUER")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE")
JWKS_URL = os.environ.get("JWKS_URL")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
PUBLIC_URL = os.environ.get("PUBLIC_URL")
VOTE_API_KEY = os.environ.get("VOTE_API_KEY")
REPORT_EMAIL_TO = os.environ.get("REPORT_EMAIL_TO")
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = os.environ.get("SMTP_PORT")
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM")
REPORT_API_KEY = os.environ.get("REPORT_API_KEY")

JWKS_TTL_SECONDS = 3600

# Default to local SQLite for dev.
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./dev.db"

# Normalize Postgres URL for psycopg v3.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL, pool_pre_ping=True, connect_args=connect_args
)

if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# Ensure we have a fully qualified public URL for OpenAPI servers.
def _normalize_public_url(raw_url: Optional[str]) -> Optional[str]:
    if not raw_url:
        return None
    if raw_url.startswith("http://") or raw_url.startswith("https://"):
        return raw_url
    return f"https://{raw_url}"


_PUBLIC_URL = (
    _normalize_public_url(PUBLIC_URL)
    or _normalize_public_url(os.environ.get("RAILWAY_PUBLIC_DOMAIN"))
    or _normalize_public_url(os.environ.get("RAILWAY_URL"))
)

app = FastAPI(title="ChatGPT Voting API")


# OpenAPI customization for GPT Actions.
def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    if _PUBLIC_URL:
        schema["servers"] = [{"url": _PUBLIC_URL}]
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = _custom_openapi

_jwks_cache: Optional[Dict[str, Any]] = None
_jwks_cache_expiry = 0.0


# Add missing columns safely for SQLite/Postgres.
def _ensure_column(
    conn, table: str, column: str, column_type: str, is_sqlite: bool
) -> None:
    if is_sqlite:
        row = conn.execute(
            text(f"PRAGMA table_info({table})")
        ).fetchall()
        exists = any(r[1] == column for r in row)
    else:
        row = conn.execute(
            text(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = :table_name
                  AND column_name = :column_name
                """
            ),
            {"table_name": table, "column_name": column},
        ).fetchone()
        exists = row is not None
    if not exists:
        conn.execute(
            text(
                f"ALTER TABLE {table} ADD COLUMN {column} {column_type}"
            )
        )


# Create tables and ensure required columns exist.
def init_db() -> None:
    is_sqlite = DATABASE_URL.startswith("sqlite")
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS submissions (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  url TEXT NOT NULL,
                  team_name TEXT,
                  track TEXT,
                  description TEXT
                )
                """
            )
        )
        _ensure_column(conn, "submissions", "team_name", "TEXT", is_sqlite)
        _ensure_column(conn, "submissions", "track", "TEXT", is_sqlite)
        _ensure_column(conn, "submissions", "description", "TEXT", is_sqlite)
        votes_sql = """
            CREATE TABLE IF NOT EXISTS votes (
              user_id TEXT PRIMARY KEY,
              submission_id TEXT NOT NULL REFERENCES submissions(id),
              api_key TEXT,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        if is_sqlite:
            votes_sql = """
                CREATE TABLE IF NOT EXISTS votes (
                  user_id TEXT PRIMARY KEY,
                  submission_id TEXT NOT NULL REFERENCES submissions(id),
                  api_key TEXT,
                  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
        conn.execute(
            text(votes_sql)
        )
        _ensure_column(conn, "votes", "api_key", "TEXT", is_sqlite)
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS settings (
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO settings(key, value) VALUES ('voting_open', 'true')
                ON CONFLICT (key) DO NOTHING
                """
            )
        )


@app.on_event("startup")
# Run DB init on startup.
def on_startup() -> None:
    init_db()


# Require environment variables for critical config.
def _require_env(name: str, value: Optional[str]) -> str:
    if not value:
        raise HTTPException(500, f"Missing required environment variable: {name}")
    return value


# Fetch and cache JWKS for JWT verification.
def get_jwks() -> Dict[str, Any]:
    global _jwks_cache, _jwks_cache_expiry

    jwks_url = _require_env("JWKS_URL", JWKS_URL)
    now = time.time()
    if _jwks_cache and now < _jwks_cache_expiry:
        return _jwks_cache

    response = requests.get(jwks_url, timeout=10)
    response.raise_for_status()
    _jwks_cache = response.json()
    _jwks_cache_expiry = now + JWKS_TTL_SECONDS
    return _jwks_cache


# Verify bearer token using JWKS.
def verify_bearer(authorization: Optional[str]) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")

    token = authorization.split(" ", 1)[1]
    jwks = get_jwks()
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")

    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if not key:
        raise HTTPException(401, "Invalid token key id")

    issuer = _require_env("JWT_ISSUER", JWT_ISSUER)
    audience = _require_env("JWT_AUDIENCE", JWT_AUDIENCE)

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[unverified_header.get("alg", "RS256")],
            audience=audience,
            issuer=issuer,
        )
        return claims
    except Exception:
        raise HTTPException(401, "Token verification failed")


# Extract user id from JWT claims.
def get_user_id(authorization: Optional[str]) -> str:
    claims = verify_bearer(authorization)
    user_id = claims.get("sub") or claims.get("email") or claims.get("preferred_username")
    if not user_id:
        raise HTTPException(401, "No user identifier in token")
    return str(user_id)


# Check voting status from settings.
def voting_open() -> bool:
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT value FROM settings WHERE key = 'voting_open'")
        ).fetchone()
    if not row:
        return True
    return str(row[0]).lower() == "true"


# Request model for voting.
class VoteIn(BaseModel):
    submission_id: str


# Health response model.
class HealthOut(BaseModel):
    status: str


# Submission response model.
class SubmissionOut(BaseModel):
    id: str
    name: str
    url: str
    team_name: Optional[str] = None
    track: Optional[str] = None
    description: Optional[str] = None


# Submissions response wrapper.
class SubmissionsOut(BaseModel):
    submissions: list[SubmissionOut]


# Vote response model.
class VoteOut(BaseModel):
    ok: bool


# Result item model.
class ResultOut(BaseModel):
    id: str
    name: str
    votes: int


# Results response wrapper.
class ResultsOut(BaseModel):
    voting_open: bool
    results: list[ResultOut]


# Admin close response model.
class CloseOut(BaseModel):
    ok: bool


# Report request model.
class ReportIn(BaseModel):
    message: str
    user_input: Optional[str] = None
    context: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


# Report response model.
class ReportOut(BaseModel):
    ok: bool


# API key header for GPT Actions.
_vote_key_header = APIKeyHeader(name="X-Vote-Key", auto_error=False)


@app.get("/health", response_model=HealthOut)
# Health check endpoint.
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/submissions", response_model=SubmissionsOut)
# List all submissions.
def list_submissions() -> Dict[str, Any]:
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, name, url, team_name, track, description
                FROM submissions
                ORDER BY name
                """
            )
        ).fetchall()
    return {
        "submissions": [
            {
                "id": r[0],
                "name": r[1],
                "url": r[2],
                "team_name": r[3],
                "track": r[4],
                "description": r[5],
            }
            for r in rows
        ]
    }


@app.post("/vote", response_model=VoteOut)
# Cast a vote for a submission.
def cast_vote(
    payload: VoteIn,
    request: Request,
    api_key: Optional[str] = Depends(_vote_key_header),
) -> Dict[str, bool]:
    if not voting_open():
        raise HTTPException(403, "Voting is closed")

    token = request.headers.get("authorization")
    api_key_value = None
    if token:
        claims = verify_bearer(token)
        user_id = (
            claims.get("sub")
            or claims.get("email")
            or claims.get("preferred_username")
        )
        if not user_id:
            raise HTTPException(401, "No user identifier in token")
        user_id = str(user_id)
    else:
        if VOTE_API_KEY:
            if api_key != VOTE_API_KEY:
                raise HTTPException(401, "Not authorized")
            user_id = f"api-key:{api_key}"
            api_key_value = api_key
        else:
            user_id = get_user_id(token)

    with engine.begin() as conn:
        submission = conn.execute(
            text("SELECT 1 FROM submissions WHERE id = :id"),
            {"id": payload.submission_id},
        ).fetchone()
        if not submission:
            raise HTTPException(400, "Invalid submission_id")

        try:
            conn.execute(
                text(
                    """
                    INSERT INTO votes(user_id, submission_id, api_key)
                    VALUES (:u, :s, :k)
                    """
                ),
                {
                    "u": user_id,
                    "s": payload.submission_id,
                    "k": api_key_value,
                },
            )
        except IntegrityError:
            raise HTTPException(409, "You have already voted")

    return {"ok": True}


@app.get("/results", response_model=ResultsOut)
# Return results when voting is closed.
def results() -> Dict[str, Any]:
    if voting_open():
        return {"voting_open": True, "results": []}

    with engine.begin() as conn:
        rows = conn.execute(
            text(
                """
                SELECT s.id, s.name, COUNT(v.user_id) AS votes
                FROM submissions s
                LEFT JOIN votes v ON v.submission_id = s.id
                GROUP BY s.id, s.name
                ORDER BY votes DESC, s.name
                """
            )
        ).fetchall()

    return {
        "voting_open": False,
        "results": [
            {"id": r[0], "name": r[1], "votes": int(r[2])} for r in rows
        ]
    }


@app.post("/admin/close", response_model=CloseOut)
# Close voting (admin-only).
def admin_close(
    request: Request,
    api_key: Optional[str] = Depends(_vote_key_header),
) -> Dict[str, bool]:
    secret = _require_env("ADMIN_SECRET", ADMIN_SECRET)
    header_value = api_key or request.headers.get("x-admin-secret")
    if header_value != secret:
        raise HTTPException(401, "Not authorized")

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO settings(key, value) VALUES ('voting_open', 'false')
                ON CONFLICT (key) DO UPDATE SET value = 'false'
                """
            )
        )

    return {"ok": True}


@app.post("/report", response_model=ReportOut)
# Email a security incident report.
def report_incident(
    payload: ReportIn,
    request: Request,
    api_key: Optional[str] = Depends(_vote_key_header),
) -> Dict[str, bool]:
    if REPORT_API_KEY or VOTE_API_KEY:
        if api_key not in {REPORT_API_KEY, VOTE_API_KEY}:
            raise HTTPException(401, "Not authorized")
    if not REPORT_EMAIL_TO:
        raise HTTPException(500, "REPORT_EMAIL_TO is not configured")
    if not SMTP_HOST or not SMTP_PORT or not SMTP_FROM:
        raise HTTPException(500, "SMTP is not configured")

    msg = EmailMessage()
    msg["Subject"] = "GPT Security Incident Report"
    msg["From"] = SMTP_FROM
    msg["To"] = REPORT_EMAIL_TO

    client_host = request.client.host if request.client else "unknown"
    body_lines = [
        f"Message: {payload.message}",
        f"User input: {payload.user_input or ''}",
        f"Context: {payload.context or ''}",
        f"Metadata: {payload.metadata or {}}",
        f"Client IP: {client_host}",
    ]
    msg.set_content("\n".join(body_lines))

    with smtplib.SMTP(SMTP_HOST, int(SMTP_PORT)) as server:
        server.starttls()
        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)

    return {"ok": True}
