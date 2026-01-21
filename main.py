import os
import time
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.openapi.utils import get_openapi
from fastapi.security import APIKeyHeader
from jose import jwt
from pydantic import BaseModel
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")
JWT_ISSUER = os.environ.get("JWT_ISSUER")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE")
JWKS_URL = os.environ.get("JWKS_URL")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
PUBLIC_URL = os.environ.get("PUBLIC_URL")
VOTE_API_KEY = os.environ.get("VOTE_API_KEY")

JWKS_TTL_SECONDS = 3600

if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./dev.db"

# Force SQLAlchemy to use psycopg v3 when on Postgres.
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
              user_full_name TEXT,
              user_email TEXT,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        if is_sqlite:
            votes_sql = """
                CREATE TABLE IF NOT EXISTS votes (
                  user_id TEXT PRIMARY KEY,
                  submission_id TEXT NOT NULL REFERENCES submissions(id),
                  user_full_name TEXT,
                  user_email TEXT,
                  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
        conn.execute(
            text(votes_sql)
        )
        _ensure_column(conn, "votes", "user_full_name", "TEXT", is_sqlite)
        _ensure_column(conn, "votes", "user_email", "TEXT", is_sqlite)
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
def on_startup() -> None:
    init_db()


def _require_env(name: str, value: Optional[str]) -> str:
    if not value:
        raise HTTPException(500, f"Missing required environment variable: {name}")
    return value


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


def get_user_id(authorization: Optional[str]) -> str:
    claims = verify_bearer(authorization)
    user_id = claims.get("sub") or claims.get("email") or claims.get("preferred_username")
    if not user_id:
        raise HTTPException(401, "No user identifier in token")
    return str(user_id)


def voting_open() -> bool:
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT value FROM settings WHERE key = 'voting_open'")
        ).fetchone()
    if not row:
        return True
    return str(row[0]).lower() == "true"


class VoteIn(BaseModel):
    submission_id: str


class HealthOut(BaseModel):
    status: str


class SubmissionOut(BaseModel):
    id: str
    name: str
    url: str
    team_name: Optional[str] = None
    track: Optional[str] = None
    description: Optional[str] = None


class SubmissionsOut(BaseModel):
    submissions: list[SubmissionOut]


class VoteOut(BaseModel):
    ok: bool


class ResultOut(BaseModel):
    id: str
    name: str
    votes: int


class ResultsOut(BaseModel):
    voting_open: bool
    results: list[ResultOut]


class CloseOut(BaseModel):
    ok: bool


_vote_key_header = APIKeyHeader(name="X-Vote-Key", auto_error=False)


@app.get("/health", response_model=HealthOut)
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/submissions", response_model=SubmissionsOut)
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
def cast_vote(
    payload: VoteIn,
    request: Request,
    api_key: Optional[str] = Depends(_vote_key_header),
) -> Dict[str, bool]:
    if not voting_open():
        raise HTTPException(403, "Voting is closed")

    token = request.headers.get("authorization")
    user_full_name = None
    user_email = None
    if not token:
        raise HTTPException(401, "Missing bearer token")
    claims = verify_bearer(token)
    user_id = (
        claims.get("sub")
        or claims.get("email")
        or claims.get("preferred_username")
    )
    if not user_id:
        raise HTTPException(401, "No user identifier in token")
    user_id = str(user_id)
    user_full_name = (
        claims.get("name")
        or " ".join(
            part for part in [claims.get("given_name"), claims.get("family_name")] if part
        ).strip()
        or None
    )
    user_email = claims.get("email")

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
                    INSERT INTO votes(user_id, submission_id, user_full_name, user_email)
                    VALUES (:u, :s, :n, :e)
                    """
                ),
                {
                    "u": user_id,
                    "s": payload.submission_id,
                    "n": user_full_name,
                    "e": user_email,
                },
            )
        except IntegrityError:
            raise HTTPException(409, "You have already voted")

    return {"ok": True}


@app.get("/results", response_model=ResultsOut)
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
