import os
import time
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException
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
app = FastAPI(title="ChatGPT Voting API")

_jwks_cache: Optional[Dict[str, Any]] = None
_jwks_cache_expiry = 0.0


def init_db() -> None:
    is_sqlite = DATABASE_URL.startswith("sqlite")
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS submissions (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  url TEXT NOT NULL
                )
                """
            )
        )
        votes_sql = """
            CREATE TABLE IF NOT EXISTS votes (
              user_id TEXT PRIMARY KEY,
              submission_id TEXT NOT NULL REFERENCES submissions(id),
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        if is_sqlite:
            votes_sql = """
                CREATE TABLE IF NOT EXISTS votes (
                  user_id TEXT PRIMARY KEY,
                  submission_id TEXT NOT NULL REFERENCES submissions(id),
                  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
        conn.execute(
            text(votes_sql)
        )
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


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/submissions")
def list_submissions() -> Dict[str, Any]:
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT id, name, url FROM submissions ORDER BY name")
        ).fetchall()
    return {
        "submissions": [
            {"id": r[0], "name": r[1], "url": r[2]} for r in rows
        ]
    }


@app.post("/vote")
def cast_vote(payload: VoteIn, authorization: Optional[str] = Header(default=None)) -> Dict[str, bool]:
    if not voting_open():
        raise HTTPException(403, "Voting is closed")

    user_id = get_user_id(authorization)

    with engine.begin() as conn:
        submission = conn.execute(
            text("SELECT 1 FROM submissions WHERE id = :id"),
            {"id": payload.submission_id},
        ).fetchone()
        if not submission:
            raise HTTPException(400, "Invalid submission_id")

        try:
            conn.execute(
                text("INSERT INTO votes(user_id, submission_id) VALUES (:u, :s)"),
                {"u": user_id, "s": payload.submission_id},
            )
        except IntegrityError:
            raise HTTPException(409, "You have already voted")

    return {"ok": True}


@app.get("/results")
def results() -> Dict[str, Any]:
    if voting_open():
        raise HTTPException(403, "Results are not available until voting closes")

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
        "results": [
            {"id": r[0], "name": r[1], "votes": int(r[2])} for r in rows
        ]
    }


@app.post("/admin/close")
def admin_close(x_admin_secret: Optional[str] = Header(default=None)) -> Dict[str, bool]:
    secret = _require_env("ADMIN_SECRET", ADMIN_SECRET)
    if x_admin_secret != secret:
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
