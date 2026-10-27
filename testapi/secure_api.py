"""A properly SECURED version of the same API, used to test the scanner.

Same endpoints as vulnerable_api.py, but:
  * /api/account requires a valid bearer token (401 otherwise)
  * /api/items uses a parameterized query (no SQL error leakage)
  * a simple in-memory rate limiter returns 429 under a burst
  * /api/users/<id>/profile enforces that the token owns the object (BOLA fixed)

The scanner should report NO high-severity findings against this one.
Run:  python -m testapi.secure_api  (listens on 127.0.0.1:8001)
"""
from __future__ import annotations

import sqlite3
import time
from collections import defaultdict

from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# token -> user id it belongs to
TOKENS = {"token-user-a": "1", "token-user-b": "2"}

# very small fixed-window rate limiter (per client IP)
_WINDOW = 10.0
_LIMIT = 15
_hits: dict[str, list[float]] = defaultdict(list)


def _rate_limited() -> bool:
    now = time.time()
    ip = request.remote_addr or "?"
    hits = [t for t in _hits[ip] if now - t < _WINDOW]
    hits.append(now)
    _hits[ip] = hits
    return len(hits) > _LIMIT


def _auth_user() -> str | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return TOKENS.get(auth[len("Bearer "):])


@app.before_request
def _limit():
    if _rate_limited():
        return Response("rate limit exceeded", status=429, headers={"Retry-After": "10"})


@app.get("/api/account")
def account():
    if _auth_user() is None:
        return Response("unauthorized", status=401)
    return jsonify({"user": "alice", "email": "alice@example.com", "balance": 4200})


@app.get("/api/items")
def items():
    q = request.args.get("q", "")
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE items (id INTEGER, name TEXT)")
    db.executemany("INSERT INTO items VALUES (?, ?)", [(1, "alpha"), (2, "beta")])
    # SAFE: parameterized query. Bad input returns an empty list, no error leak.
    rows = db.execute("SELECT id, name FROM items WHERE name = ?", (q,)).fetchall()
    return jsonify([{"id": r[0], "name": r[1]} for r in rows])


@app.get("/api/users/<uid>/profile")
def profile(uid):
    owner = _auth_user()
    if owner is None:
        return Response("unauthorized", status=401)
    # SAFE: the token must own the requested object.
    if owner != uid:
        return Response("forbidden", status=403)
    profiles = {
        "1": {"id": 1, "name": "alice"},
        "2": {"id": 2, "name": "bob"},
    }
    return jsonify(profiles.get(uid, {"error": "not found"}))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8001)
