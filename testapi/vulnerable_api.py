"""An intentionally INSECURE API, used only to test the scanner.

Every weakness here is on purpose so the scanner has something to find:
  * /api/account returns data with no authentication
  * /api/items reflects a raw SQL error for crafted input
  * no rate limiting anywhere
  * /api/users/<id>/profile lets any logged-in user read any profile (BOLA)

Do NOT copy this code into a real service. It exists to be scanned.
Run:  python -m testapi.vulnerable_api  (listens on 127.0.0.1:8000)
"""
from __future__ import annotations

import sqlite3

from flask import Flask, request, jsonify, Response

app = Flask(__name__)


def _db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE items (id INTEGER, name TEXT)")
    db.executemany("INSERT INTO items VALUES (?, ?)",
                   [(1, "alpha"), (2, "beta"), (3, "gamma")])
    db.commit()
    return db


@app.get("/api/account")
def account():
    # VULN: no auth check — returns private-looking data to anyone.
    return jsonify({"user": "alice", "email": "alice@example.com", "balance": 4200})


@app.get("/api/items")
def items():
    # VULN: user input concatenated straight into SQL -> error leaks on bad input.
    q = request.args.get("q", "")
    db = _db()
    try:
        rows = db.execute(f"SELECT id, name FROM items WHERE name = '{q}'").fetchall()
        return jsonify([{"id": r[0], "name": r[1]} for r in rows])
    except sqlite3.Error as e:
        # VULN: raw DB error returned to the client.
        return Response(f"SQL error: {e}", status=500)


@app.get("/api/users/<uid>/profile")
def profile(uid):
    # VULN: checks that a token is present, but not that it owns the object.
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return Response("missing token", status=401)
    profiles = {
        "1": {"id": 1, "name": "alice", "ssn": "***-**-0001"},
        "2": {"id": 2, "name": "bob", "ssn": "***-**-0002"},
    }
    return jsonify(profiles.get(uid, {"error": "not found"}))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
