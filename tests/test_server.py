"""Platform server tests: auth flow, projects, results intake guard, audit log."""
import json

import pytest

from server.app import create_app, sha


@pytest.fixture()
def client(tmp_path):
    app = create_app(db_url=f"sqlite:///{tmp_path}/t.db")
    app.config.update(TESTING=True)
    return app.test_client()


def _register_login(client, email="a@b.com", pw="password123"):
    r = client.post("/api/register", json={"email": email, "password": pw})
    link = r.get_json()["confirm_link"]
    client.get(link)  # confirm email
    client.post("/api/login", json={"email": email, "password": pw})


def test_login_requires_confirmation(client):
    client.post("/api/register", json={"email": "x@y.com", "password": "password123"})
    r = client.post("/api/login", json={"email": "x@y.com", "password": "password123"})
    assert r.status_code == 403  # not confirmed yet


def test_full_auth_and_project_flow(client):
    _register_login(client)
    r = client.post("/api/projects", json={"name": "My API", "repo": "me/app"})
    assert r.status_code == 201
    body = r.get_json()
    assert body["token"].startswith("scn_")
    assert "workflow" in body
    assert client.get("/api/projects").get_json()[0]["name"] == "My API"


def test_results_accepted_for_localhost(client):
    _register_login(client)
    token = client.post("/api/projects", json={"name": "P"}).get_json()["token"]
    report = {"target": "http://localhost:8000",
              "summary": {"high": 1, "medium": 0, "low": 0, "none": 3}, "findings": []}
    r = client.post("/api/results", data=json.dumps(report),
                    headers={"X-Scanner-Token": token, "Content-Type": "application/json"})
    assert r.status_code == 201
    runs = client.get("/api/projects/1/runs").get_json()
    assert runs[0]["high"] == 1


def test_results_refused_for_unverified_public_host(client):
    _register_login(client)
    token = client.post("/api/projects", json={"name": "P"}).get_json()["token"]
    report = {"target": "https://api.someoneelse.com", "summary": {}, "findings": []}
    r = client.post("/api/results", data=json.dumps(report),
                    headers={"X-Scanner-Token": token, "Content-Type": "application/json"})
    assert r.status_code == 403  # the whole point: cannot store scans of unverified hosts


def test_results_rejects_bad_token(client):
    report = {"target": "http://localhost:8000", "summary": {}, "findings": []}
    r = client.post("/api/results", data=json.dumps(report),
                    headers={"X-Scanner-Token": "nope", "Content-Type": "application/json"})
    assert r.status_code == 401


def test_token_is_hashed_not_stored_plaintext(client, tmp_path):
    _register_login(client)
    token = client.post("/api/projects", json={"name": "P"}).get_json()["token"]
    # the DB must not contain the raw token, only its hash
    import sqlite3, glob
    dbfile = glob.glob(f"{tmp_path}/t.db")[0]
    raw = open(dbfile, "rb").read()
    assert token.encode() not in raw
    assert sha(token).encode() in raw


def test_audit_log_records_actions(client):
    _register_login(client)
    client.post("/api/projects", json={"name": "P"})
    actions = {e["action"] for e in client.get("/api/audit").get_json()}
    assert "create_project" in actions and "login" in actions
