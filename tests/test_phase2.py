"""Phase 2: domain verification gates everything, and the job queue works.

DNS is simulated with the DEMO_TXT env var so the test needs no real domain.
"""
import os

import pytest

from server.app import create_app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("DEMO_TXT", raising=False)
    app = create_app(db_url=f"sqlite:///{tmp_path}/p2.db")
    app.config.update(TESTING=True)
    return app.test_client()


def _login(client):
    r = client.post("/api/register", json={"email": "e@e.com", "password": "password123"})
    client.get(r.get_json()["confirm_link"])
    client.post("/api/login", json={"email": "e@e.com", "password": "password123"})


def _project_token(client):
    return client.post("/api/projects", json={"name": "P"}).get_json()["token"]


def test_domain_must_be_verified_before_scan(client, monkeypatch):
    _login(client)
    token = _project_token(client)
    # add a domain, get the challenge
    d = client.post("/api/projects/1/domains", json={"host": "api.demo.example"}).get_json()
    challenge_value = d["txt_record"]  # apiscanner-verify=...

    # verify with NO txt record -> stays unverified
    r = client.post(f"/api/domains/{d['id']}/verify").get_json()
    assert r["verified"] is False

    # queueing a scan for the unverified host is refused
    r = client.post("/api/projects/1/scan", json={"target": "https://api.demo.example/api"})
    assert r.status_code == 403

    # now simulate the TXT record existing
    monkeypatch.setenv("DEMO_TXT", f"api.demo.example={challenge_value}")
    r = client.post(f"/api/domains/{d['id']}/verify").get_json()
    assert r["verified"] is True

    # verify-target (called by scanner/agent) now allows it
    vt = client.get("/api/verify-target", query_string={"host": "api.demo.example"},
                    headers={"X-Scanner-Token": token}).get_json()
    assert vt["allowed"] is True

    # queueing a scan now succeeds
    r = client.post("/api/projects/1/scan", json={"target": "https://api.demo.example/api"})
    assert r.status_code == 201


def test_removed_txt_revokes_access(client, monkeypatch):
    _login(client)
    token = _project_token(client)
    d = client.post("/api/projects/1/domains", json={"host": "api.demo.example"}).get_json()
    monkeypatch.setenv("DEMO_TXT", f"api.demo.example={d['txt_record']}")
    client.post(f"/api/domains/{d['id']}/verify")

    # record disappears -> verify-target must refuse and revoke
    monkeypatch.delenv("DEMO_TXT", raising=False)
    vt = client.get("/api/verify-target", query_string={"host": "api.demo.example"},
                    headers={"X-Scanner-Token": token}).get_json()
    assert vt["allowed"] is False


def test_agent_key_and_job_queue(client):
    _login(client)
    _project_token(client)
    ak = client.post("/api/projects/1/agent-keys").get_json()["agent_key"]
    assert ak.startswith("agt_")
    # queue a localhost job (always allowed) and the agent picks it up
    client.post("/api/projects/1/scan", json={"target": "http://localhost:8000"})
    job = client.get("/api/agent/jobs", headers={"X-Agent-Key": ak}).get_json()["job"]
    assert job["target"] == "http://localhost:8000"
    # a second poll returns nothing (job was taken)
    assert client.get("/api/agent/jobs", headers={"X-Agent-Key": ak}).get_json()["job"] is None
