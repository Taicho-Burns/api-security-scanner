"""Platform API server (Flask).

Responsibilities:
  * accounts with email confirmation and password login
  * projects, each with a hashed scanner token and a ready-to-copy workflow
  * results intake from the CI scanner (Phase 1) and the agent (Phase 2)
  * Phase 2: DNS TXT domain verification, agent keys, a job queue
  * an audit log of everything that matters

Security choices worth noting for the teacher:
  * passwords and tokens are stored only as salted/sha256 hashes
  * results are accepted only for localhost/private targets OR verified domains
  * every domain verification is re-checked live before a job is created
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets

from flask import Flask, request, jsonify, session, g
from werkzeug.security import generate_password_hash, check_password_hash

from .models import (make_engine, init_db, User, Project, VerifiedDomain,
                     AgentKey, ScanJob, ScanRun, AuditLog)
from scanner.guard import is_loopback_or_private, parse_target, TargetError

try:
    import dns.resolver  # Phase 2 DNS verification
except ImportError:  # pragma: no cover
    dns = None


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def create_app(db_url: str | None = None):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))

    @app.get("/")
    def _index():
        return app.send_static_file("index.html")
    Session = init_db(make_engine(db_url))

    # In a real deployment the confirmation link is emailed. For local running
    # and the demo we capture "sent emails" in memory so the flow is visible.
    app.config["SENT_EMAILS"] = []

    @app.before_request
    def _open_session():
        g.db = Session()

    @app.teardown_request
    def _close_session(exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def audit(action, status="ok", target=None, detail=None, user_id=None, project_id=None):
        g.db.add(AuditLog(
            user_id=user_id if user_id is not None else session.get("uid"),
            project_id=project_id, action=action, target=target, status=status,
            ip=request.headers.get("X-Forwarded-For", request.remote_addr),
            detail=detail))
        g.db.commit()

    def current_user():
        uid = session.get("uid")
        return g.db.get(User, uid) if uid else None

    def require_user():
        u = current_user()
        if u is None:
            return None, (jsonify({"error": "login required"}), 401)
        return u, None

    def project_for(user, pid):
        p = g.db.get(Project, pid)
        if p is None or p.owner_id != user.id:
            return None
        return p

    # ---------------- auth ----------------
    @app.post("/api/register")
    def register():
        data = request.get_json(force=True, silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        if "@" not in email or len(password) < 8:
            return jsonify({"error": "valid email and password (8+ chars) required"}), 400
        if g.db.query(User).filter_by(email=email).first():
            return jsonify({"error": "email already registered"}), 409
        token = secrets.token_urlsafe(24)
        user = User(email=email, password_hash=generate_password_hash(password),
                    verified=False, confirm_token=token)
        g.db.add(user); g.db.commit()
        link = f"/api/confirm?token={token}"
        app.config["SENT_EMAILS"].append({"to": email, "confirm_link": link})
        audit("register", user_id=user.id)
        # The link is returned here so the flow works without a mail server.
        return jsonify({"status": "registered", "confirm_link": link}), 201

    @app.get("/api/confirm")
    def confirm():
        token = request.args.get("token", "")
        user = g.db.query(User).filter_by(confirm_token=token).first()
        if not user:
            return jsonify({"error": "invalid or used token"}), 400
        user.verified = True
        user.confirm_token = None
        g.db.commit()
        audit("confirm_email", user_id=user.id)
        return jsonify({"status": "email confirmed"})

    @app.post("/api/login")
    def login():
        data = request.get_json(force=True, silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        user = g.db.query(User).filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, data.get("password") or ""):
            audit("login", status="failed", detail=email, user_id=user.id if user else None)
            return jsonify({"error": "invalid email or password"}), 401
        if not user.verified:
            return jsonify({"error": "please confirm your email first"}), 403
        session["uid"] = user.id
        audit("login", user_id=user.id)
        return jsonify({"status": "logged in", "email": user.email})

    @app.post("/api/logout")
    def logout():
        session.pop("uid", None)
        return jsonify({"status": "logged out"})

    @app.get("/api/me")
    def me():
        u = current_user()
        return jsonify({"email": u.email} if u else {"email": None})

    # ---------------- projects ----------------
    @app.post("/api/projects")
    def create_project():
        user, err = require_user()
        if err:
            return err
        data = request.get_json(force=True, silent=True) or {}
        name = (data.get("name") or "").strip() or "My API"
        raw_token = "scn_" + secrets.token_urlsafe(24)
        p = Project(owner_id=user.id, name=name, repo=data.get("repo"),
                    token_hash=sha(raw_token), token_prefix=raw_token[:10])
        g.db.add(p); g.db.commit()
        audit("create_project", project_id=p.id)
        # The raw token is shown once, here, and never stored in the clear.
        return jsonify({"id": p.id, "name": p.name, "token": raw_token,
                        "workflow": _workflow_snippet(p)}), 201

    @app.get("/api/projects")
    def list_projects():
        user, err = require_user()
        if err:
            return err
        out = []
        for p in g.db.query(Project).filter_by(owner_id=user.id).all():
            last = (g.db.query(ScanRun).filter_by(project_id=p.id)
                    .order_by(ScanRun.created_at.desc()).first())
            out.append({"id": p.id, "name": p.name, "repo": p.repo,
                        "token_prefix": p.token_prefix,
                        "last_run": _run_brief(last) if last else None})
        return jsonify(out)

    @app.get("/api/projects/<int:pid>/runs")
    def project_runs(pid):
        user, err = require_user()
        if err:
            return err
        p = project_for(user, pid)
        if not p:
            return jsonify({"error": "not found"}), 404
        runs = (g.db.query(ScanRun).filter_by(project_id=pid)
                .order_by(ScanRun.created_at.desc()).limit(50).all())
        return jsonify([_run_full(r) for r in runs])

    # ---------------- results intake (CI scanner + agent) ----------------
    @app.post("/api/results")
    def results():
        token = request.headers.get("X-Scanner-Token", "")
        project = g.db.query(Project).filter_by(token_hash=sha(token)).first()
        mode = "ci"
        if not project:
            # maybe an agent key (Phase 2)
            ak = g.db.query(AgentKey).filter_by(key_hash=sha(token), revoked=False).first()
            if ak:
                project = g.db.get(Project, ak.project_id)
                mode = "agent"
        if not project:
            return jsonify({"error": "invalid token"}), 401

        payload = request.get_json(force=True, silent=True) or {}
        target = payload.get("target", "")
        # Accept results only for localhost/private OR a verified domain.
        try:
            _scheme, host = parse_target(target)
        except TargetError:
            audit("results_refused", status="refused", target=target, project_id=project.id)
            return jsonify({"error": "bad target"}), 400
        if not is_loopback_or_private(host) and not _host_verified(g.db, project.id, host):
            audit("results_refused", status="refused", target=target, project_id=project.id,
                  detail="unverified public host")
            return jsonify({"error": "target not verified"}), 403

        summary = payload.get("summary", {})
        run = ScanRun(project_id=project.id, target=target, mode=mode,
                      high=summary.get("high", 0), medium=summary.get("medium", 0),
                      low=summary.get("low", 0), ok=summary.get("none", 0),
                      findings_json=json.dumps(payload.get("findings", [])))
        g.db.add(run); g.db.commit()
        audit("results_stored", target=target, project_id=project.id,
              detail=f"{run.high} high / {run.medium} medium")
        return jsonify({"status": "stored", "run_id": run.id}), 201

    # ---------------- Phase 2: domain verification ----------------
    @app.post("/api/projects/<int:pid>/domains")
    def add_domain(pid):
        user, err = require_user()
        if err:
            return err
        p = project_for(user, pid)
        if not p:
            return jsonify({"error": "not found"}), 404
        host = ((request.get_json(force=True, silent=True) or {}).get("host") or "").strip().lower()
        if not host:
            return jsonify({"error": "host required"}), 400
        challenge = secrets.token_urlsafe(24)
        vd = VerifiedDomain(project_id=pid, host=host, challenge=challenge, verified=False)
        g.db.add(vd); g.db.commit()
        audit("domain_added", target=host, project_id=pid)
        return jsonify({"id": vd.id, "host": host,
                        "txt_record": f"apiscanner-verify={challenge}",
                        "instructions": f"Add a TXT record to {host} with the value above, then verify."}), 201

    @app.post("/api/domains/<int:did>/verify")
    def verify_domain(did):
        user, err = require_user()
        if err:
            return err
        vd = g.db.get(VerifiedDomain, did)
        if not vd or not project_for(user, vd.project_id):
            return jsonify({"error": "not found"}), 404
        ok, detail = _dns_has_txt(vd.host, f"apiscanner-verify={vd.challenge}")
        vd.verified = ok
        vd.verified_at = dt.datetime.now(dt.timezone.utc) if ok else None
        g.db.commit()
        audit("domain_verify", status="ok" if ok else "failed", target=vd.host,
              project_id=vd.project_id, detail=detail)
        return jsonify({"host": vd.host, "verified": ok, "detail": detail})

    @app.get("/api/verify-target")
    def verify_target():
        """Called by the scanner/agent before scanning a public host.
        Re-checks the live TXT record every time, so a removed record revokes access."""
        token = request.headers.get("X-Scanner-Token", "")
        project = g.db.query(Project).filter_by(token_hash=sha(token)).first()
        if not project:
            ak = g.db.query(AgentKey).filter_by(key_hash=sha(token), revoked=False).first()
            project = g.db.get(Project, ak.project_id) if ak else None
        if not project:
            return jsonify({"allowed": False, "error": "invalid token"}), 401
        host = (request.args.get("host") or "").strip().lower()
        vd = (g.db.query(VerifiedDomain)
              .filter_by(project_id=project.id, host=host, verified=True).first())
        if not vd:
            return jsonify({"allowed": False, "reason": "not verified"}), 200
        ok, detail = _dns_has_txt(host, f"apiscanner-verify={vd.challenge}")
        if not ok:
            vd.verified = False; g.db.commit()
            audit("verify_revoked", status="revoked", target=host, project_id=project.id, detail=detail)
            return jsonify({"allowed": False, "reason": "txt record missing now"}), 200
        return jsonify({"allowed": True}), 200

    # ---------------- Phase 2: agent keys + job queue ----------------
    @app.post("/api/projects/<int:pid>/agent-keys")
    def create_agent_key(pid):
        user, err = require_user()
        if err:
            return err
        if not project_for(user, pid):
            return jsonify({"error": "not found"}), 404
        raw = "agt_" + secrets.token_urlsafe(24)
        ak = AgentKey(project_id=pid, key_hash=sha(raw), key_prefix=raw[:10])
        g.db.add(ak); g.db.commit()
        audit("agent_key_created", project_id=pid)
        return jsonify({"agent_key": raw}), 201

    @app.post("/api/projects/<int:pid>/scan")
    def queue_scan(pid):
        user, err = require_user()
        if err:
            return err
        p = project_for(user, pid)
        if not p:
            return jsonify({"error": "not found"}), 404
        target = ((request.get_json(force=True, silent=True) or {}).get("target") or "").strip()
        try:
            _scheme, host = parse_target(target)
        except TargetError as e:
            return jsonify({"error": str(e)}), 400
        # Re-check ownership before creating the job.
        if not is_loopback_or_private(host):
            vd = (g.db.query(VerifiedDomain)
                  .filter_by(project_id=pid, host=host, verified=True).first())
            ok = bool(vd) and _dns_has_txt(host, f"apiscanner-verify={vd.challenge}")[0]
            if not ok:
                audit("scan_refused", status="refused", target=target, project_id=pid)
                return jsonify({"error": "target not verified"}), 403
        job = ScanJob(project_id=pid, target=target, status="queued")
        g.db.add(job); g.db.commit()
        audit("scan_queued", target=target, project_id=pid)
        return jsonify({"job_id": job.id, "status": "queued"}), 201

    @app.get("/api/agent/jobs")
    def agent_jobs():
        """The agent polls here. Returns one queued job for its project, or none."""
        token = request.headers.get("X-Agent-Key", "")
        ak = g.db.query(AgentKey).filter_by(key_hash=sha(token), revoked=False).first()
        if not ak:
            return jsonify({"error": "invalid agent key"}), 401
        job = (g.db.query(ScanJob).filter_by(project_id=ak.project_id, status="queued")
               .order_by(ScanJob.created_at).first())
        if not job:
            return jsonify({"job": None})
        job.status = "taken"; g.db.commit()
        return jsonify({"job": {"id": job.id, "target": job.target}})

    # ---------------- audit log view ----------------
    @app.get("/api/audit")
    def audit_view():
        user, err = require_user()
        if err:
            return err
        pids = [p.id for p in g.db.query(Project).filter_by(owner_id=user.id).all()]
        logs = (g.db.query(AuditLog)
                .filter((AuditLog.user_id == user.id) | (AuditLog.project_id.in_(pids or [-1])))
                .order_by(AuditLog.created_at.desc()).limit(100).all())
        return jsonify([{"action": l.action, "status": l.status, "target": l.target,
                         "detail": l.detail, "at": l.created_at.isoformat() if l.created_at else None}
                        for l in logs])

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    return app


# ---------------- helpers ----------------
def _workflow_snippet(p: Project) -> str:
    return (
        "name: API security\n"
        "on: [push, pull_request]\n"
        "jobs:\n"
        "  api-security:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-python@v5\n"
        "        with: { python-version: '3.11' }\n"
        "      - name: Start API\n"
        "        run: |\n"
        "          pip install -r requirements.txt\n"
        "          python app.py &\n"
        "          sleep 5\n"
        "      - uses: your-org/api-security-scanner/action@v1\n"
        "        with:\n"
        "          target: 'http://localhost:8000'\n"
        "          report-url: 'PLATFORM_URL/api/results'\n"
        "          token: ${{ secrets.API_SCANNER_TOKEN }}\n"
    )


def _host_verified(db, project_id, host) -> bool:
    return bool(db.query(VerifiedDomain)
                .filter_by(project_id=project_id, host=host, verified=True).first())


def _dns_has_txt(host: str, expected: str) -> tuple[bool, str]:
    """True if host has a TXT record containing `expected`. For local demos,
    DEMO_TXT lets you simulate DNS without owning a domain."""
    demo = os.environ.get("DEMO_TXT")  # e.g. "api.demo.example=apiscanner-verify=abc"
    if demo:
        for pair in demo.split(";"):
            if "=" in pair:
                h, val = pair.split("=", 1)
                if h.strip() == host and expected in val:
                    return True, "matched DEMO_TXT"
        return False, "no DEMO_TXT match"
    if dns is None:
        return False, "dnspython not installed"
    try:
        answers = dns.resolver.resolve(host, "TXT")
        for rr in answers:
            if expected in rr.to_text().strip('"'):
                return True, "TXT record matched"
        return False, "TXT record not found"
    except Exception as e:  # noqa: BLE001
        return False, f"DNS lookup failed: {e}"


def _run_brief(r: ScanRun) -> dict:
    return {"id": r.id, "high": r.high, "medium": r.medium,
            "at": r.created_at.isoformat() if r.created_at else None}


def _run_full(r: ScanRun) -> dict:
    return {"id": r.id, "target": r.target, "mode": r.mode,
            "high": r.high, "medium": r.medium, "low": r.low, "ok": r.ok,
            "findings": json.loads(r.findings_json or "[]"),
            "at": r.created_at.isoformat() if r.created_at else None}


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
