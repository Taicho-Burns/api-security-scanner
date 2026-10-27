# API Security Scanner

A web service that automatically checks a REST API for common security
weaknesses and tells you how to fix them. The scanning always runs on the
**user's side** — never on the platform's server — and the tool cannot be
used against APIs you do not control.

API のセキュリティ上の弱点を自動で検査し、直し方まで教えてくれる Web サービスです。
スキャンは必ず**利用者側**で実行され、プラットフォームのサーバーからは行いません。
自分が管理していない API には使えない設計です。

---

## What it checks / 検査する項目

| Check | OWASP | What it looks for |
|---|---|---|
| Authentication | API2:2023 | A protected endpoint that returns data with no login |
| SQL injection | A05:2025 | DB errors / boolean-based differences from read-only probes |
| Rate limiting | API4:2023 | No HTTP 429 under a small capped burst |
| Access control (BOLA) | API1:2023 | One user reading another user's object |
| OpenAPI (static) | A01/A04:2025 | Unprotected operations, plain-http servers (no traffic sent) |

Results are **findings to confirm**, not proven vulnerabilities, each with a
severity, a confidence level, and a fix.

---

## Two modes

### Phase 1 — CI mode (main version)
The scanner is a **GitHub Action**. On every push it starts your API on
`localhost` inside the CI runner and scans that copy. A high-severity finding
fails the build (❌ on the pull request). Nothing leaves the runner, so no real
server and no one else's API is ever touched.

### Phase 2 — Agent mode (extension)
For APIs that are already deployed. You prove you own the domain with a **DNS
TXT record**, then run a small **agent** on your own machine. It polls the
platform for jobs and scans from your own IP. The platform re-checks the TXT
record before every scan, so a removed record revokes access.

---

## Quick start / クイックスタート

```bash
pip install -r requirements.txt

# 1) Run the scanner against the included vulnerable test API
python -m testapi.vulnerable_api &          # starts on 127.0.0.1:8000
python -m scanner.cli --target http://127.0.0.1:8000 \
    --openapi testapi/openapi_vulnerable.json
# -> reports high findings and exits 1 (fails a CI build)

# 2) Against the secure test API: clean, exits 0
python -m testapi.secure_api &              # starts on 127.0.0.1:8001
python -m scanner.cli --target http://127.0.0.1:8001

# 3) Run the platform + dashboard
python -m server.app                        # open http://localhost:5000

# 4) Run the tests
python -m pytest -q
```

With Docker (platform + PostgreSQL):

```bash
docker compose up --build        # open http://localhost:5000
```

---

## Using it in your own repo (CI mode)

Copy `examples/example-workflow.yml` to `.github/workflows/api-security.yml`,
change the three marked lines (how your API starts, its port, your action
repo), and push. See the dashboard for a ready-to-copy snippet with your
project token.

---

## Project layout

```
scanner/      the scanning engine: 4 checks, OpenAPI check, target guard, CLI
testapi/      a vulnerable API and a secure API, to test the scanner
action/       the GitHub Action (composite)
server/       Flask platform: accounts, projects, results, audit log, dashboard
agent/        Phase 2 agent (polls the platform, scans locally)
tests/        pytest suite (24 tests)
examples/     example workflow to copy into your repo
```

## Safety design (for review)

- The **target guard** (`scanner/guard.py`) refuses any public host unless the
  platform confirms it is DNS-verified; localhost/private targets are always
  allowed. It resolves hostnames so a public name pointing at a private IP is
  still treated as private.
- The platform **stores results only** for localhost/private or verified hosts.
- Tokens and passwords are stored as **hashes**, never in clear text.
- Every action is written to an **audit log** (who, what, when, from which IP).
- SQL-injection probes are **read-only**; no payload can change or delete data.

### Known limit
The scanner and agent are code that runs on the user's side, so a determined
user could modify them — the same as any open tool like OWASP ZAP. The traffic
would carry their own IP, and the platform never stores results or creates jobs
for targets that are not verified.

---

Built as a 個人開発 (personal development) project. Not a replacement for a
professional security assessment.
