"""The four security checks.

Each check is deliberately conservative:

  * It only sends inputs that cannot change or delete data. The SQL-injection
    check uses read-only probe strings, never a destructive payload.
  * It reports a *finding* with a confidence level, not a proven vulnerability.
    Scanner findings and exploitable vulnerabilities are different things.
  * Every request has a short timeout so a scan cannot hang.

A check returns a Finding. severity is "high" / "medium" / "low" / "none".
Only "high" findings fail a CI build by default.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict

import requests


TIMEOUT = 8  # seconds per request


@dataclass
class Finding:
    check: str                 # machine id, e.g. "authentication"
    title: str                 # human title
    severity: str              # high | medium | low | none
    owasp: str                 # mapped OWASP category
    detail: str                # what was observed
    fix: str                   # how to fix it
    confidence: str = "medium"  # how sure we are
    evidence: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _get(session, url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    kw.setdefault("allow_redirects", False)  # never follow a redirect off-host
    return session.get(url, **kw)


# --------------------------------------------------------------------------
# 1. Authentication: a protected endpoint should refuse an unauthenticated call
# --------------------------------------------------------------------------
def check_authentication(base: str, protected_path: str = "/api/account",
                         session: requests.Session | None = None) -> Finding:
    s = session or requests.Session()
    url = base.rstrip("/") + protected_path
    try:
        r = _get(s, url)  # no credentials sent
    except requests.RequestException as e:
        return Finding("authentication", "Authentication check could not run",
                       "none", "API2:2023 Broken Authentication",
                       f"Request failed: {e}", "Make sure the endpoint is reachable.",
                       confidence="low")

    evidence = [f"GET {protected_path} with no credentials -> HTTP {r.status_code}"]
    # 401/403 = protected (good). A login redirect (3xx to a login page) is also
    # a form of protection. 200 with a body = data leaked to an anonymous caller.
    if r.status_code in (401, 403):
        return Finding("authentication", "Protected endpoint requires authentication",
                       "none", "API2:2023 Broken Authentication",
                       f"Returned {r.status_code} without credentials, as expected.",
                       "No action needed.", confidence="high", evidence=evidence)
    if 300 <= r.status_code < 400:
        return Finding("authentication", "Endpoint redirects unauthenticated callers",
                       "low", "API2:2023 Broken Authentication",
                       f"Returned {r.status_code} (redirect). Likely a login redirect; confirm it is not leaking data.",
                       "Prefer returning 401 for APIs instead of redirecting.",
                       confidence="low", evidence=evidence)
    if r.status_code == 200 and r.text.strip():
        return Finding("authentication", "Protected data returned without authentication",
                       "high", "API2:2023 Broken Authentication",
                       f"GET {protected_path} returned 200 with a body and no credentials. "
                       f"Anonymous callers may be able to read protected data.",
                       "Require a valid token on this endpoint and return 401 when it is missing.",
                       confidence="high",
                       evidence=evidence + [f"body (first 120 chars): {r.text[:120]!r}"])
    return Finding("authentication", "Authentication behaviour unclear",
                   "low", "API2:2023 Broken Authentication",
                   f"Unexpected status {r.status_code}; review manually.",
                   "Confirm the endpoint requires authentication.",
                   confidence="low", evidence=evidence)


# --------------------------------------------------------------------------
# 2. SQL injection: read-only probes, look for DB error leakage
# --------------------------------------------------------------------------
# These probes are intentionally non-destructive: a trailing quote and a
# benign always-true/always-false pair. No DROP, DELETE, UPDATE, or stacked
# statements are ever sent.
_SQL_QUOTE = "'"                     # breaks an unbalanced string literal
_SQL_TRUE = "' OR '1'='1' -- "       # read-only: always-true tautology
_SQL_FALSE = "zzno' AND '1'='2' -- "  # read-only: always-false
_SQL_ERROR_SIGNATURES = [
    "sql syntax", "syntax error", "sqlite3.", "psycopg2", "unclosed quotation",
    "sqlstate", "ora-0", "mysql_fetch", "pg::", "near \"", "you have an error in your sql",
    "unrecognized token", "sql error", "unterminated", "malformed", "odbc", "quoted string not",
]


def check_sql_injection(base: str, path: str = "/api/items", param: str = "q",
                        session: requests.Session | None = None) -> Finding:
    s = session or requests.Session()
    url = base.rstrip("/") + path
    evidence = []
    try:
        baseline = _get(s, url, params={param: "ping"})
    except requests.RequestException as e:
        return Finding("sql_injection", "SQL injection check could not run",
                       "none", "A05:2025 Injection", f"Request failed: {e}",
                       "Make sure the endpoint is reachable.", confidence="low")

    # Signal 1: a crafted input makes the DB error leak out.
    leaked_error = False
    for probe in (_SQL_QUOTE, _SQL_TRUE, _SQL_FALSE):
        try:
            r = _get(s, url, params={param: probe})
        except requests.RequestException:
            continue
        body = (r.text or "").lower()
        hit = next((sig for sig in _SQL_ERROR_SIGNATURES if sig in body), None)
        if hit:
            leaked_error = True
            evidence.append(f"probe {probe!r} -> HTTP {r.status_code}, DB error signature {hit!r}")

    if leaked_error:
        return Finding("sql_injection", "Database error leaked from a crafted input",
                       "high", "A05:2025 Injection",
                       "A read-only probe caused the API to return a database error message. "
                       "That strongly suggests input is concatenated into a SQL query.",
                       "Use parameterized queries / an ORM; never build SQL by string concatenation. "
                       "Return a generic error and log the detail server-side.",
                       confidence="high", evidence=evidence)

    # Signal 2 (boolean-based): an always-true tautology returns noticeably more
    # than an always-false one. On a parameterized query both match nothing and
    # look identical, so this does not fire on the secure API.
    try:
        r_true = _get(s, url, params={param: _SQL_TRUE})
        r_false = _get(s, url, params={param: _SQL_FALSE})
        len_true, len_false = len(r_true.text or ""), len(r_false.text or "")
        evidence.append(f"always-true body {len_true} bytes vs always-false {len_false} bytes")
        if len_true > max(len_false, 2) and (len_true - len_false) > 10:
            return Finding("sql_injection", "Input appears to alter the SQL query (boolean-based)",
                           "high", "A05:2025 Injection",
                           "An always-true condition returned more data than an always-false one, "
                           "which means the input is changing the query logic (SQL injection).",
                           "Use parameterized queries / an ORM; never build SQL by string concatenation.",
                           confidence="high", evidence=evidence)
    except requests.RequestException:
        pass

    return Finding("sql_injection", "No SQL injection signal detected",
                   "none", "A05:2025 Injection",
                   "Read-only probes produced no DB errors and no boolean-based difference.",
                   "No action needed from this check. (This does not prove the API is injection-free.)",
                   confidence="medium",
                   evidence=[f"baseline HTTP {baseline.status_code}"] + evidence)


# --------------------------------------------------------------------------
# 3. Rate limiting: a small capped burst should start being limited
# --------------------------------------------------------------------------
def check_rate_limiting(base: str, path: str = "/api/items", burst: int = 25,
                        session: requests.Session | None = None) -> Finding:
    s = session or requests.Session()
    url = base.rstrip("/") + path
    statuses = []
    try:
        for _ in range(burst):
            r = _get(s, url)
            statuses.append(r.status_code)
            if r.status_code == 429:
                break
    except requests.RequestException as e:
        return Finding("rate_limiting", "Rate-limit check could not run",
                       "none", "API4:2023 Unrestricted Resource Consumption",
                       f"Request failed: {e}", "Make sure the endpoint is reachable.",
                       confidence="low")

    sent = len(statuses)
    limited = 429 in statuses
    evidence = [f"sent {sent} requests; saw 429: {limited}"]
    if limited:
        return Finding("rate_limiting", "Rate limiting is enforced",
                       "none", "API4:2023 Unrestricted Resource Consumption",
                       f"The API returned HTTP 429 after {sent} rapid requests.",
                       "No action needed.", confidence="high", evidence=evidence)
    return Finding("rate_limiting", "No rate limiting observed",
                   "medium", "API4:2023 Unrestricted Resource Consumption",
                   f"Sent {sent} rapid requests and never received HTTP 429. "
                   f"The endpoint may allow unrestricted use (brute force, scraping, cost abuse).",
                   "Add per-client rate limiting (e.g. a token-bucket at the gateway or app) "
                   "and return 429 with a Retry-After header.",
                   confidence="medium", evidence=evidence)


# --------------------------------------------------------------------------
# 4. Access control (BOLA): user A's token must not read user B's object
# --------------------------------------------------------------------------
def check_access_control(base: str, path_tmpl: str = "/api/users/{id}/profile",
                         token_a: str = "token-user-a", id_a: str = "1", id_b: str = "2",
                         session: requests.Session | None = None) -> Finding:
    s = session or requests.Session()
    headers = {"Authorization": f"Bearer {token_a}"}
    own = base.rstrip("/") + path_tmpl.format(id=id_a)
    other = base.rstrip("/") + path_tmpl.format(id=id_b)
    try:
        r_own = _get(s, own, headers=headers)
        r_other = _get(s, other, headers=headers)
    except requests.RequestException as e:
        return Finding("access_control", "Access-control check could not run",
                       "none", "API1:2023 Broken Object Level Authorization",
                       f"Request failed: {e}", "Make sure the endpoints are reachable.",
                       confidence="low")

    evidence = [f"user A token -> own object {path_tmpl.format(id=id_a)}: HTTP {r_own.status_code}",
                f"user A token -> other object {path_tmpl.format(id=id_b)}: HTTP {r_other.status_code}"]
    # Vulnerable if A can read its own object (200) AND also read B's object (200).
    if r_own.status_code == 200 and r_other.status_code == 200:
        return Finding("access_control", "One user can read another user's object",
                       "high", "API1:2023 Broken Object Level Authorization",
                       "User A's token successfully read user B's object. The API checks that you "
                       "are logged in, but not that the object belongs to you (BOLA / IDOR).",
                       "On every object fetch, check that the object's owner matches the "
                       "authenticated user; return 403/404 otherwise.",
                       confidence="high", evidence=evidence)
    if r_other.status_code in (401, 403, 404):
        return Finding("access_control", "Object-level access control is enforced",
                       "none", "API1:2023 Broken Object Level Authorization",
                       f"User A was blocked from user B's object ({r_other.status_code}).",
                       "No action needed.", confidence="high", evidence=evidence)
    return Finding("access_control", "Access-control behaviour unclear",
                   "low", "API1:2023 Broken Object Level Authorization",
                   f"Own={r_own.status_code}, other={r_other.status_code}; review manually.",
                   "Confirm users cannot read objects they do not own.",
                   confidence="low", evidence=evidence)


# Order matters: the rate-limiting check deliberately sends a burst and can
# use up a per-client budget, so it runs LAST — otherwise later checks on a
# well-behaved API would hit 429 and look "unclear".
ALL_CHECKS = {
    "authentication": check_authentication,
    "sql_injection": check_sql_injection,
    "access_control": check_access_control,
    "rate_limiting": check_rate_limiting,
}
