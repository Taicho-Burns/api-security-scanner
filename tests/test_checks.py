"""The scanner must find the planted weaknesses and clear the secure API."""
import time

import pytest

from scanner import checks
from scanner.cli import run_scan
from scanner.report import exit_code, summarize


# ---- vulnerable API: each check finds its weakness ----
def test_auth_finds_missing_auth(vuln_url):
    f = checks.check_authentication(vuln_url)
    assert f.severity == "high"


def test_sql_finds_injection(vuln_url):
    f = checks.check_sql_injection(vuln_url)
    assert f.severity == "high"


def test_bola_finds_broken_access_control(vuln_url):
    f = checks.check_access_control(vuln_url)
    assert f.severity == "high"


def test_rate_limit_missing(vuln_url):
    f = checks.check_rate_limiting(vuln_url, burst=20)
    assert f.severity == "medium"


def test_full_scan_vulnerable_fails_build(vuln_url):
    findings = run_scan(vuln_url, openapi_path=None)
    assert exit_code(findings, "high") == 1
    assert summarize(findings)["high"] >= 2


# ---- secure API: no high findings, build passes ----
def test_full_scan_secure_passes_build(secure_url):
    time.sleep(11)  # let any rate-limit window from earlier tests reset
    findings = run_scan(secure_url, openapi_path=None)
    assert summarize(findings)["high"] == 0
    assert exit_code(findings, "high") == 0
