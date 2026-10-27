"""Command-line entry point for the scanner.

Examples
--------
    # Phase 1 (CI mode): scan the API running on localhost in the runner
    python -m scanner.cli --target http://localhost:8000 --openapi openapi.json

    # Send results to the platform (the GitHub Action does this for you)
    python -m scanner.cli --target http://localhost:8000 \
        --report-url https://platform.example/api/results --token $SCANNER_TOKEN

Exit code is 0 when the API passes and 1 when a high-severity finding is
present, so a CI job fails the build on a high finding.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import requests

from . import checks, report
from .guard import check_target_allowed, TargetError
from .openapi_check import analyze_openapi


def make_platform_verifier(report_url: str, token: str):
    """Return a verifier(hostname) -> bool that asks the platform.

    Used only for public targets (Phase 2). The platform answers whether the
    host is DNS-verified for this token, re-checking the TXT record live.
    """
    base = report_url.rsplit("/api/", 1)[0]

    def verifier(hostname: str) -> bool:
        try:
            r = requests.get(f"{base}/api/verify-target",
                             params={"host": hostname},
                             headers={"X-Scanner-Token": token}, timeout=10)
            return r.status_code == 200 and r.json().get("allowed") is True
        except (requests.RequestException, ValueError):
            return False

    return verifier


def run_scan(target: str, openapi_path: str | None = None, verifier=None) -> list:
    findings: list = []
    session = requests.Session()
    for name, fn in checks.ALL_CHECKS.items():
        findings.append(fn(target, session=session))
    if openapi_path:
        try:
            with open(openapi_path, "r", encoding="utf-8") as fh:
                text = fh.read()
            spec = json.loads(text) if openapi_path.endswith(".json") else _load_yaml(text)
            findings.extend(analyze_openapi(spec))
        except FileNotFoundError:
            print(f"warning: OpenAPI file not found: {openapi_path}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 - surface any parse error, keep scanning
            print(f"warning: could not read OpenAPI file: {e}", file=sys.stderr)
    return findings


def _load_yaml(text: str) -> dict:
    import yaml  # local import so JSON-only use needs no yaml
    return yaml.safe_load(text)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="API Security Scanner")
    p.add_argument("--target", required=True, help="Base URL, e.g. http://localhost:8000")
    p.add_argument("--openapi", help="Path to an OpenAPI JSON/YAML file (optional static check)")
    p.add_argument("--report-url", help="Platform URL to POST results to (optional)")
    p.add_argument("--token", default=os.environ.get("SCANNER_TOKEN"),
                   help="Project/agent token (or set SCANNER_TOKEN)")
    p.add_argument("--fail-on", default="high", choices=["high", "medium", "low"],
                   help="Minimum severity that fails the build (default: high)")
    p.add_argument("--json-out", help="Write the JSON report to this path")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    verifier = None
    if args.report_url and args.token:
        verifier = make_platform_verifier(args.report_url, args.token)

    try:
        reason = check_target_allowed(args.target, verifier=verifier)
    except TargetError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    print(f"Target allowed: {reason}", file=sys.stderr)

    findings = run_scan(args.target, args.openapi, verifier=verifier)

    print(report.to_text(args.target, findings, color=not args.no_color))
    json_report = report.to_json(args.target, findings)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(json_report)

    if args.report_url and args.token:
        try:
            r = requests.post(args.report_url, data=json_report,
                              headers={"X-Scanner-Token": args.token,
                                       "Content-Type": "application/json"}, timeout=15)
            print(f"\nReported to platform: HTTP {r.status_code}", file=sys.stderr)
        except requests.RequestException as e:
            print(f"\nwarning: could not report to platform: {e}", file=sys.stderr)

    code = report.exit_code(findings, fail_on=args.fail_on)
    if code:
        print(f"\nBuild FAILED: a finding at or above '{args.fail_on}' severity was found.",
              file=sys.stderr)
    else:
        print("\nBuild passed.", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
