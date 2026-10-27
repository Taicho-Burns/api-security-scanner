"""Phase 2 agent.

Runs on the company's own machine. It connects OUT to the platform every few
seconds to ask for a job, runs the scan locally (so the traffic leaves the
company's own IP), and posts the summary back. The platform never connects in.

Usage:
    export AGENT_KEY=agt_xxx              # from the dashboard; never on the CLI
    python -m agent.agent --platform http://localhost:5000 --interval 5

The agent key is read from the environment, not a flag, so it does not show up
in the process list or shell history.
"""
from __future__ import annotations

import argparse
import os
import time

import requests

from scanner import checks, report
from scanner.guard import check_target_allowed, TargetError


def make_verifier(platform: str, agent_key: str):
    def verifier(hostname: str) -> bool:
        try:
            r = requests.get(f"{platform}/api/verify-target",
                             params={"host": hostname},
                             headers={"X-Scanner-Token": agent_key}, timeout=10)
            return r.status_code == 200 and r.json().get("allowed") is True
        except (requests.RequestException, ValueError):
            return False
    return verifier


def run_one_job(platform: str, agent_key: str, job: dict) -> None:
    target = job["target"]
    verifier = make_verifier(platform, agent_key)
    try:
        reason = check_target_allowed(target, verifier=verifier)
    except TargetError as e:
        print(f"  refused: {e}")
        return
    print(f"  scanning {target} ({reason})")
    session = requests.Session()
    findings = [fn(target, session=session) for fn in checks.ALL_CHECKS.values()]
    body = report.to_json(target, findings)
    try:
        r = requests.post(f"{platform}/api/results", data=body,
                          headers={"X-Scanner-Token": agent_key,
                                   "Content-Type": "application/json"}, timeout=15)
        c = report.summarize(findings)
        print(f"  done: {c['high']} high / {c['medium']} medium -> platform HTTP {r.status_code}")
    except requests.RequestException as e:
        print(f"  could not report: {e}")


def poll_loop(platform: str, agent_key: str, interval: float, once: bool = False) -> None:
    print(f"agent started; polling {platform} every {interval}s")
    while True:
        try:
            r = requests.get(f"{platform}/api/agent/jobs",
                             headers={"X-Agent-Key": agent_key}, timeout=10)
            if r.status_code == 401:
                print("invalid agent key; stopping"); return
            job = r.json().get("job")
            if job:
                print(f"got job #{job['id']}: {job['target']}")
                run_one_job(platform, agent_key, job)
        except (requests.RequestException, ValueError) as e:
            print(f"poll error: {e}")
        if once:
            return
        time.sleep(interval)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="API Security Scanner — Phase 2 agent")
    p.add_argument("--platform", required=True, help="Platform base URL")
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--once", action="store_true", help="Poll once and exit (for testing)")
    args = p.parse_args(argv)
    agent_key = os.environ.get("AGENT_KEY")
    if not agent_key:
        print("set AGENT_KEY in the environment first"); return 2
    poll_loop(args.platform, agent_key, args.interval, once=args.once)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
