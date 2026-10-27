"""Target guard: decides whether the scanner is allowed to scan a URL.

This is the safety core of the whole project. The scanner must never be
usable against systems the user does not control. Two things are allowed:

  1. A loopback / private target (localhost, 127.0.0.1, ::1, a private LAN
     address). In CI mode the API under test runs inside the runner on
     localhost, so this covers the main version.

  2. A public target that has been verified with the platform. The scanner
     asks the platform "is this host verified for my token?" and only
     proceeds if the platform says yes (Phase 2, agent mode).

Anything else is refused before a single request is sent.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class TargetError(Exception):
    """Raised when a target URL is malformed or not allowed."""


def parse_target(url: str) -> tuple[str, str]:
    """Return (scheme, hostname) for a target URL, or raise TargetError."""
    if not url or "://" not in url:
        raise TargetError(f"Target must be a full URL like http://localhost:8000 (got: {url!r})")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TargetError(f"Only http/https targets are allowed (got scheme: {parsed.scheme!r})")
    if not parsed.hostname:
        raise TargetError("Target URL has no hostname")
    return parsed.scheme, parsed.hostname


def _resolved_ips(hostname: str) -> list[ipaddress._BaseAddress]:
    """Resolve a hostname to the IP addresses it points at."""
    ips: list[ipaddress._BaseAddress] = []
    try:
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            # Strip an IPv6 zone id such as fe80::1%eth0 before parsing.
            addr = addr.split("%", 1)[0]
            ips.append(ipaddress.ip_address(addr))
    except (socket.gaierror, ValueError):
        pass
    return ips


def is_loopback_or_private(hostname: str) -> bool:
    """True if the hostname is loopback/private, including after DNS resolution.

    We check both the literal (e.g. "localhost") and every IP it resolves to,
    so a public name that secretly points at a private address is still
    treated as private and never scanned as a "public" target.
    """
    if hostname in ("localhost", "ip6-localhost"):
        return True
    try:
        literal = ipaddress.ip_address(hostname)
        return literal.is_loopback or literal.is_private or literal.is_link_local
    except ValueError:
        pass  # not an IP literal; resolve it below
    ips = _resolved_ips(hostname)
    if not ips:
        # Cannot resolve. Treat as not-private so it falls through to the
        # verification path, which will refuse an unverified public name.
        return False
    return all(ip.is_loopback or ip.is_private or ip.is_link_local for ip in ips)


def check_target_allowed(url: str, verifier=None) -> str:
    """Return the reason a target is allowed, or raise TargetError.

    verifier: optional callable(hostname) -> bool, asked only for public
    targets. In CI mode there is no verifier and only localhost is allowed.
    In agent mode the verifier calls the platform to confirm DNS ownership.
    """
    _scheme, hostname = parse_target(url)
    if is_loopback_or_private(hostname):
        return f"local target ({hostname}) — always allowed"
    if verifier is None:
        raise TargetError(
            f"Refusing to scan public host {hostname!r}: in CI mode only "
            f"localhost / private targets are allowed. To scan a deployed "
            f"API, verify the domain first (Phase 2)."
        )
    if verifier(hostname):
        return f"public target ({hostname}) — ownership verified"
    raise TargetError(
        f"Refusing to scan {hostname!r}: domain is not verified for this "
        f"account. Prove ownership with a DNS TXT record first."
    )
