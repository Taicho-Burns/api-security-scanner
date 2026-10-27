"""Static check of an OpenAPI (Swagger) document.

This sends no traffic at all. It reads the API's own description file and
flags obvious problems: endpoints with no security defined, plain-http
servers, and so on. It is a cheap "shift-left" check that complements the
dynamic checks in checks.py.
"""
from __future__ import annotations

from dataclasses import asdict

from .checks import Finding


def _methods(path_item: dict) -> dict:
    verbs = ("get", "put", "post", "delete", "patch", "options", "head")
    return {m: op for m, op in path_item.items() if m in verbs and isinstance(op, dict)}


def analyze_openapi(spec: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(spec, dict):
        return [Finding("openapi", "OpenAPI document could not be parsed", "low",
                        "A01:2025 Broken Access Control", "The file is not a mapping.",
                        "Provide a valid OpenAPI 3.x document.", confidence="low")]

    has_global_security = bool(spec.get("security"))
    schemes = (spec.get("components") or {}).get("securitySchemes") or {}

    # Plain-http servers
    for server in spec.get("servers", []) or []:
        url = (server or {}).get("url", "")
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            findings.append(Finding(
                "openapi", "Server URL uses plain HTTP", "medium",
                "A04:2025 Cryptographic Failures",
                f"Server {url!r} is declared over http://, so traffic and tokens are unencrypted.",
                "Serve the API over HTTPS and declare https:// URLs.",
                confidence="high", evidence=[url]))

    # No security schemes defined at all
    if not schemes and not has_global_security:
        findings.append(Finding(
            "openapi", "No security schemes defined", "medium",
            "A01:2025 Broken Access Control",
            "The document defines no securitySchemes and no global security, so every "
            "operation is effectively public unless the code enforces auth separately.",
            "Define a security scheme (e.g. bearer JWT) and apply it globally or per operation.",
            confidence="medium"))

    # Operations without security (that look state-changing or data-returning)
    unprotected = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for verb, op in _methods(item).items():
            op_sec = op.get("security", None)
            effective = op_sec if op_sec is not None else (spec.get("security") or [])
            if not effective:
                unprotected.append(f"{verb.upper()} {path}")
    if unprotected:
        shown = unprotected[:12]
        findings.append(Finding(
            "openapi", "Operations with no security requirement", "medium",
            "A01:2025 Broken Access Control",
            f"{len(unprotected)} operation(s) declare no security. If they return or change "
            f"data, they are open to anyone.",
            "Add a security requirement to each non-public operation.",
            confidence="medium", evidence=shown + (["..."] if len(unprotected) > len(shown) else [])))

    if not findings:
        findings.append(Finding(
            "openapi", "No obvious issues in the OpenAPI document", "none",
            "A01:2025 Broken Access Control",
            "Every operation references a security requirement and servers use HTTPS.",
            "No action needed from the static check.", confidence="medium"))
    return findings
