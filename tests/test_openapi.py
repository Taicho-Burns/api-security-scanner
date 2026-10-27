"""Static OpenAPI check tests (no network)."""
from scanner.openapi_check import analyze_openapi


def test_flags_unprotected_and_http():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "http://api.example.com"}],
        "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    findings = analyze_openapi(spec)
    checks = {f.title for f in findings}
    assert any("plain HTTP" in t for t in checks)
    assert any("no security" in t.lower() for t in checks)


def test_clean_spec_has_no_findings():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com"}],
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
        "security": [{"bearer": []}],
        "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    findings = analyze_openapi(spec)
    assert all(f.severity == "none" for f in findings)
