"""The target guard is the safety core: these tests pin its behaviour."""
import pytest

from scanner.guard import check_target_allowed, parse_target, TargetError


def test_localhost_always_allowed():
    assert "local" in check_target_allowed("http://localhost:8000")
    assert "local" in check_target_allowed("http://127.0.0.1:8000")


def test_private_address_allowed():
    assert "local" in check_target_allowed("http://192.168.1.10")
    assert "local" in check_target_allowed("http://10.0.0.5:3000")


def test_public_refused_without_verifier():
    with pytest.raises(TargetError):
        check_target_allowed("http://api.example.com")


def test_public_refused_when_verifier_says_no():
    with pytest.raises(TargetError):
        check_target_allowed("https://api.example.com", verifier=lambda h: False)


def test_public_allowed_when_verifier_says_yes():
    reason = check_target_allowed("https://api.example.com", verifier=lambda h: True)
    assert "verified" in reason


def test_bad_scheme_and_url():
    with pytest.raises(TargetError):
        parse_target("ftp://example.com")
    with pytest.raises(TargetError):
        parse_target("not-a-url")
