import pytest
from datetime import datetime, timedelta, timezone

from reverselens_worker.web_capture import apply_authorization_expiry, redact_text


def test_redacts_bearer_and_query_secrets():
    cleaned = redact_text("Bearer abc.def.ghi api_key=supersecret&ok=1")
    assert "abc.def.ghi" not in cleaned
    assert "supersecret" not in cleaned
    assert "[REDACTED]" in cleaned


def test_authorization_expiry_clamps_capture_duration():
    now = datetime(2026, 11, 28, 12, 0, tzinfo=timezone.utc)
    values = apply_authorization_expiry(
        {"max_duration_seconds": 120},
        (now + timedelta(seconds=45)).isoformat(),
        now,
    )
    assert values["max_duration_seconds"] == 45


def test_authorization_expiry_never_increases_configured_duration():
    now = datetime(2026, 11, 28, 12, 0, tzinfo=timezone.utc)
    values = apply_authorization_expiry(
        {"max_duration_seconds": 30},
        (now + timedelta(minutes=5)).isoformat(),
        now,
    )
    assert values["max_duration_seconds"] == 30


@pytest.mark.parametrize("expiry", ["", "not-a-date", "2026-11-29T12:00:00"])
def test_rejects_missing_invalid_or_timezone_naive_expiry(expiry):
    with pytest.raises(RuntimeError):
        apply_authorization_expiry({"max_duration_seconds": 120}, expiry)


def test_rejects_expired_authorization():
    now = datetime(2026, 11, 28, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(RuntimeError, match="expired"):
        apply_authorization_expiry(
            {"max_duration_seconds": 120},
            (now - timedelta(seconds=1)).isoformat(),
            now,
        )
