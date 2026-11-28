from reverselens_worker.web_capture import redact_text

def test_redacts_bearer_and_query_secrets():
    cleaned = redact_text("Bearer abc.def.ghi api_key=supersecret&ok=1")
    assert "abc.def.ghi" not in cleaned
    assert "supersecret" not in cleaned
    assert "[REDACTED]" in cleaned
