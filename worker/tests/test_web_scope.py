import socket
import pytest
from reverselens_worker.web_scope import ScopeViolation, WebScope, validate_url


def resolver(addresses):
    def resolve(host, port, type=socket.SOCK_STREAM):
        return [
            (socket.AF_INET if ":" not in address else socket.AF_INET6,
             socket.SOCK_STREAM, 6, "", (address, port))
            for address in addresses
        ]
    return resolve


def test_allows_scoped_public_url():
    scope = WebScope(("example.com",), ("/app",))
    assert validate_url(
        "https://example.com/app/home?x=1", scope, resolver(["93.184.216.34"])
    ) == "https://example.com/app/home?x=1"


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://user:pass@example.com/",
    "https://evil.example/",
    "https://example.com/admin",
    "https://example.com/application",
    "https://example.com/app/%2e%2e/admin",
    "https://example.com/app/%252e%252e/admin",
    "https://example.com/app/..%2fadmin",
    "https://example.com:8443/app/",
    "https://example.com:0/app/",
])
def test_rejects_out_of_scope_urls(url):
    scope = WebScope(("example.com",), ("/app",))
    with pytest.raises(ScopeViolation):
        validate_url(url, scope, resolver(["93.184.216.34"]))


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.169.254", "::1", "fc00::1", "fe80::1",
])
def test_rejects_private_loopback_link_local(address):
    scope = WebScope(("example.com",))
    with pytest.raises(ScopeViolation):
        validate_url("https://example.com/", scope, resolver([address]))


def test_rejects_mixed_dns_answers():
    scope = WebScope(("example.com",))
    with pytest.raises(ScopeViolation):
        validate_url(
            "https://example.com/", scope, resolver(["93.184.216.34", "10.1.2.3"])
        )


def test_rejects_empty_dns_answers():
    scope = WebScope(("example.com",))
    with pytest.raises(ScopeViolation):
        validate_url("https://example.com/", scope, resolver([]))


def test_local_lab_loopback_requires_explicit_nonstandard_port():
    scope = WebScope(("localhost",), allowed_ports=(3000,), local_lab=True)
    assert validate_url(
        "http://localhost:3000/", scope, resolver(["127.0.0.1"])
    ) == "http://localhost:3000/"
    with pytest.raises(ScopeViolation):
        validate_url(
            "http://localhost:3000/", scope, resolver(["169.254.169.254"])
        )


def test_rejects_invalid_budgets_and_ports():
    with pytest.raises(ValueError):
        WebScope(("example.com",), max_requests=0)
    with pytest.raises(ValueError):
        WebScope(("example.com",), allowed_ports=(0,))
    with pytest.raises(ValueError):
        WebScope(("example.com",), allowed_ports=(True,))
