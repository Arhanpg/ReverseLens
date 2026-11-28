from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit


class ScopeViolation(ValueError):
    """Raised when a URL falls outside the asserted authorization scope."""


def _fully_unquote(value: str) -> str:
    for _ in range(5):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def _safe_path(path: str) -> str:
    decoded = _fully_unquote(path or "/")
    if "\\" in decoded or "\x00" in decoded:
        raise ScopeViolation("Path contains an invalid separator or NUL byte")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ScopeViolation("Dot-segment paths are not permitted")
    return decoded


@dataclass(frozen=True)
class WebScope:
    allowed_hosts: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...] = ("/",)
    allowed_ports: tuple[int, ...] = (80, 443)
    max_requests: int = 80
    max_pages: int = 10
    max_response_bytes: int = 2_000_000
    max_duration_seconds: int = 120
    local_lab: bool = False

    def __post_init__(self):
        if not self.allowed_hosts:
            raise ValueError("At least one explicitly authorized host is required")
        if not 1 <= self.max_requests <= 10000:
            raise ValueError("max_requests must be between 1 and 10000")
        if not 1 <= self.max_pages <= 500:
            raise ValueError("max_pages must be between 1 and 500")
        if not 1024 <= self.max_response_bytes <= 50_000_000:
            raise ValueError("max_response_bytes must be between 1024 and 50000000")
        if not 1 <= self.max_duration_seconds <= 1800:
            raise ValueError("max_duration_seconds must be between 1 and 1800")
        hosts = tuple(host.strip().lower().rstrip(".") for host in self.allowed_hosts)
        if any(not host or "/" in host or ":" in host or "*" in host for host in hosts):
            raise ValueError("Allowed hosts must be exact DNS names without wildcard or port")
        ports = tuple(sorted(set(self.allowed_ports)))
        if not ports or any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            for port in ports
        ):
            raise ValueError("Allowed ports must contain valid TCP ports")
        prefixes = tuple(prefix if prefix.startswith("/") else "/" + prefix
                         for prefix in self.allowed_path_prefixes)
        if not prefixes:
            raise ValueError("At least one path prefix is required")
        for prefix in prefixes:
            _safe_path(prefix)
        object.__setattr__(self, "allowed_hosts", hosts)
        object.__setattr__(self, "allowed_ports", ports)
        object.__setattr__(self, "allowed_path_prefixes", prefixes)


def _allowed_ip(address: str, local_lab: bool) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if local_lab:
        return not (
            ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved
        )
    return ip.is_global


def validate_url(url: str, scope: WebScope, resolver=socket.getaddrinfo) -> str:
    """Validate protocol, exact host, explicit port, path scope and all DNS answers."""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ScopeViolation("Only HTTP and HTTPS URLs are permitted")
        if parts.username or parts.password:
            raise ScopeViolation("URLs containing credentials are not permitted")
        if not parts.hostname:
            raise ScopeViolation("URL must include a host")
        host = parts.hostname.lower().rstrip(".")
        if host not in scope.allowed_hosts:
            raise ScopeViolation(f"Host is outside authorized scope: {host}")
        explicit_port = parts.port
        port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ScopeViolation("Invalid destination port")
        if port not in scope.allowed_ports:
            raise ScopeViolation(f"Destination port {port} is outside authorized scope")
        path = parts.path or "/"
        safe_path = _safe_path(path)
        allowed = False
        for prefix in scope.allowed_path_prefixes:
            safe_prefix = _safe_path(prefix)
            prefix_root = safe_prefix.rstrip("/")
            if safe_prefix == "/" or safe_path == prefix_root or safe_path.startswith(prefix_root + "/"):
                allowed = True
                break
        if not allowed:
            raise ScopeViolation(f"Path is outside authorized scope: {path}")
        answers = resolver(host, port, type=socket.SOCK_STREAM)
        addresses = sorted({answer[4][0] for answer in answers})
        if not addresses:
            raise ScopeViolation("Host did not resolve to an address")
        for address in addresses:
            if not _allowed_ip(address, scope.local_lab):
                raise ScopeViolation(f"Host resolved to prohibited address: {address}")
        netloc = host if explicit_port is None else f"{host}:{explicit_port}"
        return urlunsplit((scheme, netloc, path, parts.query, ""))
    except ScopeViolation:
        raise
    except (ValueError, OSError, socket.gaierror) as exc:
        raise ScopeViolation(f"URL could not be safely validated: {exc}") from exc
