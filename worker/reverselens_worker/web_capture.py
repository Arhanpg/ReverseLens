from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from .security import inventory_files
from .web_scope import ScopeViolation, WebScope, validate_url
from .graph_builder import build_graphs

SECRET_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
SECRET_PATTERN = re.compile(
    r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*|((?:api[_-]?key|token|secret|password)=)[^&\s\"'<>]+"
)
QUERY_VALUE_PATTERN = re.compile(r"([?&][A-Za-z0-9_.~%+-]+=)[^&#\"'\s<>]+")


def redact_text(value: str) -> str:
    value = SECRET_PATTERN.sub(
        lambda match: (match.group(1) or match.group(2) or "") + "[REDACTED]", value
    )
    return QUERY_VALUE_PATTERN.sub(r"\1[REDACTED]", value)


def safe_headers(headers: dict) -> dict:
    return {
        key: "[REDACTED]" if key.lower() in SECRET_HEADERS else redact_text(str(value))
        for key, value in headers.items()
    }


def safe_url_for_evidence(value: str) -> str:
    """Remove query strings and fragments before a URL is persisted as evidence."""
    parts = urlsplit(value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def capture_web(job: dict, workspace_root: Path) -> dict:
    """Bounded passive Playwright capture for a URL with an explicit authorization scope."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright is not installed; install worker/requirements-web.txt") from exc

    values = job.get("scope") or {}
    scope = WebScope(
        allowed_hosts=tuple(values.get("allowed_hosts", ())),
        allowed_path_prefixes=tuple(values.get("allowed_path_prefixes", ("/",))),
        allowed_ports=tuple(int(port) for port in values.get("allowed_ports", (80, 443))),
        max_requests=int(values.get("max_requests", 80)),
        max_pages=int(values.get("max_pages", 10)),
        max_response_bytes=int(values.get("max_response_bytes", 2_000_000)),
        max_duration_seconds=int(values.get("max_duration_seconds", 120)),
        local_lab=bool(values.get("local_lab", False)),
    )
    start_url = validate_url(str(job.get("url", "")), scope)
    root = (
        workspace_root
        / "web"
        / str(job.get("targetId", "target"))
        / ("run-" + str(job.get("runId", "run")))
    ).resolve()
    engine = root / "engines" / "playwright"
    for name in ("dom", "screenshots", "responses", "logs", "metadata", "graphs"):
        (engine / name).mkdir(parents=True, exist_ok=True)

    request_records: list[dict] = []
    response_records: list[dict] = []
    page_records: list[dict] = []
    console_records: list[dict] = []
    warnings: list[str] = []
    pages_captured = 0
    request_attempts = 0
    saved_asset_bytes = 0
    started = time.monotonic()
    seen: set[str] = set()
    queue = [start_url]

    def remaining_seconds() -> float:
        return scope.max_duration_seconds - (time.monotonic() - started)

    def within_budget() -> bool:
        return (
            request_attempts < scope.max_requests
            and pages_captured < scope.max_pages
            and remaining_seconds() > 0
            and saved_asset_bytes < scope.max_response_bytes
        )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=False,
            service_workers="block",
            accept_downloads=False,
        )
        page = context.new_page()
        page.set_default_timeout(10_000)

        def guard(route):
            nonlocal request_attempts
            request = route.request
            if request_attempts >= scope.max_requests:
                route.abort("blockedbyclient")
                return
            request_attempts += 1
            try:
                checked = validate_url(request.url, scope)
                # Passive capture only: never submit forms or replay state-changing
                # requests that page scripts attempt to issue.
                if request.method not in {"GET", "HEAD"}:
                    warnings.append(
                        f"blocked non-read request: {request.method} {safe_url_for_evidence(checked)}"
                    )
                    route.abort("blockedbyclient")
                    return
                if checked != request.url or remaining_seconds() <= 0 or pages_captured >= scope.max_pages:
                    route.abort("blockedbyclient")
                    return
                if request.resource_type in {"media", "font"}:
                    route.abort()
                    return
                try:
                    page_url = safe_url_for_evidence(request.frame.url) if request.frame.url else None
                except Exception:
                    page_url = None
                request_records.append(
                    {
                        "url": safe_url_for_evidence(checked),
                        "page_url": page_url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "headers": safe_headers(request.headers),
                    }
                )
                route.continue_()
            except ScopeViolation as exc:
                warnings.append(
                    f"blocked out-of-scope request: {safe_url_for_evidence(request.url)} ({exc})"
                )
                route.abort("blockedbyclient")

        page.route("**/*", guard)

        def on_response(response):
            nonlocal saved_asset_bytes
            try:
                url = validate_url(response.url, scope)
                content_type = response.headers.get("content-type", "")
                content_length_value = response.headers.get("content-length")
                content_length = (
                    int(content_length_value)
                    if content_length_value and content_length_value.isdecimal()
                    else None
                )
                try:
                    page_url = safe_url_for_evidence(response.request.frame.url) if response.request.frame.url else None
                except Exception:
                    page_url = None
                record = {
                    "url": safe_url_for_evidence(url),
                    "page_url": page_url,
                    "status": response.status,
                    "content_type": content_type,
                    "headers": safe_headers(response.headers),
                    "content_length_header": content_length,
                }
                is_javascript = (
                    "javascript" in content_type.lower()
                    or urlsplit(url).path.lower().endswith((".js", ".mjs"))
                )
                if is_javascript:
                    remaining = scope.max_response_bytes - saved_asset_bytes
                    if content_length is None or content_length > remaining:
                        warnings.append(
                            "JavaScript asset skipped: missing or over-budget Content-Length ("
                            + safe_url_for_evidence(url) + ")"
                        )
                    else:
                        body = response.body()
                        if len(body) <= remaining:
                            saved_asset_bytes += len(body)
                            digest = hashlib.sha256(body).hexdigest()
                            asset_name = digest + ".js"
                            (engine / "responses" / asset_name).write_bytes(body)
                            record["saved_asset"] = "responses/" + asset_name
                            record["sha256"] = digest
                        else:
                            warnings.append(
                                "JavaScript asset exceeded declared storage budget: "
                                + safe_url_for_evidence(url)
                            )
                response_records.append(record)
            except Exception as exc:
                warnings.append("response metadata unavailable: " + type(exc).__name__)

        page.on("response", on_response)
        page.on(
            "console",
            lambda message: console_records.append(
                {"type": message.type, "text": redact_text(message.text)[:2000]}
            ),
        )
        page.on(
            "pageerror",
            lambda error: console_records.append(
                {"type": "pageerror", "text": redact_text(str(error))[:2000]}
            ),
        )

        try:
            while queue and within_budget():
                url = validate_url(queue.pop(0), scope)
                if url in seen:
                    continue
                seen.add(url)
                timeout_ms = max(1, min(10_000, int(remaining_seconds() * 1000)))
                try:
                    response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                    pages_captured += 1
                    if remaining_seconds() <= 0:
                        warnings.append("Capture duration budget reached; page artifacts skipped.")
                        break
                    title = redact_text(page.title())[:500]
                    html = redact_text(page.content())
                    html_size = len(html.encode("utf-8"))
                    key = hashlib.sha256(url.encode()).hexdigest()[:16]
                    dom_file = None
                    screenshot_file = None
                    if html_size <= scope.max_response_bytes:
                        dom_file = "dom/" + key + ".html"
                        (engine / dom_file).write_text(html, encoding="utf-8")
                    else:
                        warnings.append(
                            f"DOM snapshot skipped because it exceeds the per-page size limit: {safe_url_for_evidence(url)}"
                        )
                    # Viewport screenshots avoid unbounded full-page image dimensions.
                    if remaining_seconds() > 0:
                        screenshot_file = "screenshots/" + key + ".png"
                        page.screenshot(
                            path=str(engine / screenshot_file),
                            full_page=False,
                            animations="disabled",
                            timeout=max(1, min(10_000, int(max(0.1, remaining_seconds()) * 1000))),
                        )
                    links = page.locator("a[href]").evaluate_all(
                        "(elements) => elements.map((element) => element.href).slice(0, 500)"
                    )
                    safe_links = []
                    for link in links:
                        try:
                            candidate = validate_url(urljoin(url, link), scope)
                            evidence_url = safe_url_for_evidence(candidate)
                            if evidence_url not in safe_links:
                                safe_links.append(evidence_url)
                            if candidate not in seen and len(queue) + pages_captured < scope.max_pages:
                                queue.append(candidate)
                        except ScopeViolation:
                            pass
                    page_record = {
                        "url": safe_url_for_evidence(url),
                        "title": title,
                        "status": response.status if response else None,
                        "dom_file": dom_file,
                        "screenshot_file": screenshot_file,
                        "links": safe_links,
                    }
                    page_records.append(page_record)
                    (engine / "metadata" / (key + ".json")).write_text(
                        json.dumps(page_record, indent=2), encoding="utf-8"
                    )
                except Exception as exc:
                    warnings.append(
                        f"page capture failed for {safe_url_for_evidence(url)}: {type(exc).__name__}: {exc}"[:1000]
                    )
        finally:
            context.close()
            browser.close()

    graph_data = build_graphs(engine, page_records, request_records, response_records)
    for graph_name, graph in graph_data.items():
        (engine / "graphs" / (graph_name + ".json")).write_text(
            json.dumps(graph, indent=2), encoding="utf-8"
        )

    for name, records in (
        ("console.json", console_records),
        ("requests.json", request_records),
        ("responses.json", response_records),
    ):
        (engine / "logs" / name).write_text(json.dumps(records, indent=2), encoding="utf-8")

    duration = int((time.monotonic() - started) * 1000)
    manifest = {
        "schema_version": "1.0.0",
        "engine_id": "playwright",
        "status": "succeeded" if not warnings else ("partial" if pages_captured else "failed"),
        "start_url": safe_url_for_evidence(start_url),
        "pages_captured": pages_captured,
        "requests_attempted": request_attempts,
        "requests_observed": len(request_records),
        "responses_observed": len(response_records),
        "graphs_created": sorted(graph_data.keys()),
        "javascript_asset_bytes_saved": saved_asset_bytes,
        "duration_ms": duration,
        "authorization_scope": {
            "allowed_hosts": list(scope.allowed_hosts),
            "allowed_path_prefixes": list(scope.allowed_path_prefixes),
            "allowed_ports": list(scope.allowed_ports),
            "max_requests": scope.max_requests,
            "max_pages": scope.max_pages,
            "max_saved_javascript_bytes": scope.max_response_bytes,
            "max_duration_seconds": scope.max_duration_seconds,
            "local_lab": scope.local_lab,
        },
        "limitations": [
            "Captures browser-visible behavior only; it does not recover server code.",
            "No login, cookies, browser profile or credentialed session is used.",
            "Only GET and HEAD browser requests are allowed; state-changing requests are blocked.",
            "The saved-JavaScript byte cap is not a total network-transfer cap.",
            "Network-layer egress filtering is required to enforce a hard response-size and SSRF boundary.",
            "Other reconstruction engines are separate integrations and are not run by this worker.",
        ],
        "warnings": warnings,
    }
    (engine / "engine-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    inventory = [item for item in inventory_files(engine) if item["path"] != "engine-manifest.json"]
    manifest["files"] = inventory
    (engine / "engine-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "status": manifest["status"],
        "engine_id": "playwright",
        "duration_ms": duration,
        "artifact_count": len(inventory),
        "output_bytes": sum(item["size_bytes"] for item in inventory),
        "manifest": manifest,
    }
