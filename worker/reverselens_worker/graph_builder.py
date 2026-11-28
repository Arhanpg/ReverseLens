from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


LIBRARY_SIGNATURES = (
    ("react", re.compile(r"React(?:DOM)?\.createElement|react\.production(?:\.min)?\.js|__REACT_DEVTOOLS_GLOBAL_HOOK__")),
    ("vue", re.compile(r"Vue\.version|__VUE__|vue\.global(?:\.prod)?\.js")),
    ("jquery", re.compile(r"jQuery v\d|window\.jQuery|jquery(?:-\d[\w.-]*)?\.min\.js")),
    ("angular", re.compile(r"ngVersion|@angular/core|angular(?:\.min)?\.js")),
    ("svelte", re.compile(r"svelte/internal|svelte/internal/client")),
    ("lodash", re.compile(r"lodash(?:\.min)?\.js|_.assignIn|_.debounce")),
)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def _asset_candidate(path: Path, relative: str, digest: str) -> list[dict]:
    try:
        if not path.is_file() or path.stat().st_size > 2_000_000:
            return []
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    matches = []
    for library, signature in LIBRARY_SIGNATURES:
        match = signature.search(source)
        if match:
            matches.append({
                "library": library,
                "confidence": "low",
                "match_excerpt": match.group(0)[:120],
                "evidence_path": relative,
                "evidence_sha256": digest,
                "validation_status": "candidate_unverified",
            })
    return matches


def build_graphs(
    engine_root: Path,
    pages: list[dict],
    requests: list[dict],
    responses: list[dict],
) -> dict[str, dict]:
    """Build evidence-linked graphs; library identifications remain unverified candidates."""
    page_nodes = {}
    route_edges = []
    for page in pages:
        url = page.get("url")
        if not url:
            continue
        page_nodes[url] = {
            "id": url,
            "kind": "route",
            "title": page.get("title", ""),
            "status": page.get("status"),
            "evidence_path": page.get("dom_file"),
        }
        for destination in page.get("links", []):
            if destination:
                route_edges.append({
                    "from": url,
                    "to": destination,
                    "kind": "navigates_to",
                    "evidence_path": page.get("dom_file"),
                    "validation_status": "observed_link",
                })
    route_graph = {
        "schema_version": "1.0.0",
        "graph_type": "route",
        "nodes": list(page_nodes.values()),
        "edges": route_edges,
        "limitations": [
            "Links are observed from rendered anchor elements; they do not prove a route is reachable.",
            "Routes requiring user interaction or authentication are not discovered.",
        ],
    }

    dependency_nodes = {}
    dependency_edges = []
    for record in responses:
        asset = record.get("saved_asset")
        if not asset:
            continue
        digest = record.get("sha256")
        if not digest:
            continue
        asset_id = "asset:" + digest
        dependency_nodes[asset_id] = {
            "id": asset_id,
            "kind": "javascript_asset",
            "url": record.get("url"),
            "evidence_path": "responses/" + Path(asset).name,
            "evidence_sha256": digest,
        }
        page_url = record.get("page_url")
        if page_url and page_url in page_nodes:
            dependency_edges.append({
                "from": page_url,
                "to": asset_id,
                "kind": "loads_script_asset",
                "evidence_path": "logs/responses.json",
            })
        asset_path = (engine_root / asset).resolve()
        try:
            asset_path.relative_to(engine_root.resolve())
        except ValueError:
            continue
        for match in _asset_candidate(asset_path, "responses/" + Path(asset).name, digest):
            library_id = "library:" + match["library"]
            dependency_nodes.setdefault(library_id, {
                "id": library_id,
                "kind": "library_candidate",
                "name": match["library"],
                "confidence": match["confidence"],
                "validation_status": match["validation_status"],
            })
            dependency_edges.append({
                "from": asset_id,
                "to": library_id,
                "kind": "signature_candidate",
                "evidence_path": match["evidence_path"],
                "evidence_sha256": match["evidence_sha256"],
                "match_excerpt": match["match_excerpt"],
                "validation_status": "candidate_unverified",
            })
    dependency_graph = {
        "schema_version": "1.0.0",
        "graph_type": "dependency",
        "nodes": list(dependency_nodes.values()),
        "edges": dependency_edges,
        "limitations": [
            "Library signatures are heuristic candidates, not package-manager or SBOM proof.",
            "Unrecognized, bundled, tree-shaken or transformed dependencies may be missed.",
        ],
    }

    network_nodes = {}
    network_edges = []
    for record in requests:
        url = record.get("url")
        origin = _origin(url or "")
        if not origin:
            continue
        origin_id = "origin:" + origin
        network_nodes[origin_id] = {"id": origin_id, "kind": "origin", "origin": origin}
        path = urlsplit(url).path or "/"
        endpoint_id = "endpoint:" + origin + path
        network_nodes[endpoint_id] = {
            "id": endpoint_id,
            "kind": "endpoint",
            "url": origin + path,
        }
        page_url = record.get("page_url")
        if page_url and page_url in page_nodes:
            network_edges.append({
                "from": page_url,
                "to": origin_id,
                "kind": "browser_request",
                "method": record.get("method"),
                "resource_type": record.get("resource_type"),
                "evidence_path": "logs/requests.json",
            })
        network_edges.append({
            "from": origin_id,
            "to": endpoint_id,
            "kind": "requests_endpoint",
            "method": record.get("method"),
            "resource_type": record.get("resource_type"),
            "evidence_path": "logs/requests.json",
        })
    for record in responses:
        url = record.get("url")
        origin = _origin(url or "")
        if not origin:
            continue
        origin_id = "origin:" + origin
        path = urlsplit(url).path or "/"
        endpoint_id = "endpoint:" + origin + path
        if endpoint_id in network_nodes:
            network_edges.append({
                "from": endpoint_id,
                "to": "response:" + str(record.get("status", "unknown")),
                "kind": "response_status",
                "status": record.get("status"),
                "evidence_path": "logs/responses.json",
            })
            status_id = "response:" + str(record.get("status", "unknown"))
            network_nodes[status_id] = {
                "id": status_id,
                "kind": "http_status",
                "status": record.get("status"),
            }
    network_graph = {
        "schema_version": "1.0.0",
        "graph_type": "network",
        "nodes": list(network_nodes.values()),
        "edges": network_edges,
        "limitations": [
            "Only requests observed in this browser session are represented.",
            "DNS, socket-level and server-to-server traffic are not captured by this graph.",
        ],
    }
    return {
        "route-graph": route_graph,
        "dependency-graph": dependency_graph,
        "network-graph": network_graph,
    }
