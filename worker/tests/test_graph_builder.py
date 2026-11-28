import hashlib
from pathlib import Path

from reverselens_worker.graph_builder import build_graphs


def test_graphs_preserve_route_request_and_dependency_evidence(tmp_path):
    engine = tmp_path / "engines" / "playwright"
    (engine / "responses").mkdir(parents=True)
    source = b"/* react.production.min.js */ React.createElement('div')"
    digest = hashlib.sha256(source).hexdigest()
    asset = engine / "responses" / (digest + ".js")
    asset.write_bytes(source)

    pages = [
        {
            "url": "https://example.test/",
            "title": "Home",
            "status": 200,
            "dom_file": "dom/home.html",
            "links": ["https://example.test/about"],
        },
        {
            "url": "https://example.test/about",
            "title": "About",
            "status": 200,
            "dom_file": "dom/about.html",
            "links": [],
        },
    ]
    requests = [
        {
            "url": "https://example.test/assets/app.js",
            "page_url": "https://example.test/",
            "method": "GET",
            "resource_type": "script",
        }
    ]
    responses = [
        {
            "url": "https://example.test/assets/app.js",
            "page_url": "https://example.test/",
            "status": 200,
            "content_type": "application/javascript",
            "saved_asset": "responses/" + asset.name,
            "sha256": digest,
        }
    ]

    graphs = build_graphs(engine, pages, requests, responses)
    route = graphs["route-graph"]
    deps = graphs["dependency-graph"]
    network = graphs["network-graph"]

    assert any(edge["to"] == "https://example.test/about" for edge in route["edges"])
    assert any(node.get("name") == "react" and node.get("validation_status") == "candidate_unverified"
               for node in deps["nodes"])
    assert any(edge["kind"] == "loads_script_asset" for edge in deps["edges"])
    assert any(node["kind"] == "endpoint" for node in network["nodes"])
    assert all("evidence_path" in edge for graph in graphs.values() for edge in graph["edges"])
