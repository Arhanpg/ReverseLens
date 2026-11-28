from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import redis
import requests

from .web_capture import capture_web

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("reverselens.web-worker")


def report(api_url: str, token: str, run_id: str, payload: dict) -> None:
    response = requests.put(
        f"{api_url.rstrip('/')}/internal/v1/web-captures/{run_id}",
        json=payload,
        headers={"X-ReverseLens-Worker-Token": token},
        timeout=20,
    )
    response.raise_for_status()


def main() -> None:
    root = Path(os.getenv("WORKSPACE_ROOT", "/workspace")).resolve()
    client = redis.Redis(
        host=os.getenv("REDIS_HOST", "redis"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        password=os.getenv("REDIS_PASSWORD") or None,
        decode_responses=True,
        socket_timeout=30,
    )
    queue = os.getenv("WEB_QUEUE_NAME", "reverselens:web:capture")
    api_url = os.getenv("API_INTERNAL_URL", "http://api:8080")
    token = os.environ.get("REVERSE_LENS_WORKER_TOKEN")
    if not token:
        raise RuntimeError("REVERSE_LENS_WORKER_TOKEN is required for API status callbacks.")
    log.info("Web capture worker listening on %s", queue)

    while True:
        try:
            item = client.brpop(queue, timeout=5)
            if not item:
                continue
            job = json.loads(item[1])
            run_id = str(job["runId"])
            log.info("Starting Playwright capture run=%s target=%s", run_id, job.get("targetId"))
            try:
                report(api_url, token, run_id, {"status": "running", "manifest": {}, "errorSummary": None})
                result = capture_web(job, root)
                manifest = result.get("manifest", {})
                error_summary = None
                if result.get("status") == "failed":
                    error_summary = "; ".join(manifest.get("warnings", []))[:4000] or "Browser capture failed."
                report(
                    api_url,
                    token,
                    run_id,
                    {"status": result["status"], "manifest": manifest, "errorSummary": error_summary},
                )
                log.info(
                    "Finished run=%s status=%s artifacts=%s",
                    run_id,
                    result["status"],
                    result["artifact_count"],
                )
            except Exception as exc:
                log.exception("Web capture failed for run=%s", run_id)
                try:
                    report(
                        api_url,
                        token,
                        run_id,
                        {
                            "status": "failed",
                            "manifest": {},
                            "errorSummary": f"{type(exc).__name__}: {exc}"[:4000],
                        },
                    )
                except requests.RequestException:
                    log.exception("Could not report failure for run=%s", run_id)
        except (redis.RedisError, requests.RequestException, json.JSONDecodeError) as exc:
            log.error("Web worker infrastructure error: %s", exc)
            time.sleep(3)


if __name__ == "__main__":
    main()
