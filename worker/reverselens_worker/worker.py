from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import redis
import requests

from .engine_runner import execute

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("reverselens.worker")


def report(api_url: str, token: str, execution_id: str, payload: dict) -> None:
    response = requests.put(
        f"{api_url.rstrip('/')}/internal/v1/worker/executions/{execution_id}",
        json=payload,
        headers={"X-ReverseLens-Worker-Token": token},
        timeout=20,
    )
    response.raise_for_status()


def main() -> None:
    root = Path(os.getenv("WORKSPACE_ROOT", "/workspace")).resolve()
    redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=int(os.getenv("REDIS_PORT", "6379")),
        password=os.getenv("REDIS_PASSWORD") or None, decode_responses=True, socket_timeout=30)
    queue = os.getenv("QUEUE_NAME", "reverselens:analysis:jobs")
    api_url, token = os.getenv("API_INTERNAL_URL", "http://api:8080"), os.environ["REVERSE_LENS_WORKER_TOKEN"]
    log.info("Worker started queue=%s workspace=%s", queue, root)
    while True:
        try:
            item = redis_client.brpop(queue, timeout=5)
            if not item:
                continue
            _, encoded = item
            job = json.loads(encoded)
            execution_id = str(job["executionId"])
            log.info("Starting engine=%s run=%s", job.get("engineId"), job.get("runId"))
            try:
                report(api_url, token, execution_id, {"status": "running", "toolVersion": None,
                    "exitCode": None, "durationMs": None, "outputBytes": None, "errorSummary": None})
                result = execute(job, root)
                report(api_url, token, execution_id, {"status": result["status"], "toolVersion": result["toolVersion"],
                    "exitCode": result["exit_code"], "durationMs": result["duration_ms"],
                    "outputBytes": result["output_bytes"], "errorSummary": result["errorSummary"]})
                log.info("Finished execution=%s status=%s artifacts=%s", execution_id, result["status"], result["artifact_count"])
            except Exception as exc:
                log.exception("Execution %s failed", execution_id)
                try:
                    report(api_url, token, execution_id, {"status": "failed", "toolVersion": None,
                        "exitCode": 1, "durationMs": 0, "outputBytes": 0,
                        "errorSummary": f"{type(exc).__name__}: {exc}"[:4000]})
                except requests.RequestException:
                    log.exception("Could not report failure for %s", execution_id)
        except (redis.RedisError, requests.RequestException, json.JSONDecodeError) as exc:
            log.error("Worker infrastructure error: %s", exc)
            time.sleep(3)


if __name__ == "__main__":
    main()
