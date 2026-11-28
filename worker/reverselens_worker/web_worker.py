from __future__ import annotations
import json, logging, os, time
from pathlib import Path
import redis
from .web_capture import capture_web
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("reverselens.web-worker")
def main():
    root = Path(os.getenv("WORKSPACE_ROOT", "/workspace")).resolve()
    client = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=int(os.getenv("REDIS_PORT", "6379")),
        password=os.getenv("REDIS_PASSWORD") or None, decode_responses=True, socket_timeout=30)
    queue = os.getenv("WEB_QUEUE_NAME", "reverselens:web:capture")
    log.info("Web capture worker listening on %s", queue)
    while True:
        try:
            item = client.brpop(queue, timeout=5)
            if not item:
                continue
            job = json.loads(item[1])
            try:
                result = capture_web(job, root)
                log.info("Capture %s ended with %s (%s artifacts)", job.get("runId"),
                         result["status"], result["artifact_count"])
            except Exception:
                log.exception("Web capture job failed for run=%s", job.get("runId"))
        except redis.RedisError as exc:
            log.error("Queue error: %s", exc)
            time.sleep(3)
if __name__ == "__main__":
    main()
