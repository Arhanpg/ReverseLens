import sys

from reverselens_worker.engine_runner import run_command, select_base_split


def test_runner_executes_argument_vector_without_shell():
    metrics_path = tmp_path / "wrapper-metrics.json"
    code, stdout, stderr, duration, metrics = run_command(
        [sys.executable, "-c", "print('worker-ok')"], timeout=10, metrics_path=metrics_path
    )
    assert code == 0
    assert "worker-ok" in stdout
    assert duration >= 0
    assert metrics["wall_time_ms"] >= 0


def test_base_split_prefers_base_named_apk(tmp_path):
    locale = tmp_path / "config.en.apk"
    base = tmp_path / "base-master.apk"
    locale.touch()
    base.touch()
    assert select_base_split([locale, base]) == base



def test_resource_wrapper_records_wall_and_cpu_metrics(tmp_path):
    import json
    import subprocess
    import sys
    from pathlib import Path

    wrapper = Path(__file__).parents[1] / "reverselens_worker" / "resource_wrapper.py"
    metrics = tmp_path / "metrics.json"
    result = subprocess.run(
        [sys.executable, str(wrapper), "--metrics", str(metrics), "--timeout", "5",
         "--", sys.executable, "-c", "print('benchmark-wrapper-ok')"],
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0
    assert "benchmark-wrapper-ok" in result.stdout
    recorded = json.loads(metrics.read_text())
    assert recorded["wall_time_ms"] >= 0
    assert recorded["cpu_time_ms"] >= 0
    assert recorded["peak_rss_bytes"] >= 0
