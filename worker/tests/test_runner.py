import sys

from reverselens_worker.engine_runner import run_command, select_base_split


def test_runner_executes_argument_vector_without_shell():
    code, stdout, stderr, duration = run_command([sys.executable, "-c", "print('worker-ok')"], timeout=10)
    assert code == 0
    assert "worker-ok" in stdout
    assert duration >= 0


def test_base_split_prefers_base_named_apk(tmp_path):
    locale = tmp_path / "config.en.apk"
    base = tmp_path / "base-master.apk"
    locale.touch()
    base.touch()
    assert select_base_split([locale, base]) == base
