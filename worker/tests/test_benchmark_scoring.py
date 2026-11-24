from reverselens_worker.benchmark_scoring import score_observations


def observation(key: str, evidence: bool = True) -> dict:
    return {"canonical_key": key, "evidence_path": "raw/sample.json" if evidence else None,
            "evidence_sha256": "a" * 64 if evidence else None}


def test_verified_ground_truth_produces_precision_recall_and_f1():
    result = score_observations(
        [observation("permission:android.permission.internet"),
         observation("permission:android.permission.camera"),
         observation("permission:android.permission.internet")],
        [{"canonical_key": "permission:android.permission.internet"},
         {"canonical_key": "permission:android.permission.contacts"}],
    )
    assert result["true_positive"] == 1
    assert result["false_positive"] == 1
    assert result["false_negative"] == 1
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["f1"] == 0.5
    assert result["duplicate_rate"] == 1 / 3
    assert result["evidence_completeness"] == 1.0


def test_accuracy_is_null_without_verified_ground_truth():
    result = score_observations([observation("class:example.demo")], [])
    assert result["precision"] is None
    assert result["recall"] is None
    assert result["f1"] is None
    assert result["ground_truth_available"] is False


def test_empty_observations_with_ground_truth_are_zero_not_unknown():
    result = score_observations([], [{"canonical_key": "permission:android.permission.internet"}])
    assert result["precision"] == 0.0
    assert result["recall"] == 0.0
    assert result["f1"] == 0.0
    assert result["missed_items"] == ["permission:android.permission.internet"]
