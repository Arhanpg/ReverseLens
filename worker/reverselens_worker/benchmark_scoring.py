from __future__ import annotations

from collections import Counter


def score_observations(observations: list[dict], ground_truth: list[dict]) -> dict:
    """Score evidence against verified/applicable ground truth only."""
    expected = {str(item["canonical_key"]).strip().lower() for item in ground_truth}
    observed_items = [str(item["canonical_key"]).strip().lower() for item in observations]
    observed = set(observed_items)
    available = bool(expected)

    if available:
        matched = sorted(expected & observed)
        missed = sorted(expected - observed)
        extras = sorted(observed - expected)
        tp, fp, fn = len(matched), len(extras), len(missed)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        coverage = tp / len(expected)
    else:
        matched, missed, extras = [], [], []
        tp = fp = fn = None
        precision = recall = f1 = coverage = None

    duplicate_count = sum(count - 1 for count in Counter(observed_items).values())
    duplicate_rate = duplicate_count / len(observed_items) if observed_items else 0.0
    evidenced = sum(1 for item in observations if item.get("evidence_path") and item.get("evidence_sha256"))
    evidence_completeness = evidenced / len(observations) if observations else 0.0

    return {
        "ground_truth_available": available,
        "ground_truth_count": len(expected) if available else None,
        "observation_count": len(observations),
        "unique_observation_count": len(observed),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "coverage": coverage,
        "duplicate_rate": duplicate_rate,
        "evidence_completeness": evidence_completeness,
        "matched_items": matched,
        "missed_items": missed,
        "false_positive_items": extras,
    }
