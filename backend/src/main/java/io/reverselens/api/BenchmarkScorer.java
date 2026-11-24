package io.reverselens.api;

import java.util.*;
import java.util.stream.Collectors;

record BenchmarkScore(
    boolean accuracyAvailable, Integer groundTruthCount, Integer truePositive,
    Integer falsePositive, Integer falseNegative, Double precision, Double recall,
    Double f1, Double coverage, double duplicateRate, double evidenceCompleteness,
    List<String> matchedItems, List<String> missedItems, List<String> falsePositiveItems
) {}

final class BenchmarkScorer {
    private BenchmarkScorer() {}

    static BenchmarkScore score(Collection<String> expectedKeys, List<Map<String,Object>> observations) {
        Set<String> expected = expectedKeys.stream().map(BenchmarkScorer::canonical)
                .filter(s -> !s.isBlank()).collect(Collectors.toCollection(TreeSet::new));
        List<String> observedValues = observations.stream()
                .map(o -> canonical(String.valueOf(o.getOrDefault("canonicalKey", ""))))
                .filter(s -> !s.isBlank()).toList();
        Set<String> observed = new TreeSet<>(observedValues);
        boolean available = !expected.isEmpty();
        List<String> matched = available ? expected.stream().filter(observed::contains).toList() : List.of();
        List<String> missed = available ? expected.stream().filter(k -> !observed.contains(k)).toList() : List.of();
        List<String> extras = available ? observed.stream().filter(k -> !expected.contains(k)).toList() : List.of();
        Integer tp = available ? matched.size() : null;
        Integer fp = available ? extras.size() : null;
        Integer fn = available ? missed.size() : null;
        Double precision = available ? (tp + fp == 0 ? 0.0 : (double)tp / (tp + fp)) : null;
        Double recall = available ? (double)tp / (tp + fn) : null;
        Double f1 = available ? (precision + recall == 0 ? 0.0 : 2 * precision * recall / (precision + recall)) : null;
        Double coverage = available ? (double)tp / expected.size() : null;
        long duplicateCount = observedValues.size() - observed.size();
        double duplicateRate = observedValues.isEmpty() ? 0.0 : (double)duplicateCount / observedValues.size();
        long evidenced = observations.stream().filter(o -> o.get("evidencePath") != null && o.get("evidenceSha256") != null).count();
        double evidence = observations.isEmpty() ? 0.0 : (double)evidenced / observations.size();
        return new BenchmarkScore(available, available ? expected.size() : null, tp, fp, fn,
                precision, recall, f1, coverage, duplicateRate, evidence, matched, missed, extras);
    }

    private static String canonical(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
    }
}
