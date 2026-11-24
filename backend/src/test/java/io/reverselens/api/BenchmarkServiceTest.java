package io.reverselens.api;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;

class BenchmarkServiceTest {
  @Test void enginesAdvertiseDistinctCapabilityClasses() {
    assertThat(BenchmarkService.capabilitiesFor("jadx")).contains("dex_to_source");
    assertThat(BenchmarkService.capabilitiesFor("apktool")).contains("manifest");
    assertThat(BenchmarkService.capabilitiesFor("apkid")).contains("packer_detection");
    assertThat(BenchmarkService.capabilitiesFor("jadx")).doesNotContain("packer_detection");
  }

  @Test void onlyScoresObservationsInCapabilityClassesWithVerifiedLabels() {
    List<Map<String,Object>> gt=List.of(Map.of("capabilityClass","manifest","canonicalKey","permission:android.permission.internet"));
    List<Map<String,Object>> observed=List.of(
      Map.of("capabilityClass","manifest","canonicalKey","permission:android.permission.internet"),
      Map.of("capabilityClass","dex_analysis","canonicalKey","dex_entry:classes.dex"));
    List<Map<String,Object>> comparable=BenchmarkService.filterComparableObservations(gt,observed);
    assertThat(comparable).hasSize(1);
    assertThat(comparable.get(0).get("capabilityClass")).isEqualTo("manifest");
  }

  @Test void scoringDoesNotTreatMissingGroundTruthAsZero() {
    BenchmarkScore score=BenchmarkScorer.score(List.of(),List.of(
      Map.of("canonicalKey","permission:android.permission.internet","evidencePath","raw/out","evidenceSha256","a".repeat(64))));
    assertThat(score.accuracyAvailable()).isFalse();
    assertThat(score.precision()).isNull();
    assertThat(score.recall()).isNull();
    assertThat(score.f1()).isNull();
  }

  @Test void scoringCountsDuplicatesAndKeepsMatchedMissedAndExtraItems() {
    List<Map<String,Object>> observations=List.of(
      Map.of("canonicalKey","permission:android.permission.internet","evidencePath","raw/one","evidenceSha256","a".repeat(64)),
      Map.of("canonicalKey","permission:android.permission.internet","evidencePath","raw/two","evidenceSha256","b".repeat(64)),
      Map.of("canonicalKey","permission:android.permission.camera","evidencePath","raw/three","evidenceSha256","c".repeat(64)));
    BenchmarkScore score=BenchmarkScorer.score(List.of("permission:android.permission.internet","permission:android.permission.contacts"),observations);
    assertThat(score.truePositive()).isEqualTo(1);
    assertThat(score.falsePositive()).isEqualTo(1);
    assertThat(score.falseNegative()).isEqualTo(1);
    assertThat(score.precision()).isEqualTo(0.5);
    assertThat(score.recall()).isEqualTo(0.5);
    assertThat(score.f1()).isEqualTo(0.5);
    assertThat(score.duplicateRate()).isEqualTo(1.0/3.0);
    assertThat(score.missedItems()).containsExactly("permission:android.permission.contacts");
  }
}
