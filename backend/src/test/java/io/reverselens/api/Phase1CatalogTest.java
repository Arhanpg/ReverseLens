package io.reverselens.api;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class Phase1CatalogTest {
  @Test void apkProfileUsesFourIndependentEngines(){
    EngineCatalog catalog=new EngineCatalog();
    assertThat(catalog.defaults("apk")).containsExactlyInAnyOrder("jadx","apktool","androguard","apkid");
  }
  @Test void specialistCatalogExposesRuntimeAndProvisioningMetadata(){
    EngineCatalog catalog=new EngineCatalog();
    assertThat(catalog.exists("blutter")).isTrue();
    assertThat(catalog.exists("hermes-dec")).isTrue();
    assertThat(catalog.exists("ghidra")).isTrue();
    assertThat(catalog.all().stream().filter(e -> e.integrationStatus().equals("optional")).count()).isGreaterThanOrEqualTo(4);
    assertThat(catalog.supports("hermes-dec","apk")).isTrue();
    assertThat(catalog.supports("hermes-dec","aab")).isFalse();
  }
  @Test void bundleProfilesStayWithBundletool(){
    EngineCatalog catalog=new EngineCatalog();
    assertThat(catalog.defaults("aab")).containsExactly("bundletool");
    assertThat(catalog.supports("jadx","aab")).isFalse();
  }
}
