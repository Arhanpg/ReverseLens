package io.reverselens.api;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class Phase1CatalogTest {
  @Test void apkProfileUsesFourIndependentEngines(){
    EngineCatalog catalog=new EngineCatalog();
    assertThat(catalog.defaults("apk")).containsExactlyInAnyOrder("jadx","apktool","androguard","apkid");
  }
  @Test void bundleProfilesStayWithBundletool(){
    EngineCatalog catalog=new EngineCatalog();
    assertThat(catalog.defaults("aab")).containsExactly("bundletool");
    assertThat(catalog.supports("jadx","aab")).isFalse();
  }
}
