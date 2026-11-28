package io.reverselens.api;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class WebTargetValidationTest {
    private WebTargetRequest request(String url, String basis, Instant expiry) {
        return new WebTargetRequest(
            "Example target", url, basis, "Authorization recorded in a local test plan",
            true, expiry, null, List.of("/"), null, null, null, null, null,
            "local_training_lab".equals(basis)
        );
    }

    @Test
    void normalizesAnExplicitlyAuthorizedHttpsTarget() {
        Instant now = Instant.now();
        NormalizedWebTarget target = WebTargetValidation.normalize(
            request("https://example.com/app", "owner_or_developer", now.plus(1, ChronoUnit.DAYS)), now
        );
        assertEquals(List.of("example.com"), target.allowedHosts());
        assertEquals(List.of("/"), target.allowedPathPrefixes());
        assertEquals(List.of(443), target.allowedPorts());
        assertEquals(80, target.maxRequests());
        assertFalse(target.localLab());
    }

    @Test
    void allowsNonstandardPortOnlyWhenExplicitlyScopedAsLocalLab() {
        Instant now = Instant.now();
        WebTargetRequest request = new WebTargetRequest(
            "Lab", "http://juice-shop:3000/lab", "local_training_lab",
            "Disposable local training environment", true, now.plus(2, ChronoUnit.HOURS),
            List.of("juice-shop"), List.of("/lab"), List.of(3000), 30, 3, 1_000_000, 60, true
        );
        NormalizedWebTarget target = WebTargetValidation.normalize(request, now);
        assertEquals(List.of(3000), target.allowedPorts());
        assertTrue(target.localLab());
    }

    @Test
    void rejectsNonHttpSchemesAndCredentialBearingUrls() {
        Instant expiry = Instant.now().plus(1, ChronoUnit.DAYS);
        assertThrows(IllegalArgumentException.class, () -> WebTargetValidation.normalize(
            request("file:///etc/passwd", "owner_or_developer", expiry), Instant.now()));
        assertThrows(IllegalArgumentException.class, () -> WebTargetValidation.normalize(
            request("https://user:pass@example.com/", "owner_or_developer", expiry), Instant.now()));
    }

    @Test
    void rejectsQueryParametersAndOutOfScopePaths() {
        Instant expiry = Instant.now().plus(1, ChronoUnit.DAYS);
        assertThrows(IllegalArgumentException.class, () -> WebTargetValidation.normalize(
            request("https://example.com/?token=secret", "owner_or_developer", expiry), Instant.now()));
        WebTargetRequest limited = new WebTargetRequest(
            "Limited", "https://example.com/admin", "owner_or_developer",
            "Written scope permits only /app", true, expiry,
            List.of("example.com"), List.of("/app"), List.of(443), 20, 2, 500_000, 30, false
        );
        assertThrows(IllegalArgumentException.class, () -> WebTargetValidation.normalize(limited, Instant.now()));
    }

    @Test
    void rejectsEncodedTraversalWildcardHostsAndUnapprovedPorts() {
        Instant expiry = Instant.now().plus(1, ChronoUnit.DAYS);
        WebTargetRequest traversal = new WebTargetRequest(
            "Traversal", "https://example.com/app/%252e%252e/admin", "owner_or_developer",
            "scope note", true, expiry, List.of("example.com"), List.of("/app"), List.of(443), 20, 2, 500_000, 30, false
        );
        assertThrows(IllegalArgumentException.class, () -> WebTargetValidation.normalize(traversal, Instant.now()));
        WebTargetRequest wildcard = new WebTargetRequest(
            "Wildcard", "https://example.com/", "owner_or_developer",
            "scope note", true, expiry, List.of("*.example.com"), List.of("/"), List.of(443), 20, 2, 500_000, 30, false
        );
        assertThrows(IllegalArgumentException.class, () -> WebTargetValidation.normalize(wildcard, Instant.now()));
        WebTargetRequest badPort = new WebTargetRequest(
            "Bad port", "https://example.com:8443/", "owner_or_developer",
            "scope note", true, expiry, List.of("example.com"), List.of("/"), List.of(443), 20, 2, 500_000, 30, false
        );
        assertThrows(IllegalArgumentException.class, () -> WebTargetValidation.normalize(badPort, Instant.now()));
    }

    @Test
    void rejectsMissingConfirmationAndExpiredAuthorization() {
        Instant now = Instant.now();
        WebTargetRequest unconfirmed = new WebTargetRequest(
            "Target", "https://example.com/", "owner_or_developer",
            "scope note", false, now.plus(1, ChronoUnit.DAYS), null, null, null,
            null, null, null, null, false
        );
        assertThrows(IllegalArgumentException.class, () -> WebTargetValidation.normalize(unconfirmed, now));
        assertThrows(IllegalArgumentException.class, () -> WebTargetValidation.normalize(
            request("https://example.com/", "owner_or_developer", now.minus(1, ChronoUnit.MINUTES)), now));
    }

    @Test
    void restrictsPrivateLabModeToLocalTrainingBasis() {
        Instant expiry = Instant.now().plus(1, ChronoUnit.DAYS);
        WebTargetRequest invalid = new WebTargetRequest(
            "Target", "https://example.com/", "owner_or_developer",
            "scope note", true, expiry, null, null, null, null, null, null, null, true
        );
        assertThrows(IllegalArgumentException.class, () -> WebTargetValidation.normalize(invalid, Instant.now()));
    }
}
