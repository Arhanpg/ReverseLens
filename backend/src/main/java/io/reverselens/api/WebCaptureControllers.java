package io.reverselens.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.net.IDN;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

record WebTargetRequest(
    String displayName, String url, String authorizationBasis, String authorizationReference,
    Boolean authorizationConfirmed, Instant authorizationExpiresAt, List<String> allowedHosts,
    List<String> allowedPathPrefixes, List<Integer> allowedPorts, Integer maxRequests,
    Integer maxPages, Integer maxSavedJavaScriptBytes, Integer maxDurationSeconds, Boolean localLab
) {}

record WebTargetResponse(
    UUID id, String displayName, String url, String authorizationBasis, String authorizationReference,
    Instant authorizationExpiresAt, List<String> allowedHosts, List<String> allowedPathPrefixes,
    List<Integer> allowedPorts, int maxRequests, int maxPages, int maxSavedJavaScriptBytes,
    int maxDurationSeconds, boolean localLab, String status, Instant createdAt
) {}

record WebCaptureResponse(
    UUID id, UUID webTargetId, String status, String workspacePath, Map<String, Object> manifest,
    String errorSummary, Instant createdAt, Instant startedAt, Instant finishedAt
) {}

record WebCaptureWorkerUpdate(String status, Map<String, Object> manifest, String errorSummary) {}

record NormalizedWebTarget(
    String displayName, String url, String authorizationBasis, String authorizationReference,
    Instant authorizationExpiresAt, List<String> allowedHosts, List<String> allowedPathPrefixes,
    List<Integer> allowedPorts, int maxRequests, int maxPages, int maxSavedJavaScriptBytes,
    int maxDurationSeconds, boolean localLab
) {}

final class WebTargetValidation {
    private static final Set<String> AUTHORIZATION_BASES = Set.of(
        "owner_or_developer", "written_permission", "local_training_lab", "lawful_possession_or_access"
    );
    private WebTargetValidation() {}

    static NormalizedWebTarget normalize(WebTargetRequest request, Instant now) {
        if (request == null) throw new IllegalArgumentException("Web target request is required.");
        if (!Boolean.TRUE.equals(request.authorizationConfirmed())) {
            throw new IllegalArgumentException("Confirm that you own the target or have explicit authorization to assess it.");
        }
        String basis = requireText(request.authorizationBasis(), "Authorization basis", 64);
        if (!AUTHORIZATION_BASES.contains(basis)) throw new IllegalArgumentException("A supported authorization basis is required.");
        String reference = requireText(request.authorizationReference(), "Authorization reference", 2000);
        Instant expires = request.authorizationExpiresAt();
        if (expires == null || !expires.isAfter(now)) throw new IllegalArgumentException("Authorization expiry must be in the future.");
        if (expires.isAfter(now.plus(Duration.ofDays(30)))) throw new IllegalArgumentException("Authorization expiry cannot be more than 30 days ahead.");

        URI uri;
        try {
            uri = URI.create(requireText(request.url(), "URL", 2048).trim());
        } catch (IllegalArgumentException exc) {
            throw new IllegalArgumentException("Target URL is invalid.");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!Set.of("http", "https").contains(scheme) || !uri.isAbsolute() || uri.getHost() == null) {
            throw new IllegalArgumentException("Only absolute HTTP/HTTPS URLs with a valid host are accepted.");
        }
        if (uri.getRawUserInfo() != null) throw new IllegalArgumentException("URLs containing credentials are not permitted.");
        if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("Target URLs must not contain query strings or fragments; define permitted paths in scope instead.");
        }
        String host = normalizeHost(uri.getHost());
        int targetPort = uri.getPort() == -1 ? (scheme.equals("https") ? 443 : 80) : uri.getPort();
        if (targetPort < 1 || targetPort > 65535) throw new IllegalArgumentException("URL contains an invalid TCP port.");

        List<String> hosts = request.allowedHosts() == null || request.allowedHosts().isEmpty()
            ? List.of(host) : request.allowedHosts().stream().map(WebTargetValidation::normalizeHost).distinct().toList();
        if (hosts.size() > 20 || !hosts.contains(host)) {
            throw new IllegalArgumentException("The start URL host must be present in an exact-host allowlist of at most 20 hosts.");
        }

        List<Integer> ports = request.allowedPorts() == null || request.allowedPorts().isEmpty()
            ? List.of(targetPort) : new ArrayList<>(request.allowedPorts());
        if (ports.size() > 10 || ports.stream().anyMatch(port -> port == null || port < 1 || port > 65535)) {
            throw new IllegalArgumentException("Allowed ports must be valid TCP ports.");
        }
        ports = ports.stream().distinct().sorted().toList();
        if (!ports.contains(targetPort)) throw new IllegalArgumentException("The allowed port list must include the start URL port.");

        List<String> prefixes = request.allowedPathPrefixes() == null || request.allowedPathPrefixes().isEmpty()
            ? List.of("/") : request.allowedPathPrefixes().stream().map(WebTargetValidation::normalizePrefix).distinct().toList();
        if (prefixes.size() > 25) throw new IllegalArgumentException("At most 25 path prefixes can be authorized.");
        String targetPath = decodeSafePath(uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath());
        boolean pathAllowed = prefixes.stream().anyMatch(prefix -> {
            String root = prefix.equals("/") ? "/" : prefix.replaceAll("/+$", "");
            return root.equals("/") || targetPath.equals(root) || targetPath.startsWith(root + "/");
        });
        if (!pathAllowed) throw new IllegalArgumentException("The start URL path is outside the authorized path prefixes.");

        int maxRequests = bounded(request.maxRequests(), 80, 1, 200, "maxRequests");
        int maxPages = bounded(request.maxPages(), 10, 1, 50, "maxPages");
        int maxBytes = bounded(request.maxSavedJavaScriptBytes(), 2_000_000, 1024, 10_485_760, "maxSavedJavaScriptBytes");
        int maxDuration = bounded(request.maxDurationSeconds(), 120, 1, 300, "maxDurationSeconds");
        boolean localLab = Boolean.TRUE.equals(request.localLab());
        if (localLab && !"local_training_lab".equals(basis)) {
            throw new IllegalArgumentException("Private/local address mode is only available for a declared local training lab.");
        }
        String displayName = request.displayName() == null || request.displayName().isBlank()
            ? host : requireText(request.displayName(), "Display name", 200);
        return new NormalizedWebTarget(displayName, uri.toASCIIString(), basis, reference, expires,
            hosts, prefixes, ports, maxRequests, maxPages, maxBytes, maxDuration, localLab);
    }

    private static int bounded(Integer value, int fallback, int min, int max, String field) {
        int n = value == null ? fallback : value;
        if (n < min || n > max) throw new IllegalArgumentException(field + " must be between " + min + " and " + max + ".");
        return n;
    }

    private static String requireText(String value, String label, int max) {
        if (value == null || value.isBlank() || value.length() > max) {
            throw new IllegalArgumentException(label + " is required and must not exceed " + max + " characters.");
        }
        return value.trim();
    }

    private static String normalizeHost(String value) {
        String host = requireText(value, "Allowed host", 253).toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        if (host.contains("*") || host.contains("/") || host.contains(":") || host.contains("@")) {
            throw new IllegalArgumentException("Only exact DNS names or IPv4 addresses may be allowlisted; wildcard and port syntax are rejected.");
        }
        try {
            return IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES);
        } catch (IllegalArgumentException exc) {
            throw new IllegalArgumentException("Allowlist contains an invalid DNS name.");
        }
    }

    private static String normalizePrefix(String value) {
        String prefix = requireText(value, "Allowed path prefix", 512);
        if (!prefix.startsWith("/")) prefix = "/" + prefix;
        decodeSafePath(prefix);
        return prefix;
    }

    private static String decodeSafePath(String raw) {
        String value = raw;
        try {
            for (int i = 0; i < 5; i++) {
                String decoded = URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
                if (decoded.equals(value)) break;
                value = decoded;
            }
        } catch (IllegalArgumentException exc) {
            throw new IllegalArgumentException("Path contains invalid percent encoding.");
        }
        if (value.indexOf('\\') >= 0 || value.indexOf('\0') >= 0
            || Arrays.stream(value.split("/", -1)).anyMatch(part -> part.equals(".") || part.equals(".."))) {
            throw new IllegalArgumentException("Dot-segment or invalid-separator paths are not permitted.");
        }
        return value;
    }
}

@Service
class WebTargetService {
    private final JdbcTemplate jdbc;
    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;
    private final String queue;

    WebTargetService(JdbcTemplate jdbc, StringRedisTemplate redis, ObjectMapper mapper,
                     @Value("$" + "{reverselens.web-capture-queue:reverselens:web:capture}") String queue) {
        this.jdbc = jdbc;
        this.redis = redis;
        this.mapper = mapper;
        this.queue = queue;
    }

    @Transactional
    WebTargetResponse register(WebTargetRequest request) throws JsonProcessingException {
        NormalizedWebTarget value = WebTargetValidation.normalize(request, Instant.now());
        UUID id = UUID.randomUUID();
        Instant now = Instant.now();
        jdbc.update("""
            INSERT INTO web_targets(
              id,display_name,start_url,authorization_basis,authorization_reference,
              authorization_confirmed,authorization_expires_at,allowed_hosts,allowed_path_prefixes,
              allowed_ports,max_requests,max_pages,max_saved_javascript_bytes,max_duration_seconds,
              local_lab,status,created_at
            ) VALUES(?,?,?,?,?,?,?,CAST(? AS jsonb),CAST(? AS jsonb),CAST(? AS jsonb),?,?,?,?,?,'active',?)
            """,
            id, value.displayName(), value.url(), value.authorizationBasis(), value.authorizationReference(),
            true, Timestamp.from(value.authorizationExpiresAt()), mapper.writeValueAsString(value.allowedHosts()),
            mapper.writeValueAsString(value.allowedPathPrefixes()), mapper.writeValueAsString(value.allowedPorts()),
            value.maxRequests(), value.maxPages(), value.maxSavedJavaScriptBytes(), value.maxDurationSeconds(),
            value.localLab(), Timestamp.from(now));
        return new WebTargetResponse(id, value.displayName(), value.url(), value.authorizationBasis(),
            value.authorizationReference(), value.authorizationExpiresAt(), value.allowedHosts(),
            value.allowedPathPrefixes(), value.allowedPorts(), value.maxRequests(), value.maxPages(),
            value.maxSavedJavaScriptBytes(), value.maxDurationSeconds(), value.localLab(), "active", now);
    }

    WebTargetResponse getTarget(UUID id) {
        List<WebTargetResponse> rows = jdbc.query("SELECT * FROM web_targets WHERE id=?", targetMapper, id);
        return rows.stream().findFirst().orElse(null);
    }

    List<WebTargetResponse> listTargets() {
        return jdbc.query("SELECT * FROM web_targets ORDER BY created_at DESC LIMIT 100", targetMapper);
    }

    @Transactional
    WebCaptureResponse createCapture(UUID targetId) throws JsonProcessingException {
        WebTargetResponse target = getTarget(targetId);
        if (target == null) throw new IllegalArgumentException("Web target not found.");
        Instant now = Instant.now();
        if (!"active".equals(target.status()) || !target.authorizationExpiresAt().isAfter(now)) {
            throw new IllegalArgumentException("This target's authorization is disabled or expired.");
        }
        long remainingSeconds = Duration.between(now, target.authorizationExpiresAt()).getSeconds();
        if (remainingSeconds < 1) throw new IllegalArgumentException("Authorization expires too soon to begin a capture.");

        UUID runId = UUID.randomUUID();
        String workspacePath = "web/" + target.id() + "/run-" + runId;
        jdbc.update("""
            INSERT INTO web_capture_runs(id,web_target_id,status,workspace_path,created_at)
            VALUES(?,?,'queued',?,?)
            """, runId, target.id(), workspacePath, Timestamp.from(now));

        int maxDuration = (int) Math.min(target.maxDurationSeconds(), remainingSeconds);
        Map<String, Object> scope = new LinkedHashMap<>();
        scope.put("allowed_hosts", target.allowedHosts());
        scope.put("allowed_path_prefixes", target.allowedPathPrefixes());
        scope.put("allowed_ports", target.allowedPorts());
        scope.put("max_requests", target.maxRequests());
        scope.put("max_pages", target.maxPages());
        scope.put("max_response_bytes", target.maxSavedJavaScriptBytes());
        scope.put("max_duration_seconds", maxDuration);
        scope.put("local_lab", target.localLab());

        Map<String, Object> job = new LinkedHashMap<>();
        job.put("url", target.url());
        job.put("targetId", target.id().toString());
        job.put("runId", runId.toString());
        job.put("authorizationExpiresAt", target.authorizationExpiresAt().toString());
        job.put("scope", scope);
        String encoded = mapper.writeValueAsString(job);
        Runnable enqueue = () -> redis.opsForList().leftPush(queue, encoded);
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override public void afterCommit() { enqueue.run(); }
            });
        } else {
            enqueue.run();
        }
        return new WebCaptureResponse(runId, target.id(), "queued", workspacePath, Map.of(), null, now, null, null);
    }

    List<WebCaptureResponse> listCaptures(UUID targetId) {
        if (getTarget(targetId) == null) throw new IllegalArgumentException("Web target not found.");
        return jdbc.query("SELECT * FROM web_capture_runs WHERE web_target_id=? ORDER BY created_at DESC LIMIT 50",
            captureMapper, targetId);
    }

    WebCaptureResponse getCapture(UUID id) {
        List<WebCaptureResponse> rows = jdbc.query("SELECT * FROM web_capture_runs WHERE id=?", captureMapper, id);
        return rows.stream().findFirst().orElse(null);
    }

    void updateCapture(UUID id, WebCaptureWorkerUpdate update) throws JsonProcessingException {
        if (update == null || !Set.of("running", "succeeded", "partial", "failed").contains(update.status())) {
            throw new IllegalArgumentException("Invalid web capture worker status.");
        }
        String current;
        try {
            current = jdbc.queryForObject("SELECT status FROM web_capture_runs WHERE id=?", String.class, id);
        } catch (EmptyResultDataAccessException exc) {
            throw new IllegalArgumentException("Web capture run not found.");
        }
        boolean starting = "running".equals(update.status()) && "queued".equals(current);
        boolean terminal = Set.of("succeeded", "partial", "failed").contains(update.status())
            && Set.of("queued", "running").contains(current);
        if (!starting && !terminal) throw new IllegalArgumentException("Web capture run is already terminal or has an invalid transition.");
        String manifest = mapper.writeValueAsString(update.manifest() == null ? Map.of() : update.manifest());
        jdbc.update("""
            UPDATE web_capture_runs
            SET status=?, manifest_json=CAST(? AS jsonb), error_summary=?,
                started_at=CASE WHEN ?='running' THEN COALESCE(started_at,NOW()) ELSE started_at END,
                finished_at=CASE WHEN ? IN ('succeeded','partial','failed') THEN NOW() ELSE finished_at END
            WHERE id=?
            """, update.status(), manifest, truncate(update.errorSummary()), update.status(), update.status(), id);
    }

    private final RowMapper<WebTargetResponse> targetMapper = (rs, row) -> new WebTargetResponse(
        rs.getObject("id", UUID.class), rs.getString("display_name"), rs.getString("start_url"),
        rs.getString("authorization_basis"), rs.getString("authorization_reference"),
        rs.getTimestamp("authorization_expires_at").toInstant(),
        readList(rs.getString("allowed_hosts"), String.class),
        readList(rs.getString("allowed_path_prefixes"), String.class),
        readList(rs.getString("allowed_ports"), Integer.class),
        rs.getInt("max_requests"), rs.getInt("max_pages"), rs.getInt("max_saved_javascript_bytes"),
        rs.getInt("max_duration_seconds"), rs.getBoolean("local_lab"), rs.getString("status"),
        rs.getTimestamp("created_at").toInstant()
    );

    private final RowMapper<WebCaptureResponse> captureMapper = (rs, row) -> new WebCaptureResponse(
        rs.getObject("id", UUID.class), rs.getObject("web_target_id", UUID.class), rs.getString("status"),
        rs.getString("workspace_path"), readMap(rs.getString("manifest_json")), rs.getString("error_summary"),
        rs.getTimestamp("created_at").toInstant(),
        rs.getTimestamp("started_at") == null ? null : rs.getTimestamp("started_at").toInstant(),
        rs.getTimestamp("finished_at") == null ? null : rs.getTimestamp("finished_at").toInstant()
    );

    private <T> List<T> readList(String json, Class<T> valueType) throws SQLException {
        try {
            return mapper.readValue(json, mapper.getTypeFactory().constructCollectionType(List.class, valueType));
        } catch (JsonProcessingException exc) {
            throw new SQLException("Stored web target scope is invalid.", exc);
        }
    }

    private Map<String, Object> readMap(String json) throws SQLException {
        try {
            return mapper.readValue(json, new TypeReference<>() {});
        } catch (JsonProcessingException exc) {
            throw new SQLException("Stored capture manifest is invalid.", exc);
        }
    }

    private static String truncate(String value) {
        return value == null ? null : value.substring(0, Math.min(4000, value.length()));
    }
}

@RestController
@RequestMapping("/api/v1/web-targets")
class WebTargetController {
    private final WebTargetService service;
    WebTargetController(WebTargetService service) { this.service = service; }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    WebTargetResponse register(@RequestBody WebTargetRequest request) throws JsonProcessingException {
        return service.register(request);
    }

    @GetMapping
    List<WebTargetResponse> list() { return service.listTargets(); }

    @GetMapping("/{id}")
    WebTargetResponse get(@PathVariable UUID id) {
        WebTargetResponse target = service.getTarget(id);
        if (target == null) throw new IllegalArgumentException("Web target not found.");
        return target;
    }

    @PostMapping("/{id}/captures")
    @ResponseStatus(HttpStatus.CREATED)
    WebCaptureResponse createCapture(@PathVariable UUID id) throws JsonProcessingException {
        return service.createCapture(id);
    }

    @GetMapping("/{id}/captures")
    List<WebCaptureResponse> captures(@PathVariable UUID id) { return service.listCaptures(id); }
}

@RestController
@RequestMapping("/api/v1/web-captures")
class WebCaptureController {
    private final WebTargetService service;
    WebCaptureController(WebTargetService service) { this.service = service; }

    @GetMapping("/{id}")
    WebCaptureResponse get(@PathVariable UUID id) {
        WebCaptureResponse run = service.getCapture(id);
        if (run == null) throw new IllegalArgumentException("Web capture run not found.");
        return run;
    }
}

@RestController
@RequestMapping("/internal/v1/web-captures")
class WebCaptureWorkerController {
    private final WebTargetService service;
    private final String token;
    WebCaptureWorkerController(WebTargetService service,
                               @Value("$" + "{reverselens.worker-token}") String token) {
        this.service = service;
        this.token = token;
    }

    @PutMapping("/{id}")
    void update(@PathVariable UUID id,
                @RequestHeader("X-ReverseLens-Worker-Token") String supplied,
                @RequestBody WebCaptureWorkerUpdate update) throws JsonProcessingException {
        if (!java.security.MessageDigest.isEqual(
            token.getBytes(StandardCharsets.UTF_8), supplied.getBytes(StandardCharsets.UTF_8))) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Worker token rejected");
        }
        service.updateCapture(id, update);
    }
}
