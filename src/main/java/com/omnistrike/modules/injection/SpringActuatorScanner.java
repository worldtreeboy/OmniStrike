package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.*;
import com.omnistrike.model.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * MODULE: Spring Boot Actuator Exposure Scanner
 *
 * This module CANNOT be manually triggered by the user. It is an active module
 * that passively gates on Spring Boot indicators in responses. Only when
 * Spring Boot is confirmed does it probe actuator endpoints.
 *
 * Flow:
 *   1. Receives request/response via processHttpFlow() during active scanning
 *   2. Checks the RESPONSE body, URL, and headers for Spring Boot indicators
 *   3. If NO Spring indicators -> returns empty (zero payloads sent)
 *   4. If Spring detected -> reports INFO finding, then probes actuator endpoints
 *   5. 4 phases: Actuator Discovery, Sensitive Endpoint Probing, Info Disclosure, Heap/Thread Dump
 *
 * All methods are READ-ONLY (GET requests to actuator endpoints — no POST/shutdown).
 *
 * Stop-scan: Respects ScanState.isCancelled() and Thread.isInterrupted().
 */
public class SpringActuatorScanner implements ScanModule {

    private static final String MODULE_ID = "spring-actuator-scanner";

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    // ── Spring Boot detection patterns (passive gate) ─────────────────────

    // Error messages/patterns that confirm Spring Boot — only Spring-exclusive
    // Excluded: generic Java stack traces, generic 404 pages
    private static final Pattern SPRING_ERROR_PATTERN = Pattern.compile(
            "Whitelabel Error Page|"
                    + "org\\.springframework\\.|"
                    + "spring\\.boot\\.|"
                    + "org\\.apache\\.catalina\\..*spring|"
                    + "DispatcherServlet|"
                    + "RequestMappingHandlerMapping|"
                    + "\"timestamp\".*\"status\".*\"error\".*\"path\"",  // Spring Boot default JSON error (4 fields together)
            Pattern.CASE_INSENSITIVE);

    // URL patterns for actuator endpoints (Spring-specific)
    private static final Pattern SPRING_URL_PATTERN = Pattern.compile(
            "/actuator(?:/|$)|"
                    + "/actuator/health|"
                    + "/actuator/info|"
                    + "/actuator/env|"
                    + "/manage/health|"
                    + "/manage/info",
            Pattern.CASE_INSENSITIVE);

    // Response headers that confirm Spring Boot
    private static final Set<String> SPRING_HEADERS = Set.of(
            "x-application-context");

    // ── Actuator endpoints to probe ───────────────────────────────────────

    // Phase 1: Discovery — probe the actuator root to find available endpoints
    private static final String[] ACTUATOR_ROOTS = {
            "/actuator", "/manage", "/actuator/"
    };

    // Phase 2: Sensitive endpoints — ordered by severity
    private static final String[][] SENSITIVE_ENDPOINTS = {
            // {path, description, severity}
            {"/actuator/env", "Environment properties (may contain secrets, DB passwords, API keys)", "HIGH"},
            {"/actuator/configprops", "Configuration properties (may contain credentials)", "HIGH"},
            {"/actuator/heapdump", "JVM heap dump (contains in-memory secrets, sessions)", "CRITICAL"},
            {"/actuator/threaddump", "Thread dump (reveals internal state, stack traces)", "MEDIUM"},
            {"/actuator/mappings", "Request mappings (reveals all API endpoints)", "MEDIUM"},
            {"/actuator/beans", "Spring beans (reveals internal architecture)", "LOW"},
            {"/actuator/conditions", "Auto-configuration conditions", "LOW"},
            {"/actuator/metrics", "Application metrics", "LOW"},
            {"/actuator/loggers", "Logger configuration (may allow log level change via POST)", "MEDIUM"},
            {"/actuator/scheduledtasks", "Scheduled tasks (reveals background jobs)", "LOW"},
            {"/actuator/httptrace", "HTTP trace (recent requests, may contain auth headers)", "HIGH"},
            {"/actuator/caches", "Cache information", "LOW"},
            {"/actuator/flyway", "Flyway DB migration info (reveals DB schema changes)", "MEDIUM"},
            {"/actuator/liquibase", "Liquibase DB migration info", "MEDIUM"},
            {"/actuator/sessions", "Active sessions (if Spring Session enabled)", "HIGH"},
            {"/actuator/jolokia/list", "Jolokia JMX access — may enable RCE via MBeans", "CRITICAL"},
            {"/actuator/gateway/routes", "Spring Cloud Gateway routes — may reveal backends (CVE-2022-22947)", "HIGH"},
            {"/actuator/prometheus", "Prometheus metrics endpoint (leaks internal metric names)", "MEDIUM"},
    };

    // Also try legacy Spring Boot 1.x paths (without /actuator prefix)
    private static final String[][] LEGACY_ENDPOINTS = {
            {"/env", "Environment properties (Spring Boot 1.x)", "HIGH"},
            {"/configprops", "Configuration properties (Spring Boot 1.x)", "HIGH"},
            {"/heapdump", "JVM heap dump (Spring Boot 1.x)", "CRITICAL"},
            {"/dump", "Thread dump (Spring Boot 1.x)", "MEDIUM"},
            {"/mappings", "Request mappings (Spring Boot 1.x)", "MEDIUM"},
            {"/trace", "HTTP trace (Spring Boot 1.x)", "HIGH"},
            {"/beans", "Spring beans (Spring Boot 1.x)", "LOW"},
    };

    // ── ScanModule interface ──────────────────────────────────────────────

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "Spring Boot Actuator Exposure"; }
    @Override public String getDescription() {
        return "Detects Spring Boot applications and probes for exposed actuator endpoints. "
                + "Tests for env/configprops (secrets), heapdump, mappings, httptrace, and more. "
                + "Only activates when Spring Boot indicators are detected in responses.";
    }
    @Override public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }
    @Override public boolean isPassive() { return false; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                 CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
    }

    @Override public void destroy() {}

    // ── Main entry point ──────────────────────────────────────────────────

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        if (requestResponse.response() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String urlPath = extractPath(url);

        // PASSIVE GATE: Check response for Spring Boot indicators
        SpringDetection detection = detectSpringBoot(requestResponse);
        if (detection == null) return Collections.emptyList();

        // Spring Boot confirmed — report INFO finding
        if (dedup.markIfNew(MODULE_ID, urlPath, "spring-detected")) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Spring Boot Application Detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(detection.evidence)
                    .description("The target application is running Spring Boot. "
                            + "Actuator endpoint probing will be performed automatically.")
                    .requestResponse(requestResponse)
                    .build());
            api.logging().logToOutput("[Spring] Spring Boot detected: " + url + " | " + detection.evidence);
        }

        // ACTIVE PROBING: Test actuator endpoints
        try {
            testActuatorExposure(requestResponse, url);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return Collections.emptyList();
    }

    // ── Spring Boot Detection (passive gate) ──────────────────────────────

    private SpringDetection detectSpringBoot(HttpRequestResponse reqResp) {
        String body = reqResp.response().bodyToString();
        if (body == null) body = "";
        String url = reqResp.request().url();

        // Check 1: Error messages in response body (strongest signal — standalone)
        if (SPRING_ERROR_PATTERN.matcher(body).find()) {
            return new SpringDetection("Spring Boot error pattern in response body");
        }

        // Check 2: URL pattern + Spring-specific body/header markers (require both)
        if (SPRING_URL_PATTERN.matcher(url).find()) {
            // Require a Spring-specific secondary signal
            // Signal A: x-application-context header
            for (var h : reqResp.response().headers()) {
                if (SPRING_HEADERS.contains(h.name().toLowerCase())) {
                    return new SpringDetection(
                            "Spring URL pattern (" + url + ") + header: " + h.name());
                }
            }
            // Signal B: Spring actuator JSON format ({"_links":{...}} or {"status":"UP"})
            if (body.contains("\"_links\"") && body.contains("\"self\"")
                    && body.contains("\"href\"")) {
                return new SpringDetection(
                        "Spring URL pattern (" + url + ") + actuator HAL JSON body");
            }
            if (body.contains("\"status\"") && body.contains("\"UP\"")) {
                // Could be any health check — require the URL to be /health
                if (url.toLowerCase().contains("/health")) {
                    return new SpringDetection(
                            "Spring URL pattern (" + url + ") + health check response");
                }
            }
        }

        return null;
    }

    // ── Active Actuator Probing ──────────────────────────────────────────

    private void testActuatorExposure(HttpRequestResponse original, String url)
            throws InterruptedException {
        String baseUrl = extractBaseUrl(url);

        // Only probe once per HOST (not per path — actuator endpoints are host-level)
        if (!dedup.markIfNew(MODULE_ID, baseUrl, "actuator-probe")) return;

        // Phase 1: Discovery — find the actuator root
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        String actuatorRoot = discoverActuatorRoot(original, baseUrl);

        // Phase 2: Probe sensitive endpoints
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        if (actuatorRoot != null) {
            probeSensitiveEndpoints(original, baseUrl, actuatorRoot, url);
        }

        // Phase 3: Try legacy Spring Boot 1.x paths if no actuator root found
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        probeLegacyEndpoints(original, baseUrl, url);
    }

    // ── Phase 1: Actuator Root Discovery ─────────────────────────────────

    private String discoverActuatorRoot(HttpRequestResponse original, String baseUrl)
            throws InterruptedException {
        for (String root : ACTUATOR_ROOTS) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return null;

            HttpRequestResponse result = sendProbeRequest(original, baseUrl + root);
            if (result == null || result.response() == null) { perHostDelay(); continue; }
            if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body == null) body = "";

            // Actuator root returns HAL JSON with _links
            if (result.response().statusCode() == 200
                    && body.contains("\"_links\"")
                    && body.contains("\"href\"")
                    && body.length() > 50) {

                // Differential: compare against a nonexistent path to avoid catch-all pages
                HttpRequestResponse control = sendProbeRequest(original,
                        baseUrl + "/omnistrike_nonexistent_" + System.currentTimeMillis());
                perHostDelay();
                boolean differential = true;
                if (control != null && control.response() != null) {
                    String controlBody = control.response().bodyToString();
                    if (controlBody != null && controlBody.equals(body)) {
                        differential = false;
                    }
                }

                if (differential) {
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "Spring Boot Actuator Root Exposed — " + root,
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(baseUrl + root)
                            .evidence("Actuator root at '" + root + "' returned HAL JSON with endpoint links. "
                                    + "Differential probe confirmed unique response.")
                            .payload(baseUrl + root)
                            .requestResponse(result)
                            .build());
                    perHostDelay();
                    return root;
                }
            }
            perHostDelay();
        }
        return null;
    }

    // ── Phase 2: Sensitive Endpoint Probing ───────────────────────────────

    private void probeSensitiveEndpoints(HttpRequestResponse original, String baseUrl,
                                          String actuatorRoot, String url)
            throws InterruptedException {

        for (String[] endpoint : SENSITIVE_ENDPOINTS) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String path = endpoint[0];
            String description = endpoint[1];
            String severityStr = endpoint[2];

            String probeUrl = baseUrl + path;
            HttpRequestResponse result = sendProbeRequest(original, probeUrl);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            int status = result.response().statusCode();
            if (status >= 400 && status < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body == null) body = "";

            if (status == 200 && body.length() > 50) {
                // Validate the response is actually the actuator endpoint, not a catch-all
                boolean isValid = validateActuatorResponse(path, body);

                if (isValid) {
                    Severity sev = parseSeverity(severityStr);

                    // Special handling: heapdump returns binary data, not JSON
                    if (path.contains("heapdump")) {
                        // Heapdump is binary — require Content-Type validation (not just body size)
                        String contentType = "";
                        for (var h : result.response().headers()) {
                            if (h.name().equalsIgnoreCase("Content-Type")) {
                                contentType = h.value().toLowerCase();
                                break;
                            }
                        }
                        // Require binary Content-Type OR empty Content-Type with large body
                        if (contentType.contains("octet-stream") || contentType.contains("hprof")
                                || (contentType.isEmpty() && body.length() > 10000)) {
                            findingsStore.addFinding(Finding.builder(MODULE_ID,
                                            "Spring Boot Actuator — Heap Dump Accessible",
                                            Severity.CRITICAL, Confidence.CERTAIN)
                                    .url(probeUrl)
                                    .evidence("Heap dump endpoint returned binary data ("
                                            + body.length() + " bytes). Contains in-memory "
                                            + "secrets, session tokens, and credentials.")
                                    .payload(probeUrl)
                                    .requestResponse(result)
                                    .build());
                        }
                    } else {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Spring Boot Actuator — " + path.replace("/actuator/", ""),
                                        sev, Confidence.FIRM)
                                .url(probeUrl)
                                .evidence(description + ". Response length: " + body.length() + " bytes.")
                                .payload(probeUrl)
                                .requestResponse(result)
                                .build());
                    }
                }
            }
            perHostDelay();
        }
    }

    // ── Phase 3: Legacy Spring Boot 1.x Endpoints ────────────────────────

    private void probeLegacyEndpoints(HttpRequestResponse original, String baseUrl,
                                       String url) throws InterruptedException {
        for (String[] endpoint : LEGACY_ENDPOINTS) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String path = endpoint[0];
            String description = endpoint[1];
            String severityStr = endpoint[2];

            String probeUrl = baseUrl + path;
            HttpRequestResponse result = sendProbeRequest(original, probeUrl);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            int status = result.response().statusCode();
            if (status >= 400 && status < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body == null) body = "";

            if (status == 200 && body.length() > 50) {
                boolean isValid = validateLegacyResponse(path, body);

                if (isValid) {
                    Severity sev = parseSeverity(severityStr);

                    // Differential: compare against a nonexistent path
                    HttpRequestResponse control = sendProbeRequest(original,
                            baseUrl + "/omnistrike_legacy_nonexistent_" + System.currentTimeMillis());
                    perHostDelay();
                    boolean differential = true;
                    if (control != null && control.response() != null) {
                        String controlBody = control.response().bodyToString();
                        if (controlBody != null && controlBody.equals(body)) {
                            differential = false;
                        }
                    }

                    if (differential) {
                        // Only /heapdump gets CRITICAL binary-data handling (not /dump which is thread dump = MEDIUM)
                        if (path.contains("heapdump")) {
                            String contentType = "";
                            for (var h : result.response().headers()) {
                                if (h.name().equalsIgnoreCase("Content-Type")) {
                                    contentType = h.value().toLowerCase();
                                    break;
                                }
                            }
                            if (contentType.contains("octet-stream") || contentType.contains("hprof")
                                    || (contentType.isEmpty() && body.length() > 10000)) {
                                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                                "Spring Boot Actuator — Heap Dump Accessible (Legacy 1.x)",
                                                Severity.CRITICAL, Confidence.CERTAIN)
                                        .url(probeUrl)
                                        .evidence("Legacy heap dump endpoint returned binary data ("
                                                + body.length() + " bytes).")
                                        .payload(probeUrl)
                                        .requestResponse(result)
                                        .build());
                            }
                        } else {
                            findingsStore.addFinding(Finding.builder(MODULE_ID,
                                            "Spring Boot Actuator — " + path.substring(1) + " (Legacy 1.x)",
                                            sev, Confidence.FIRM)
                                    .url(probeUrl)
                                    .evidence(description + " (Legacy Spring Boot 1.x path). "
                                            + "Differential probe confirmed unique response. "
                                            + "Response length: " + body.length() + " bytes.")
                                    .payload(probeUrl)
                                    .requestResponse(result)
                                    .build());
                        }
                    }
                }
            }
            perHostDelay();
        }
    }

    // ── Response Validation ──────────────────────────────────────────────

    /**
     * Validate that a response from an actuator endpoint is actually that endpoint's data,
     * not a generic catch-all/error page.
     */
    private boolean validateActuatorResponse(String path, String body) {
        String lowerBody = body.toLowerCase();

        if (path.contains("/env")) {
            // env returns JSON with property sources
            return body.contains("\"propertySources\"") || body.contains("\"activeProfiles\"")
                    || body.contains("\"systemProperties\"") || body.contains("\"systemEnvironment\"");
        }
        if (path.contains("/configprops")) {
            return body.contains("\"contexts\"") || body.contains("\"beans\"")
                    || body.contains("\"prefix\"");
        }
        if (path.contains("/mappings")) {
            return body.contains("\"dispatcherServlets\"") || body.contains("\"servletFilters\"")
                    || body.contains("\"requestMappingConditions\"") || body.contains("\"handler\"");
        }
        if (path.contains("/beans")) {
            return body.contains("\"contexts\"") || body.contains("\"beans\"")
                    || body.contains("\"scope\"");
        }
        if (path.contains("/threaddump") || path.contains("/dump")) {
            return body.contains("\"threads\"") || body.contains("\"threadName\"")
                    || body.contains("\"threadState\"") || body.contains("\"stackTrace\"");
        }
        if (path.contains("/httptrace") || path.contains("/trace")) {
            return body.contains("\"traces\"") || body.contains("\"request\"")
                    || body.contains("\"timeTaken\"");
        }
        if (path.contains("/loggers")) {
            return body.contains("\"loggers\"") || body.contains("\"effectiveLevel\"")
                    || body.contains("\"configuredLevel\"");
        }
        if (path.contains("/metrics")) {
            return body.contains("\"names\"") || body.contains("\"jvm.memory\"")
                    || body.contains("\"http.server.requests\"");
        }
        if (path.contains("/conditions")) {
            return body.contains("\"contexts\"") || body.contains("\"positiveMatches\"")
                    || body.contains("\"negativeMatches\"");
        }
        if (path.contains("/sessions")) {
            return body.contains("\"sessions\"") || body.contains("\"sessionId\"");
        }
        if (path.contains("/scheduledtasks")) {
            return body.contains("\"cron\"") || body.contains("\"fixedDelay\"")
                    || body.contains("\"fixedRate\"");
        }
        if (path.contains("/flyway")) {
            return body.contains("\"contexts\"") || body.contains("\"flywayBeans\"");
        }
        if (path.contains("/liquibase")) {
            return body.contains("\"contexts\"") || body.contains("\"liquibaseBeans\"");
        }
        if (path.contains("/caches")) {
            return body.contains("\"cacheManagers\"") || body.contains("\"caches\"");
        }
        if (path.contains("/heapdump")) {
            // Heapdump is binary — just check it's large enough
            return body.length() > 1000;
        }
        if (path.contains("/jolokia")) {
            // Jolokia returns JSON with "value" containing MBean info
            return body.contains("\"value\"") && body.contains("\"request\"")
                    && body.contains("\"status\"");
        }
        if (path.contains("/gateway/routes")) {
            // Spring Cloud Gateway returns array of route objects
            return body.contains("\"route_id\"") || body.contains("\"predicate\"")
                    || body.contains("\"uri\"");
        }
        if (path.contains("/prometheus")) {
            // Prometheus metrics in text format (not JSON)
            return body.contains("# HELP") || body.contains("# TYPE")
                    || body.contains("jvm_memory") || body.contains("http_server_requests");
        }

        // Default: require at least JSON-like structure
        return body.startsWith("{") || body.startsWith("[");
    }

    /**
     * Validate legacy Spring Boot 1.x endpoint responses.
     */
    private boolean validateLegacyResponse(String path, String body) {
        // Legacy endpoints return similar structures
        return validateActuatorResponse("/actuator" + path, body);
    }

    // ── HTTP Request Sending ──────────────────────────────────────────────

    private HttpRequestResponse sendProbeRequest(HttpRequestResponse original, String probeUrl) {
        if (ScanState.isCancelled()) return null;

        try {
            HttpRequest probe = HttpRequest.httpRequestFromUrl(probeUrl);
            for (var header : original.request().headers()) {
                String name = header.name().toLowerCase();
                if (name.equals("cookie") || name.equals("authorization")
                        || name.startsWith("x-")) {
                    probe = probe.withRemovedHeader(header.name())
                            .withAddedHeader(header.name(), header.value());
                }
            }
            // Accept JSON
            probe = probe.withRemovedHeader("Accept")
                    .withAddedHeader("Accept", "application/json");

            HttpRequestResponse result = api.http().sendRequest(probe);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    // ── Utility Methods ──────────────────────────────────────────────────

    private Severity parseSeverity(String sev) {
        switch (sev) {
            case "CRITICAL": return Severity.CRITICAL;
            case "HIGH": return Severity.HIGH;
            case "MEDIUM": return Severity.MEDIUM;
            case "LOW": return Severity.LOW;
            default: return Severity.INFO;
        }
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("spring-actuator.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    private String extractPath(String url) {
        try {
            int s = url.indexOf("://");
            if (s >= 0) { int q = url.indexOf('?', s + 3); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private String extractBaseUrl(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return url;
            int pathStart = url.indexOf('/', schemeEnd + 3);
            if (pathStart < 0) return url;
            return url.substring(0, pathStart);
        } catch (Exception e) {
            return url;
        }
    }

    // ── Inner classes ────────────────────────────────────────────────────

    private static class SpringDetection {
        final String evidence;
        SpringDetection(String evidence) {
            this.evidence = evidence;
        }
    }
}
