package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;

import com.omnistrike.model.*;

import java.util.*;

/**
 * HTTP Parameter Pollution Scanner
 *
 * Detects inconsistent parameter parsing by duplicating parameters and analyzing
 * server behavior. Tests 4 attack scenarios:
 *   Phase 1: Duplicate parameter with canary value to detect which value the server uses
 *   Phase 2: Conflicting parameter values for privilege escalation (admin=true, role=admin)
 *   Phase 3: WAF bypass via payload splitting across duplicate parameters
 *   Phase 4: Parameter precedence detection (informational — FIRST vs LAST preference)
 */
public class HttpParamPollutionScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Canary value for duplicate detection
    private static final String CANARY = "omnistrike_hpp_canary";

    // Privilege-related parameter names and their escalation values
    private static final Map<String, String> PRIVILEGE_PARAMS = new LinkedHashMap<>();
    static {
        PRIVILEGE_PARAMS.put("admin", "true");
        PRIVILEGE_PARAMS.put("is_admin", "true");
        PRIVILEGE_PARAMS.put("isAdmin", "true");
        PRIVILEGE_PARAMS.put("role", "admin");
        PRIVILEGE_PARAMS.put("user_role", "admin");
        PRIVILEGE_PARAMS.put("access", "admin");
        PRIVILEGE_PARAMS.put("level", "admin");
        PRIVILEGE_PARAMS.put("privilege", "admin");
        PRIVILEGE_PARAMS.put("permissions", "all");
        PRIVILEGE_PARAMS.put("debug", "true");
        PRIVILEGE_PARAMS.put("test", "true");
        PRIVILEGE_PARAMS.put("verified", "true");
        PRIVILEGE_PARAMS.put("approved", "true");
        PRIVILEGE_PARAMS.put("active", "true");
        PRIVILEGE_PARAMS.put("status", "active");
    }

    // XSS split payloads for WAF bypass (Phase 3)
    private static final String[][] SPLIT_PAYLOADS = {
            {"<script", ">alert(1)</script>"},
            {"<img src=x onerror", "=alert(1)>"},
            {"javascript:", "alert(1)"},
    };

    @Override
    public String getId() { return "hpp"; }

    @Override
    public String getName() { return "HTTP Parameter Pollution Scanner"; }

    @Override
    public String getDescription() {
        return "Detects HTTP Parameter Pollution by duplicating parameters and analyzing server behavior. "
                + "Tests for canary reflection, privilege escalation via conflicting values, WAF bypass via "
                + "payload splitting, and parameter precedence detection.";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }

    @Override
    public boolean isPassive() { return false; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                 CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;
    }

    @Override
    public List<Finding> processHttpFlowForParameter(
            HttpRequestResponse requestResponse, String targetParameterName, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<HppTarget> targets = extractTargets(request);
        targets.removeIf(t -> !t.name.equalsIgnoreCase(targetParameterName));
        return runHppTargets(requestResponse, targets, urlPath);
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<HppTarget> targets = extractTargets(request);
        return runHppTargets(requestResponse, targets, urlPath);
    }

    private List<Finding> runHppTargets(HttpRequestResponse requestResponse,
                                         List<HppTarget> targets, String urlPath) {
        for (HppTarget target : targets) {
            if (!dedup.markIfNew("hpp", urlPath, target.name)) continue;

            try {
                String url = requestResponse.request().url();

                // Phase 1: Duplicate parameter with canary
                if (config.getBool("hpp.duplicateCanary.enabled", true)) {
                    testDuplicateCanary(requestResponse, target, url, urlPath);
                }

                // Phase 2: Conflicting privilege values
                if (config.getBool("hpp.conflictingValues.enabled", true)) {
                    testConflictingValues(requestResponse, target, url, urlPath);
                }

                // Phase 3: WAF bypass via payload splitting
                if (config.getBool("hpp.wafBypass.enabled", true)) {
                    testWafBypass(requestResponse, target, url, urlPath);
                }

                // Phase 4: Parameter precedence detection
                if (config.getBool("hpp.precedence.enabled", true)) {
                    testParameterPrecedence(requestResponse, target, url, urlPath);
                }

            } catch (Exception e) {
                api.logging().logToError("HPP test error on " + target.name + ": " + e.getMessage());
            }
        }

        return Collections.emptyList();
    }

    // ==================== PHASE 1: DUPLICATE PARAMETER WITH CANARY ====================

    private void testDuplicateCanary(HttpRequestResponse original, HppTarget target,
                                      String url, String urlPath) throws InterruptedException {
        // Get baseline response for comparison
        HttpRequestResponse baseline = sendRequest(original.request());
        if (baseline == null || baseline.response() == null) return;
        String baselineBody = baseline.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Append duplicate parameter: param=original&param=canary
        HttpRequest modified = appendDuplicateParam(original.request(), target, CANARY);
        if (modified == null) return;

        HttpRequestResponse result = sendRequest(modified);
        if (result == null || result.response() == null) return;

        String body = result.response().bodyToString();
        // Only report if canary appears in response but NOT in baseline, and not an error page
        if (body != null && body.contains(CANARY) && !baselineBody.contains(CANARY)
                && result.response().statusCode() < 400) {
            findingsStore.addFinding(Finding.builder("hpp",
                            "HTTP Parameter Pollution: Duplicate Parameter Accepted",
                            Severity.MEDIUM, Confidence.FIRM)
                    .url(url).parameter(target.name)
                    .evidence("Sent " + target.name + "=" + target.originalValue + "&" + target.name + "="
                            + CANARY + " | Canary '" + CANARY + "' reflected in response body")
                    .description("The parameter '" + target.name + "' accepts duplicate values. When the "
                            + "parameter is sent twice (original value + attacker canary), the server uses "
                            + "the attacker-controllable duplicate. This can be exploited for: (1) bypassing "
                            + "input validation or WAF rules by splitting payloads across duplicates, "
                            + "(2) overriding security-relevant parameters when front-end and back-end servers "
                            + "parse duplicates differently (front-end validates first, back-end uses last).")
                    .remediation("The application should explicitly handle duplicate parameters — either reject "
                            + "requests with duplicates (400 Bad Request) or consistently use only the first "
                            + "occurrence. Ensure front-end proxies and back-end servers agree on parameter "
                            + "precedence.")
                    .payload(target.name + "=" + target.originalValue + "&" + target.name + "=" + CANARY)
                    .responseEvidence(CANARY)
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 2: CONFLICTING PARAMETER VALUES ====================

    private void testConflictingValues(HttpRequestResponse original, HppTarget target,
                                        String url, String urlPath) throws InterruptedException {
        // Check if this parameter name maps to a known privilege escalation value
        String escalationValue = null;
        for (Map.Entry<String, String> entry : PRIVILEGE_PARAMS.entrySet()) {
            if (target.name.equalsIgnoreCase(entry.getKey())) {
                // Only test if the original value is different from the escalation value
                if (!target.originalValue.equalsIgnoreCase(entry.getValue())) {
                    escalationValue = entry.getValue();
                }
                break;
            }
        }
        if (escalationValue == null) return;

        // Capture baseline
        HttpRequestResponse baselineResult = sendRequest(original.request());
        if (baselineResult == null || baselineResult.response() == null) return;
        int baselineStatus = baselineResult.response().statusCode();
        int baselineLen = getBodyLength(baselineResult);

        // Send with conflicting value appended
        HttpRequest modified = appendDuplicateParam(original.request(), target, escalationValue);
        if (modified == null) return;

        HttpRequestResponse result = sendRequest(modified);
        if (result == null || result.response() == null) return;

        int modStatus = result.response().statusCode();
        int modLen = getBodyLength(result);
        String modBody = result.response().bodyToString();

        // Check if response changed meaningfully — require status code change to confirm
        boolean statusChanged = modStatus != baselineStatus;
        boolean bodyLenChanged = baselineLen > 0 && Math.abs(modLen - baselineLen) > (baselineLen * 0.20);

        // Require status code upgrade (e.g., 403→200) to confirm actual escalation
        // Status downgrade (200→403) is WAF/rejection, not escalation
        boolean statusUpgrade = statusChanged && modStatus == 200 && baselineStatus >= 400;

        if (statusUpgrade || (statusChanged && bodyLenChanged)) {
            findingsStore.addFinding(Finding.builder("hpp",
                            "HTTP Parameter Pollution: Potential Privilege Escalation",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url).parameter(target.name)
                    .evidence("Original: " + target.name + "=" + target.originalValue + " (status "
                            + baselineStatus + ", " + baselineLen + " bytes) | "
                            + "With duplicate " + target.name + "=" + escalationValue + ": status "
                            + modStatus + ", " + modLen + " bytes")
                    .description("Sending a duplicate parameter '" + target.name + "' with a conflicting "
                            + "privilege value ('" + escalationValue + "') causes the server to respond "
                            + "differently. If the application's front-end validates the first value ('"
                            + target.originalValue + "') but the back-end processes the last value ('"
                            + escalationValue + "'), this HPP vector can escalate privileges, bypass access "
                            + "controls, or modify authorization decisions.")
                    .remediation("Reject requests with duplicate parameters for security-sensitive fields. "
                            + "Validate authorization server-side using session state, not client-supplied "
                            + "parameters. Never use request parameters for role or permission decisions.")
                    .payload(target.name + "=" + target.originalValue + "&" + target.name + "=" + escalationValue)
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 3: WAF BYPASS VIA PAYLOAD SPLITTING ====================

    private void testWafBypass(HttpRequestResponse original, HppTarget target,
                                String url, String urlPath) throws InterruptedException {
        for (String[] splitParts : SPLIT_PAYLOADS) {
            String part1 = splitParts[0];
            String part2 = splitParts[1];
            String fullPayload = part1 + part2;

            // Send split payload: param=<script&param=>alert(1)</script>
            HttpRequest modified = appendDuplicateParamWithValues(
                    original.request(), target, part1, part2);
            if (modified == null) continue;

            HttpRequestResponse result = sendRequest(modified);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            // Skip error responses (WAF blocked it, not bypassed)
            if (result.response().statusCode() >= 400) { perHostDelay(); continue; }
            // Check payload is present and NOT HTML-escaped (escaped = safe)
            if (body != null && body.contains(fullPayload)
                    && !body.contains(fullPayload.replace("<", "&lt;"))) {
                findingsStore.addFinding(Finding.builder("hpp",
                                "HTTP Parameter Pollution: WAF Bypass via Payload Splitting",
                                Severity.MEDIUM, Confidence.TENTATIVE)
                        .url(url).parameter(target.name)
                        .evidence("Split payload across duplicate params: " + target.name + "="
                                + part1 + "&" + target.name + "=" + part2 + " | "
                                + "Reassembled payload '" + fullPayload + "' found in response")
                        .description("An attack payload split across duplicate '" + target.name + "' "
                                + "parameters was reassembled by the server and reflected in the response. "
                                + "This technique can bypass WAF rules that inspect individual parameter "
                                + "values — neither '" + part1 + "' nor '" + part2 + "' triggers WAF rules "
                                + "alone, but the server concatenates them into a complete attack payload.")
                        .remediation("Implement WAF rules that account for parameter concatenation. Reject "
                                + "duplicate parameters at the WAF/proxy level. Apply output encoding on "
                                + "the server side regardless of input validation.")
                        .payload(target.name + "=" + part1 + "&" + target.name + "=" + part2)
                        .responseEvidence(fullPayload)
                        .requestResponse(result)
                        .build());
                return; // One finding per parameter is enough
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 4: PARAMETER PRECEDENCE DETECTION ====================

    private void testParameterPrecedence(HttpRequestResponse original, HppTarget target,
                                          String url, String urlPath) throws InterruptedException {
        String firstValue = "OMNISTRIKE_FIRST";
        String lastValue = "OMNISTRIKE_LAST";

        // Send param=FIRST&param=LAST
        HttpRequest modified = appendDuplicateParamWithValues(
                original.request(), target, firstValue, lastValue);
        if (modified == null) return;

        HttpRequestResponse result = sendRequest(modified);
        if (result == null || result.response() == null) return;

        String body = result.response().bodyToString();
        if (body == null) return;

        boolean hasFirst = body.contains(firstValue);
        boolean hasLast = body.contains(lastValue);

        String precedence = null;
        if (hasFirst && hasLast) {
            precedence = "BOTH (concatenated or all values used)";
        } else if (hasFirst && !hasLast) {
            precedence = "FIRST (uses first occurrence)";
        } else if (!hasFirst && hasLast) {
            precedence = "LAST (uses last occurrence)";
        }

        if (precedence != null) {
            findingsStore.addFinding(Finding.builder("hpp",
                            "HTTP Parameter Pollution: Parameter Precedence — " + precedence,
                            Severity.LOW, Confidence.CERTAIN)
                    .url(url).parameter(target.name)
                    .evidence("Sent " + target.name + "=" + firstValue + "&" + target.name + "="
                            + lastValue + " | Server uses: " + precedence)
                    .description("The server accepts duplicate parameters for '" + target.name + "' "
                            + "and uses the " + precedence + " value. This is informational but confirms "
                            + "the server's parameter parsing behavior, which is critical for chaining HPP "
                            + "with other attacks. If front-end and back-end disagree on precedence, an "
                            + "attacker can bypass validation (front-end checks first, back-end uses last).")
                    .remediation("Document and enforce consistent parameter handling across all layers "
                            + "(load balancer, WAF, reverse proxy, application server). Reject requests "
                            + "with duplicate parameters for sensitive operations.")
                    .payload(target.name + "=" + firstValue + "&" + target.name + "=" + lastValue)
                    .responseEvidence(hasFirst ? firstValue : lastValue)
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PARAMETER EXTRACTION ====================

    private List<HppTarget> extractTargets(HttpRequest request) {
        List<HppTarget> targets = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (ParsedHttpParameter param : request.parameters()) {
            String key = param.name() + ":" + param.type();
            if (seen.contains(key)) continue;
            seen.add(key);

            switch (param.type()) {
                case URL:
                    targets.add(new HppTarget(param.name(), param.value(), ParamLocation.QUERY));
                    break;
                case BODY:
                    targets.add(new HppTarget(param.name(), param.value(), ParamLocation.BODY));
                    break;
                case COOKIE:
                    targets.add(new HppTarget(param.name(), param.value(), ParamLocation.COOKIE));
                    break;
            }
        }

        return targets;
    }

    // ==================== REQUEST HELPERS ====================

    /**
     * Appends a duplicate parameter to the request via raw string manipulation.
     * withUpdatedParameters() replaces by name, so we manipulate the raw request
     * to ensure the parameter appears twice.
     */
    private HttpRequest appendDuplicateParam(HttpRequest request, HppTarget target, String duplicateValue) {
        return appendDuplicateParamWithValues(request, target, target.originalValue, duplicateValue);
    }

    /**
     * Appends a duplicate parameter with two specified values: param=value1&param=value2.
     * The first value replaces the original, the second is appended.
     */
    private HttpRequest appendDuplicateParamWithValues(HttpRequest request, HppTarget target,
                                                        String firstValue, String secondValue) {
        try {
            String suffix = target.name + "=" + secondValue;

            switch (target.location) {
                case QUERY: {
                    // Modify query string directly
                    String fullUrl = request.url();
                    // First update the original parameter value
                    HttpRequest modified = request.withUpdatedParameters(
                            HttpParameter.urlParameter(target.name, PayloadEncoder.encode(firstValue)));
                    // Then append the duplicate to the query string
                    String modUrl = modified.url();
                    String separator = modUrl.contains("?") ? "&" : "?";
                    String newUrl = modUrl + separator + suffix;
                    return modified.withPath(extractPathWithQuery(newUrl));
                }
                case BODY: {
                    // Modify body directly
                    HttpRequest modified = request.withUpdatedParameters(
                            HttpParameter.bodyParameter(target.name, PayloadEncoder.encode(firstValue)));
                    String body = modified.bodyToString();
                    if (body == null) body = "";
                    String separator = body.isEmpty() ? "" : "&";
                    String newBody = body + separator + suffix;
                    return modified.withBody(newBody);
                }
                case COOKIE: {
                    // Append duplicate cookie
                    String cookieHeader = null;
                    for (var h : request.headers()) {
                        if ("Cookie".equalsIgnoreCase(h.name())) {
                            cookieHeader = h.value();
                            break;
                        }
                    }
                    if (cookieHeader == null) return null;
                    String newCookie = cookieHeader + "; " + target.name + "=" + secondValue;
                    return request.withRemovedHeader("Cookie")
                            .withAddedHeader("Cookie", newCookie);
                }
                default:
                    return null;
            }
        } catch (Exception e) {
            return null;
        }
    }

    private HttpRequestResponse sendRequest(HttpRequest request) {
        try {
            return api.http().sendRequest(request);
        } catch (Exception e) {
            return null;
        }
    }

    private int getBodyLength(HttpRequestResponse rr) {
        try {
            String body = rr.response().bodyToString();
            return body != null ? body.length() : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    // ==================== GENERAL HELPERS ====================

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    /**
     * Extracts path + query string from a full URL (strips scheme + host).
     */
    private String extractPathWithQuery(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) return url.substring(s);
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("hpp.perHostDelay", 300);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }

    // ==================== INNER TYPES ====================

    private enum ParamLocation { QUERY, BODY, COOKIE }

    private static class HppTarget {
        final String name, originalValue;
        final ParamLocation location;

        HppTarget(String n, String v, ParamLocation l) {
            name = n;
            originalValue = v != null ? v : "";
            location = l;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof HppTarget)) return false;
            HppTarget t = (HppTarget) o;
            return name.equals(t.name) && location == t.location;
        }

        @Override
        public int hashCode() { return Objects.hash(name, location); }
    }
}
