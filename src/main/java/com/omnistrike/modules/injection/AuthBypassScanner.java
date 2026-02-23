package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Authentication Bypass Scanner
 *
 * Detects missing authorization enforcement by stripping or manipulating
 * authentication credentials and replaying requests. Tests 6 attack scenarios:
 *   Phase 1: Strip Authorization header entirely
 *   Phase 2: Strip Cookie header entirely
 *   Phase 3: Strip common custom auth headers (X-Auth-Token, X-API-Key, etc.)
 *   Phase 4: Empty/null auth values (empty Bearer, Bearer null, etc.)
 *   Phase 5: HTTP method override headers to bypass method-based auth checks
 *   Phase 6: Path manipulation to bypass URL-based middleware auth checks
 */
public class AuthBypassScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Common custom auth headers to test in Phase 3
    private static final String[] CUSTOM_AUTH_HEADERS = {
            "X-Auth-Token",
            "X-API-Key",
            "X-Access-Token",
            "Token",
            "Api-Key",
            "X-Session-Token",
    };

    // Invalid auth values to test in Phase 4
    private static final String[] EMPTY_AUTH_VALUES = {
            "",
            "Bearer ",
            "Bearer null",
            "Basic ",
    };

    // Method override headers for Phase 5
    private static final String[] METHOD_OVERRIDE_HEADERS = {
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
    };

    // Path manipulation patterns for Phase 6
    // Each entry is a function that transforms a path (represented as format strings)
    private static final String[] PATH_MANIPULATIONS = {
            "//",        // double slash prefix
            "/./",       // dot segment
            "/../;/",    // semicolon traversal (Tomcat)
            "UPPERCASE", // case change (special handling)
            "/%2e/",     // URL-encoded dot
    };

    // Keywords in response body that indicate auth failure
    private static final Pattern AUTH_FAILURE_PATTERN = Pattern.compile(
            "unauthorized|login|forbidden|access denied|authentication required|session expired",
            Pattern.CASE_INSENSITIVE
    );

    // Body length tolerance for comparison (15%)
    private static final double BODY_LENGTH_TOLERANCE = 0.15;

    @Override
    public String getId() { return "auth-bypass"; }

    @Override
    public String getName() { return "Authentication Bypass Scanner"; }

    @Override
    public String getDescription() {
        return "Detects missing authorization enforcement by stripping authentication credentials "
                + "(Authorization header, cookies, custom auth headers) and replaying requests. "
                + "Tests method override bypass, path manipulation bypass, and empty/null auth values.";
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
        String url = request.url();

        // Phase 1: Strip Authorization header
        if (config.getBool("authbypass.stripAuthorization.enabled", true)) {
            if (hasHeader(request, "Authorization")) {
                if (dedup.markIfNew("auth-bypass", urlPath, "__strip_authorization__")) {
                    try {
                        testStripAuthorization(requestResponse, url, urlPath);
                    } catch (Exception e) {
                        api.logging().logToError("Auth bypass Phase 1 error: " + e.getMessage());
                    }
                }
            }
        }

        // Phase 2: Strip Cookie header
        if (config.getBool("authbypass.stripCookie.enabled", true)) {
            if (hasHeader(request, "Cookie")) {
                if (dedup.markIfNew("auth-bypass", urlPath, "__strip_cookie__")) {
                    try {
                        testStripCookie(requestResponse, url, urlPath);
                    } catch (Exception e) {
                        api.logging().logToError("Auth bypass Phase 2 error: " + e.getMessage());
                    }
                }
            }
        }

        // Phase 3: Strip custom auth headers
        if (config.getBool("authbypass.stripCustomHeaders.enabled", true)) {
            for (String header : CUSTOM_AUTH_HEADERS) {
                if (hasHeader(request, header)) {
                    if (dedup.markIfNew("auth-bypass", urlPath, "__strip_" + header.toLowerCase() + "__")) {
                        try {
                            testStripCustomHeader(requestResponse, url, urlPath, header);
                        } catch (Exception e) {
                            api.logging().logToError("Auth bypass Phase 3 error (" + header + "): " + e.getMessage());
                        }
                    }
                }
            }
        }

        // Phase 4: Empty/null auth values
        if (config.getBool("authbypass.emptyAuth.enabled", true)) {
            if (hasHeader(request, "Authorization")) {
                if (dedup.markIfNew("auth-bypass", urlPath, "__empty_auth__")) {
                    try {
                        testEmptyAuthValues(requestResponse, url, urlPath);
                    } catch (Exception e) {
                        api.logging().logToError("Auth bypass Phase 4 error: " + e.getMessage());
                    }
                }
            }
        }

        // Phase 5: HTTP method override
        if (config.getBool("authbypass.methodOverride.enabled", true)) {
            if (dedup.markIfNew("auth-bypass", urlPath, "__method_override__")) {
                try {
                    testMethodOverride(requestResponse, url, urlPath);
                } catch (Exception e) {
                    api.logging().logToError("Auth bypass Phase 5 error: " + e.getMessage());
                }
            }
        }

        // Phase 6: Path manipulation
        if (config.getBool("authbypass.pathManipulation.enabled", true)) {
            if (dedup.markIfNew("auth-bypass", urlPath, "__path_manipulation__")) {
                try {
                    testPathManipulation(requestResponse, url, urlPath);
                } catch (Exception e) {
                    api.logging().logToError("Auth bypass Phase 6 error: " + e.getMessage());
                }
            }
        }

        return Collections.emptyList();
    }

    // ==================== PHASE 1: STRIP AUTHORIZATION HEADER ====================

    private void testStripAuthorization(HttpRequestResponse original, String url, String urlPath)
            throws InterruptedException {
        // Capture baseline response (with auth)
        Baseline baseline = captureBaseline(original);
        if (baseline == null) return;

        // Send request without Authorization header
        HttpRequest stripped = original.request().withRemovedHeader("Authorization");
        HttpRequestResponse result = sendRequest(stripped);
        if (result == null || result.response() == null) return;

        if (looksLikeBypass(baseline, result)) {
            findingsStore.addFinding(Finding.builder("auth-bypass",
                            "Authentication Bypass: Authorization Header Not Required",
                            Severity.CRITICAL, Confidence.CERTAIN)
                    .url(url)
                    .evidence("Original response: " + baseline.statusCode + " (" + baseline.bodyLength + " bytes) | "
                            + "Without Authorization header: " + result.response().statusCode()
                            + " (" + getBodyLength(result) + " bytes)")
                    .description("The endpoint '" + urlPath + "' returns an authenticated response even when "
                            + "the Authorization header is completely removed. This indicates the server does "
                            + "not enforce authentication for this resource, allowing any unauthenticated user "
                            + "to access protected data or functionality.")
                    .remediation("Implement server-side authentication checks on every endpoint that handles "
                            + "sensitive data or operations. Use middleware or framework-level authentication "
                            + "guards. Never rely on client-side enforcement alone.")
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 2: STRIP COOKIE HEADER ====================

    private void testStripCookie(HttpRequestResponse original, String url, String urlPath)
            throws InterruptedException {
        Baseline baseline = captureBaseline(original);
        if (baseline == null) return;

        HttpRequest stripped = original.request().withRemovedHeader("Cookie");
        HttpRequestResponse result = sendRequest(stripped);
        if (result == null || result.response() == null) return;

        if (looksLikeBypass(baseline, result)) {
            findingsStore.addFinding(Finding.builder("auth-bypass",
                            "Authentication Bypass: Cookie Session Not Required",
                            Severity.CRITICAL, Confidence.CERTAIN)
                    .url(url)
                    .evidence("Original response: " + baseline.statusCode + " (" + baseline.bodyLength + " bytes) | "
                            + "Without Cookie header: " + result.response().statusCode()
                            + " (" + getBodyLength(result) + " bytes)")
                    .description("The endpoint '" + urlPath + "' returns an authenticated response even when "
                            + "all session cookies are removed. This indicates the server does not validate "
                            + "the session cookie, allowing unauthenticated access to protected resources.")
                    .remediation("Ensure all protected endpoints validate the session cookie server-side. "
                            + "Return 401 or redirect to login when the session is missing or invalid. "
                            + "Use framework-provided session management with mandatory checks.")
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 3: STRIP CUSTOM AUTH HEADERS ====================

    private void testStripCustomHeader(HttpRequestResponse original, String url, String urlPath,
                                        String headerName) throws InterruptedException {
        Baseline baseline = captureBaseline(original);
        if (baseline == null) return;

        HttpRequest stripped = original.request().withRemovedHeader(headerName);
        HttpRequestResponse result = sendRequest(stripped);
        if (result == null || result.response() == null) return;

        if (looksLikeBypass(baseline, result)) {
            findingsStore.addFinding(Finding.builder("auth-bypass",
                            "Authentication Bypass: " + headerName + " Not Enforced",
                            Severity.HIGH, Confidence.CERTAIN)
                    .url(url).parameter(headerName)
                    .evidence("Original response: " + baseline.statusCode + " (" + baseline.bodyLength + " bytes) | "
                            + "Without " + headerName + ": " + result.response().statusCode()
                            + " (" + getBodyLength(result) + " bytes)")
                    .description("The endpoint '" + urlPath + "' returns an authenticated response even when "
                            + "the custom authentication header '" + headerName + "' is removed. The server "
                            + "does not enforce this authentication mechanism, allowing unauthorized access.")
                    .remediation("Ensure the server validates the '" + headerName + "' header on every "
                            + "protected endpoint. Return 401/403 when the header is missing or invalid.")
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 4: EMPTY/NULL AUTH VALUES ====================

    private void testEmptyAuthValues(HttpRequestResponse original, String url, String urlPath)
            throws InterruptedException {
        Baseline baseline = captureBaseline(original);
        if (baseline == null) return;

        for (String emptyValue : EMPTY_AUTH_VALUES) {
            HttpRequest modified = original.request()
                    .withRemovedHeader("Authorization")
                    .withAddedHeader("Authorization", emptyValue);
            HttpRequestResponse result = sendRequest(modified);
            if (result == null || result.response() == null) continue;

            if (looksLikeBypass(baseline, result)) {
                String valueDesc = emptyValue.isEmpty() ? "(empty string)" : "'" + emptyValue + "'";
                findingsStore.addFinding(Finding.builder("auth-bypass",
                                "Authentication Bypass: Weak Authorization Validation",
                                Severity.HIGH, Confidence.FIRM)
                        .url(url)
                        .evidence("Original response: " + baseline.statusCode + " (" + baseline.bodyLength + " bytes) | "
                                + "With Authorization: " + valueDesc + ": " + result.response().statusCode()
                                + " (" + getBodyLength(result) + " bytes)")
                        .description("The endpoint '" + urlPath + "' accepts an invalid Authorization value "
                                + valueDesc + " and still returns an authenticated response. The server's "
                                + "authorization validation is insufficient — it may only check for the "
                                + "presence of the header without validating the token value.")
                        .remediation("Validate the Authorization header value server-side. Verify the token "
                                + "signature, expiry, and claims. Reject empty, null, or malformed tokens "
                                + "with a 401 response.")
                        .requestResponse(result)
                        .build());
                return; // One finding per endpoint is sufficient
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 5: HTTP METHOD OVERRIDE ====================

    private void testMethodOverride(HttpRequestResponse original, String url, String urlPath)
            throws InterruptedException {
        Baseline baseline = captureBaseline(original);
        if (baseline == null) return;

        // Only test if the original is not already a GET
        String originalMethod = original.request().method();
        if ("GET".equalsIgnoreCase(originalMethod)) return;

        // Only meaningful if the request has auth credentials — method override bypass
        // only matters if stripping auth would cause a 401/403 but method override
        // lets an unauthenticated request through.
        boolean hasAuth = hasHeader(original.request(), "Authorization")
                || hasHeader(original.request(), "Cookie");
        if (!hasAuth) return;

        // First establish that removing auth actually blocks access (proves auth is enforced)
        HttpRequest noAuthRequest = original.request();
        if (hasHeader(noAuthRequest, "Authorization")) {
            noAuthRequest = noAuthRequest.withRemovedHeader("Authorization");
        }
        if (hasHeader(noAuthRequest, "Cookie")) {
            noAuthRequest = noAuthRequest.withRemovedHeader("Cookie");
        }
        HttpRequestResponse noAuthResult = sendRequest(noAuthRequest);
        if (noAuthResult == null || noAuthResult.response() == null) return;

        int noAuthStatus = noAuthResult.response().statusCode();
        // If removing auth still returns 200, the endpoint doesn't require auth — skip
        if (noAuthStatus >= 200 && noAuthStatus < 300) return;

        perHostDelay();

        for (String overrideHeader : METHOD_OVERRIDE_HEADERS) {
            // Strip auth AND add method override — test if the override bypasses auth
            HttpRequest modified = noAuthRequest.withAddedHeader(overrideHeader, "GET");
            HttpRequestResponse result = sendRequest(modified);
            if (result == null || result.response() == null) continue;

            // Also test: GET (no body/auth) with override header to original method
            HttpRequest getWithOverride = HttpRequest.httpRequest()
                    .withService(original.request().httpService())
                    .withMethod("GET")
                    .withPath(original.request().path());
            for (var h : original.request().headers()) {
                String name = h.name();
                if (!"Content-Length".equalsIgnoreCase(name)
                        && !"Content-Type".equalsIgnoreCase(name)
                        && !"Authorization".equalsIgnoreCase(name)
                        && !"Cookie".equalsIgnoreCase(name)) {
                    getWithOverride = getWithOverride.withAddedHeader(name, h.value());
                }
            }
            getWithOverride = getWithOverride.withAddedHeader(overrideHeader, originalMethod);
            HttpRequestResponse getResult = sendRequest(getWithOverride);

            // Check if method override restored access despite missing auth
            if (looksLikeBypass(baseline, result)) {
                findingsStore.addFinding(Finding.builder("auth-bypass",
                                "Authentication Bypass: HTTP Method Override (" + overrideHeader + ")",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter(overrideHeader)
                        .evidence("Original " + originalMethod + " (authed): " + baseline.statusCode
                                + " | No auth: " + noAuthStatus
                                + " | No auth + " + overrideHeader + ": GET: " + result.response().statusCode()
                                + " (" + getBodyLength(result) + " bytes)")
                        .description("The endpoint '" + urlPath + "' requires authentication (returns "
                                + noAuthStatus + " without credentials), but adding the '" + overrideHeader
                                + ": GET' header restores access without credentials. The server bypasses "
                                + "authorization checks when a method override header is present.")
                        .remediation("Disable HTTP method override headers in production. If method override "
                                + "is required, ensure authorization checks apply regardless of the effective "
                                + "HTTP method.")
                        .requestResponse(result)
                        .build());
                return;
            }

            if (getResult != null && getResult.response() != null && looksLikeBypass(baseline, getResult)) {
                findingsStore.addFinding(Finding.builder("auth-bypass",
                                "Authentication Bypass: HTTP Method Override (" + overrideHeader + ")",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter(overrideHeader)
                        .evidence("Original " + originalMethod + " (authed): " + baseline.statusCode
                                + " | No auth: " + noAuthStatus
                                + " | GET (no auth) + " + overrideHeader + ": " + originalMethod + ": "
                                + getResult.response().statusCode() + " (" + getBodyLength(getResult) + " bytes)")
                        .description("The endpoint '" + urlPath + "' requires authentication (returns "
                                + noAuthStatus + " without credentials), but sending a GET with '"
                                + overrideHeader + ": " + originalMethod + "' restores access. "
                                + "Authorization checks apply to the actual HTTP method, not the overridden one.")
                        .remediation("Disable HTTP method override headers in production. If method override "
                                + "is required, ensure authorization checks apply regardless of the effective "
                                + "HTTP method.")
                        .requestResponse(getResult)
                        .build());
                return;
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 6: PATH MANIPULATION ====================

    private void testPathManipulation(HttpRequestResponse original, String url, String urlPath)
            throws InterruptedException {
        Baseline baseline = captureBaseline(original);
        if (baseline == null) return;

        // Remove auth headers for path manipulation tests
        HttpRequest noAuth = original.request();
        boolean hadAuth = false;
        if (hasHeader(noAuth, "Authorization")) {
            noAuth = noAuth.withRemovedHeader("Authorization");
            hadAuth = true;
        }
        if (hasHeader(noAuth, "Cookie")) {
            noAuth = noAuth.withRemovedHeader("Cookie");
            hadAuth = true;
        }
        // If no auth headers present, path manipulation tests aren't meaningful
        if (!hadAuth) return;

        String path = original.request().path();
        if (path == null || path.isEmpty()) path = "/";

        // Generate path manipulation variants
        List<String[]> pathVariants = new ArrayList<>();

        // Double slash: /api/users → //api/users
        pathVariants.add(new String[]{"/" + path, "double slash prefix"});

        // Dot segment: /api/users → /./api/users
        pathVariants.add(new String[]{"/." + path, "dot segment prefix"});

        // Semicolon traversal: /api/users → /api/users/..;/users
        if (path.contains("/") && path.lastIndexOf('/') > 0) {
            String lastSegment = path.substring(path.lastIndexOf('/'));
            pathVariants.add(new String[]{path + "/..;" + lastSegment, "semicolon path traversal"});
        }

        // Case change: /api/users → /API/USERS
        pathVariants.add(new String[]{path.toUpperCase(), "uppercase path"});

        // URL-encoded dot: /api/users → /%2e/api/users
        pathVariants.add(new String[]{"/%2e" + path, "URL-encoded dot prefix"});

        for (String[] variant : pathVariants) {
            String manipulatedPath = variant[0];
            String technique = variant[1];

            try {
                HttpRequest modified = noAuth.withPath(manipulatedPath);
                HttpRequestResponse result = sendRequest(modified);
                if (result == null || result.response() == null) continue;

                if (looksLikeBypass(baseline, result)) {
                    findingsStore.addFinding(Finding.builder("auth-bypass",
                                    "Authentication Bypass: Path Manipulation (" + technique + ")",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .evidence("Original authenticated response: " + baseline.statusCode
                                    + " (" + baseline.bodyLength + " bytes) | "
                                    + "Unauthenticated with path '" + manipulatedPath + "': "
                                    + result.response().statusCode() + " (" + getBodyLength(result) + " bytes)")
                            .description("The endpoint '" + urlPath + "' can be accessed without authentication "
                                    + "by manipulating the URL path using " + technique + " ('" + manipulatedPath
                                    + "'). The authentication middleware matches paths literally and fails to "
                                    + "normalize the URL before checking, allowing the manipulated path to bypass "
                                    + "the auth check while still being routed to the same handler.")
                            .remediation("Normalize URLs before applying authentication checks. Use a middleware "
                                    + "that canonicalizes paths (resolves dot segments, removes duplicate slashes, "
                                    + "handles URL encoding) before routing. Apply authentication at the framework "
                                    + "level rather than route-by-route.")
                            .requestResponse(result)
                            .build());
                    return; // One finding per endpoint
                }
            } catch (Exception e) {
                // Path manipulation might cause invalid requests — skip silently
            }
            perHostDelay();
        }
    }

    // ==================== RESPONSE COMPARISON ====================

    /**
     * Determines if the modified response looks like a successful auth bypass.
     * Checks: same status code, similar body length, no auth failure indicators.
     */
    private boolean looksLikeBypass(Baseline baseline, HttpRequestResponse modifiedResult) {
        int modStatus = modifiedResult.response().statusCode();
        int modBodyLen = getBodyLength(modifiedResult);
        String modBody = modifiedResult.response().bodyToString();

        // Status code must match the authenticated response
        if (modStatus != baseline.statusCode) return false;

        // Only consider 2xx responses as potential bypasses
        if (modStatus < 200 || modStatus >= 300) return false;

        // Body length must be within tolerance
        if (baseline.bodyLength > 0) {
            double ratio = Math.abs((double)(modBodyLen - baseline.bodyLength) / baseline.bodyLength);
            if (ratio > BODY_LENGTH_TOLERANCE) return false;
        }

        // Response must not contain auth failure indicators
        if (modBody != null && AUTH_FAILURE_PATTERN.matcher(modBody).find()) {
            return false;
        }

        return true;
    }

    /**
     * Captures baseline metrics from the original authenticated response.
     */
    private Baseline captureBaseline(HttpRequestResponse original) {
        if (original.response() == null) return null;
        int statusCode = original.response().statusCode();
        int bodyLength = getBodyLength(original);
        return new Baseline(statusCode, bodyLength);
    }

    // ==================== REQUEST HELPERS ====================

    private HttpRequestResponse sendRequest(HttpRequest request) {
        try {
            return api.http().sendRequest(request);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean hasHeader(HttpRequest request, String headerName) {
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase(headerName)) return true;
        }
        return false;
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

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("authbypass.perHostDelay", 300);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }

    // ==================== INNER TYPES ====================

    private static class Baseline {
        final int statusCode;
        final int bodyLength;

        Baseline(int sc, int bl) {
            statusCode = sc;
            bodyLength = bl;
        }
    }
}
