package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.*;

import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Pattern;

/**
 * CSRF Manipulator — Tests whether CSRF protection is effective by replaying
 * the request with various token manipulations and comparing each response
 * against a baseline (the original unmodified request).
 *
 * This module is RIGHT-CLICK ONLY — it is excluded from "Send to OmniStrike
 * (All Modules)" and from auto-scanning. Users must explicitly select it from
 * the context menu.
 *
 * Test cases:
 *  1. Remove token entirely
 *  2. Empty token value
 *  3. Random/invalid token (same length)
 *  4. Truncated token (first half)
 *  5. Modified one character (last char flipped)
 *  6. Different case (uppercase / lowercase)
 *  7. Static token from different session (hardcoded fake)
 *  8. Same token replayed (nonce reuse check)
 *  9. Remove Referer + Origin headers (keep token)
 * 10. Token in different location (body ↔ URL, header ↔ body)
 * 11. Change HTTP method (POST → GET with query params, or GET → POST)
 *
 * For each test, the module first sends a BASELINE request (identical to the
 * original) and then the manipulated request. Both request/response pairs are
 * stored in the finding evidence so the tester can compare them side-by-side.
 */
public class CsrfManipulator implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    private static final SecureRandom RANDOM = new SecureRandom();

    // Wildcard patterns to auto-detect CSRF token parameters (case-insensitive)
    private static final List<Pattern> CSRF_PARAM_PATTERNS = List.of(
            Pattern.compile(".*csrf.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*xsrf.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)^(?!access_token$|refresh_token$|oauth_token$|api_token$|bearer_token$|id_token$).*_token.*"),
            Pattern.compile(".*authenticity.token.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*anti.?forgery.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*request.?verification.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile("__RequestVerificationToken", Pattern.CASE_INSENSITIVE),
            // Word-boundary nonce — avoids matching "announce", "prononce", etc.
            Pattern.compile("(?i)(^|[^a-z])nonce([^a-z]|$)")
    );

    // Parameter names to explicitly exclude — these are auth tokens, not CSRF tokens
    private static final Set<String> EXCLUDED_PARAM_NAMES = Set.of(
            "access_token", "refresh_token", "oauth_token", "api_token",
            "bearer_token", "id_token", "auth_token", "jwt", "authorization");

    // Headers that commonly carry CSRF tokens
    private static final List<Pattern> CSRF_HEADER_PATTERNS = List.of(
            Pattern.compile(".*csrf.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*xsrf.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile("x-requested-with", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public String getId() { return "csrf-manipulator"; }

    @Override
    public String getName() { return "CSRF Manipulator"; }

    @Override
    public String getDescription() {
        return "Tests CSRF protection by replaying requests with manipulated tokens "
                + "(removed, empty, random, truncated, wrong case, method change, etc.) "
                + "and comparing responses against a baseline. Right-click only.";
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
        if (requestResponse == null || requestResponse.request() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String urlPath = extractPath(url);
        if (!dedup.markIfNew("csrf-manipulator", urlPath, "csrf")) return Collections.emptyList();

        try {
            return testCsrf(requestResponse);
        } catch (Exception e) {
            api.logging().logToError("[CsrfManipulator] Error on " + urlPath + ": " + e.getMessage());
            return Collections.emptyList();
        }
    }

    @Override
    public void destroy() {}

    // ==================== CSRF TOKEN DETECTION ====================

    /**
     * Detects CSRF tokens in request parameters and headers using wildcard patterns.
     * Returns a list of CsrfTarget objects representing found tokens.
     */
    private List<CsrfTarget> detectCsrfTokens(HttpRequestResponse requestResponse) {
        List<CsrfTarget> targets = new ArrayList<>();
        HttpRequest request = requestResponse.request();

        // Check URL, body, and cookie parameters
        for (ParsedHttpParameter param : request.parameters()) {
            // Skip known auth tokens — they are NOT CSRF tokens
            if (EXCLUDED_PARAM_NAMES.contains(param.name().toLowerCase())) continue;

            for (Pattern pattern : CSRF_PARAM_PATTERNS) {
                if (pattern.matcher(param.name()).matches()) {
                    targets.add(new CsrfTarget(param.name(), param.value(), param.type(), null));
                    break;
                }
            }
        }

        // Check request headers
        for (var header : request.headers()) {
            for (Pattern pattern : CSRF_HEADER_PATTERNS) {
                if (pattern.matcher(header.name()).matches()) {
                    targets.add(new CsrfTarget(header.name(), header.value(), null, "header"));
                    break;
                }
            }
        }

        return targets;
    }

    // ==================== BEARER-ONLY CHECK ====================

    /**
     * Checks if the request relies solely on Bearer token authentication (no cookies).
     * Bearer tokens are not automatically attached by browsers, so the request is not
     * vulnerable to CSRF — the attacker's page cannot forge a request that includes
     * the Authorization header.
     *
     * Returns true (skip scan) when:
     *  - Request has an Authorization: Bearer header
     *  - Request has NO Cookie header, OR cookies are non-session (no session/auth/sid patterns)
     */
    private boolean isBearerAuthOnly(HttpRequest request) {
        boolean hasBearer = false;
        boolean hasCookie = false;
        String cookieValue = null;

        for (var header : request.headers()) {
            String name = header.name().toLowerCase();
            if (name.equals("authorization") && header.value().toLowerCase().startsWith("bearer ")) {
                hasBearer = true;
            }
            if (name.equals("cookie") && !header.value().isBlank()) {
                hasCookie = true;
                cookieValue = header.value();
            }
        }

        if (!hasBearer) return false;

        // Has Bearer token — check if there are also session cookies
        if (!hasCookie || cookieValue == null) return true; // Bearer only, no cookies at all

        // Has both Bearer and cookies — check if cookies look like session cookies.
        // If only non-session cookies (analytics, preferences), still Bearer-only for CSRF purposes.
        String lower = cookieValue.toLowerCase();
        return !SESSION_COOKIE_PATTERN.matcher(lower).find();
    }

    private static final Pattern SESSION_COOKIE_PATTERN = Pattern.compile(
            "\\b(session|sess|sid|jsessionid|phpsessid|asp\\.net_sessionid|auth|token|jwt|login|sso)\\b",
            Pattern.CASE_INSENSITIVE);

    // ==================== TEST ORCHESTRATOR ====================

    private List<Finding> testCsrf(HttpRequestResponse original) throws InterruptedException {
        String url = original.request().url();

        // Skip scan if request uses Bearer auth only — not CSRF-vulnerable
        if (isBearerAuthOnly(original.request())) {
            api.logging().logToOutput("[CsrfManipulator] SKIPPED: " + url
                    + " — uses Bearer authentication only (not CSRF-vulnerable). "
                    + "Bearer tokens are not auto-attached by browsers, so cross-origin "
                    + "requests from an attacker page cannot include the Authorization header.");

            findingsStore.addFinding(Finding.builder("csrf-manipulator",
                            "CSRF scan skipped: Bearer auth only",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence("Authorization: Bearer <token> present, no session cookies detected")
                    .description("This endpoint uses Bearer token authentication without browser-managed "
                            + "session cookies. Bearer tokens are sent via the Authorization header which "
                            + "browsers do not automatically attach to cross-origin requests. "
                            + "This means an attacker's page cannot forge authenticated requests to this "
                            + "endpoint — CSRF attacks are not applicable.<br><br>"
                            + "CSRF protection testing was skipped for this request.")
                    .build());

            return Collections.emptyList();
        }

        List<CsrfTarget> csrfTargets = detectCsrfTokens(original);

        if (csrfTargets.isEmpty()) {
            api.logging().logToOutput("[CsrfManipulator] No CSRF tokens detected in: " + url);
            return Collections.emptyList();
        }
        api.logging().logToOutput("[CsrfManipulator] Found " + csrfTargets.size()
                + " CSRF token(s): " + csrfTargets);

        // Send baseline request first — replay the original request unchanged
        // to establish what a "normal" accepted response looks like
        HttpRequestResponse baseline = sendRequest(original.request());
        if (baseline == null || baseline.response() == null) {
            api.logging().logToOutput("[CsrfManipulator] Baseline request failed for: " + url);
            return Collections.emptyList();
        }

        int baselineStatus = baseline.response().statusCode();
        int baselineBodyLen = baseline.response().body().length();
        api.logging().logToOutput("[CsrfManipulator] Baseline: status=" + baselineStatus
                + " bodyLen=" + baselineBodyLen);

        List<Finding> findings = new ArrayList<>();

        for (CsrfTarget target : csrfTargets) {
            if (Thread.currentThread().isInterrupted()) return findings;

            api.logging().logToOutput("[CsrfManipulator] Testing token: " + target.name
                    + " (" + (target.location != null ? target.location : target.paramType) + ")");

            // Run all 11 test cases against this token
            runTest(original, baseline, baselineStatus, baselineBodyLen, target, findings,
                    "1. Remove token entirely",
                    "Token parameter/header removed completely from the request",
                    buildRemovedRequest(original.request(), target));

            runTest(original, baseline, baselineStatus, baselineBodyLen, target, findings,
                    "2. Empty token value",
                    "Token value set to empty string",
                    buildModifiedRequest(original.request(), target, ""));

            runTest(original, baseline, baselineStatus, baselineBodyLen, target, findings,
                    "3. Random/invalid token",
                    "Token replaced with random string of same length",
                    buildModifiedRequest(original.request(), target, randomString(target.value.length())));

            runTest(original, baseline, baselineStatus, baselineBodyLen, target, findings,
                    "4. Truncated token (first half)",
                    "Token truncated to first half only",
                    buildModifiedRequest(original.request(), target,
                            target.value.substring(0, Math.max(1, target.value.length() / 2))));

            runTest(original, baseline, baselineStatus, baselineBodyLen, target, findings,
                    "5. Modified one character",
                    "Last character of token flipped",
                    buildModifiedRequest(original.request(), target, flipLastChar(target.value)));

            // Test 6: Skip if token is hex-only — hex comparison is case-insensitive,
            // so swapping case produces an equivalent token (not a real bypass)
            String swapped = swapCase(target.value);
            if (!swapped.equalsIgnoreCase(target.value) || !isHexOnly(target.value)) {
                runTest(original, baseline, baselineStatus, baselineBodyLen, target, findings,
                        "6. Different case (swapped)",
                        "Token case swapped (upper\u2194lower)",
                        buildModifiedRequest(original.request(), target, swapped));
            } else {
                api.logging().logToOutput("[CsrfManipulator]   6. Case swap SKIPPED — "
                        + "token is hex-only (case-insensitive comparison expected)");
            }

            runTest(original, baseline, baselineStatus, baselineBodyLen, target, findings,
                    "7. Static fake token",
                    "Token replaced with a hardcoded static value from a different session",
                    buildModifiedRequest(original.request(), target,
                            "aaaa" + "bbbb".repeat(Math.max(1, target.value.length() / 4))));

            // Test 8: Replay the exact same token (nonce reuse)
            // Send the original request twice more — if the token is a nonce, the second
            // replay should fail because the first consumed it
            runNonceTest(original, baseline, baselineStatus, baselineBodyLen, target, findings);

            // Test 9: Remove Referer + Origin headers (keep token intact)
            HttpRequest noReferer = original.request()
                    .withRemovedHeader("Referer")
                    .withRemovedHeader("Origin");
            runTest(original, baseline, baselineStatus, baselineBodyLen, target, findings,
                    "9. Remove Referer + Origin headers",
                    "Referer and Origin headers removed; CSRF token kept intact. "
                            + "Tests if server relies on Referer/Origin for CSRF validation",
                    noReferer);

            // Test 10: Move token to different location
            HttpRequest relocated = buildRelocatedRequest(original.request(), target);
            if (relocated != null) {
                runTest(original, baseline, baselineStatus, baselineBodyLen, target, findings,
                        "10. Token moved to different location",
                        "Token moved from " + getLocationName(target) + " to a different location "
                                + "(body↔URL or header↔body)",
                        relocated);
            }

            // Test 11: Change HTTP method
            HttpRequest methodChanged = buildMethodChangedRequest(original.request());
            if (methodChanged != null) {
                runTest(original, baseline, baselineStatus, baselineBodyLen, target, findings,
                        "11. HTTP method changed",
                        "HTTP method changed (POST→GET or GET→POST) with same parameters",
                        methodChanged);
            }
        }

        return findings;
    }

    // ==================== TEST EXECUTION ====================

    /**
     * Runs a single test case: sends the manipulated request, compares against baseline,
     * and creates a finding if the response suggests the manipulation was accepted.
     */
    private void runTest(HttpRequestResponse original, HttpRequestResponse baseline,
                          int baselineStatus, int baselineBodyLen,
                          CsrfTarget target, List<Finding> findings,
                          String testName, String testDescription,
                          HttpRequest manipulatedRequest) throws InterruptedException {
        if (manipulatedRequest == null) return;
        if (Thread.currentThread().isInterrupted()) throw new InterruptedException();

        HttpRequestResponse result = sendRequest(manipulatedRequest);
        if (result == null || result.response() == null) {
            perHostDelay();
            return;
        }

        int resultStatus = result.response().statusCode();
        int resultBodyLen = result.response().body().length();
        boolean accepted = isAccepted(baseline, result);

        api.logging().logToOutput("[CsrfManipulator]   " + testName
                + " → status=" + resultStatus + " bodyLen=" + resultBodyLen
                + " | " + (accepted ? "ACCEPTED (potential bypass!)" : "REJECTED (protected)"));

        if (accepted) {
            Severity severity = determineSeverity(testName);
            String url = original.request().url();

            findings.add(Finding.builder("csrf-manipulator",
                            "CSRF bypass: " + testName + " [" + target.name + "]",
                            severity, Confidence.FIRM)
                    .url(url)
                    .parameter(target.name)
                    .evidence(buildEvidenceString(testName, target, baselineStatus, baselineBodyLen,
                            resultStatus, resultBodyLen))
                    .description(buildDescription(testName, testDescription, target,
                            baselineStatus, baselineBodyLen, resultStatus, resultBodyLen))
                    .remediation("Implement proper server-side CSRF token validation. "
                            + "Tokens should be cryptographically random, bound to the user's session, "
                            + "and validated on every state-changing request. "
                            + "Reject requests with missing, empty, or invalid tokens.")
                    .requestResponse(result)
                    .payload(testName)
                    .responseEvidence(String.valueOf(resultStatus))
                    .build());

            findingsStore.addFinding(findings.get(findings.size() - 1));
        }

        perHostDelay();
    }

    /**
     * Special handler for test 8 (nonce reuse). Sends the original request twice.
     * If both succeed, the token is not single-use (not a nonce).
     */
    private void runNonceTest(HttpRequestResponse original, HttpRequestResponse baseline,
                               int baselineStatus, int baselineBodyLen,
                               CsrfTarget target, List<Finding> findings) throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) throw new InterruptedException();

        // First replay — should succeed (same as baseline)
        HttpRequestResponse replay1 = sendRequest(original.request());
        if (replay1 == null || replay1.response() == null) { perHostDelay(); return; }
        perHostDelay();

        // Second replay — if this also succeeds, token is not a nonce
        HttpRequestResponse replay2 = sendRequest(original.request());
        if (replay2 == null || replay2.response() == null) { perHostDelay(); return; }

        int replay1Status = replay1.response().statusCode();
        int replay2Status = replay2.response().statusCode();
        int replay2BodyLen = replay2.response().body().length();

        boolean bothAccepted = isAccepted(baseline, replay1)
                && isAccepted(baseline, replay2);

        api.logging().logToOutput("[CsrfManipulator]   8. Nonce reuse test"
                + " → replay1=" + replay1Status + " replay2=" + replay2Status
                + " | " + (bothAccepted ? "TOKEN IS REUSABLE (not a nonce)" : "Token appears to be single-use"));

        if (bothAccepted) {
            String url = original.request().url();
            findings.add(Finding.builder("csrf-manipulator",
                            "CSRF token reuse: not a nonce [" + target.name + "]",
                            Severity.LOW, Confidence.FIRM)
                    .url(url)
                    .parameter(target.name)
                    .evidence("Baseline: " + baselineStatus + " (" + baselineBodyLen + " bytes)"
                            + "\nReplay 1: " + replay1Status + " (" + replay1.response().body().length() + " bytes)"
                            + "\nReplay 2: " + replay2Status + " (" + replay2BodyLen + " bytes)"
                            + "\nBoth replays accepted — token is not single-use")
                    .description("The same CSRF token was accepted on multiple requests, "
                            + "indicating the token is not a single-use nonce. "
                            + "While not a direct bypass, reusable tokens have a wider attack window "
                            + "and are easier to exploit if leaked (e.g., via Referer header or logs).")
                    .remediation("Consider implementing single-use CSRF tokens (nonces) that are "
                            + "invalidated after first use, especially for sensitive operations.")
                    .requestResponse(replay2)
                    .payload("8. Same token replayed (nonce reuse)")
                    .responseEvidence(String.valueOf(replay2Status))
                    .build());

            findingsStore.addFinding(findings.get(findings.size() - 1));
        }

        perHostDelay();
    }

    // ==================== RESPONSE COMPARISON ====================

    /** Regex for CSRF/token rejection phrases in response bodies */
    private static final Pattern REJECTION_PHRASES = Pattern.compile(
            "(?i)(invalid.{0,15}(csrf|token|nonce|request)|"
            + "csrf.{0,15}(fail|invalid|mismatch|error|verification|reject)|"
            + "request.{0,15}verification.{0,15}fail|"
            + "forgery.{0,15}(detect|protect)|"
            + "token.{0,15}(expired|invalid|mismatch|missing|required)|"
            + "session.{0,15}(expired|invalid)|"
            + "security.{0,15}(violation|error)|"
            + "forbidden.{0,15}(request|action)|"
            + "access.{0,15}denied)");

    /** URL path fragments that indicate a login/error redirect */
    private static final Pattern LOGIN_REDIRECT_PATTERN = Pattern.compile(
            "(?i)(/login|/signin|/sign-in|/sso|/auth|/session/new|/unauthorized"
            + "|[?&]error=|[?&]expired=|[?&]denied=)");

    /**
     * Determines if a manipulated response was "accepted" by comparing it to the baseline.
     *
     * Checks (in order):
     *  1. Hard reject: 401, 403 status codes
     *  2. Redirect comparison: different Location header = rejected
     *  3. Login redirect detection: redirect targets login/error page = rejected
     *  4. Body rejection signals: response contains CSRF error phrases = rejected
     *  5. Status + body length comparison (within 15% tolerance)
     *
     * Returns false (rejected) if any check indicates the CSRF protection held.
     */
    private boolean isAccepted(HttpRequestResponse baseline, HttpRequestResponse result) {
        if (result == null || result.response() == null) return false;
        if (baseline == null || baseline.response() == null) return false;

        int baselineStatus = baseline.response().statusCode();
        int resultStatus = result.response().statusCode();
        int baselineBodyLen = baseline.response().body().length();
        int resultBodyLen = result.response().body().length();

        // 1. Hard rejection signals
        if (resultStatus == 401 || resultStatus == 403) return false;

        // 2. Redirect comparison — different Location = different outcome
        if (resultStatus >= 300 && resultStatus < 400) {
            String baselineLoc = getResponseHeader(baseline.response(), "Location");
            String resultLoc = getResponseHeader(result.response(), "Location");

            if (baselineLoc != null && resultLoc != null) {
                // Normalize before comparing (strip host, lowercase)
                if (!normalizeRedirectUrl(baselineLoc).equals(normalizeRedirectUrl(resultLoc))) {
                    return false; // Different redirect destination = rejected
                }
            }

            // 3. Even if baseline didn't redirect, check if result redirects to login
            if (resultLoc != null && LOGIN_REDIRECT_PATTERN.matcher(resultLoc).find()) {
                return false; // Redirect to login/error page = rejected
            }
        }

        // 4. Body rejection signal detection
        //    Only flag as rejected if the phrase appears in the result but NOT in the baseline
        //    (avoids false negatives on pages that legitimately mention "token" in content)
        String resultBody = safeBodyString(result);
        String baselineBody = safeBodyString(baseline);
        if (resultBody != null && !resultBody.isEmpty()) {
            boolean resultHasRejection = REJECTION_PHRASES.matcher(resultBody).find();
            boolean baselineHasRejection = baselineBody != null && REJECTION_PHRASES.matcher(baselineBody).find();
            if (resultHasRejection && !baselineHasRejection) {
                return false; // New rejection phrase appeared = server rejected the manipulation
            }
        }

        // 5. Status + body length comparison
        boolean baselineSuccess = baselineStatus >= 200 && baselineStatus < 400;
        boolean resultSuccess = resultStatus >= 200 && resultStatus < 400;

        if (baselineSuccess && resultSuccess) {
            if (baselineBodyLen == 0) return resultBodyLen == 0;
            double ratio = (double) resultBodyLen / baselineBodyLen;
            return ratio >= 0.85 && ratio <= 1.15;
        }

        if (resultStatus == baselineStatus) {
            if (baselineBodyLen == 0) return true;
            double ratio = (double) resultBodyLen / baselineBodyLen;
            return ratio >= 0.85 && ratio <= 1.15;
        }

        return false;
    }

    private static String getResponseHeader(burp.api.montoya.http.message.responses.HttpResponse response, String name) {
        for (var h : response.headers()) {
            if (h.name().equalsIgnoreCase(name)) return h.value();
        }
        return null;
    }

    /** Normalize redirect URL for comparison — extract path, lowercase, strip trailing slash */
    private static String normalizeRedirectUrl(String url) {
        if (url == null) return "";
        String lower = url.toLowerCase();
        // Strip scheme + host if present
        int idx = lower.indexOf("://");
        if (idx > 0) {
            int slashIdx = lower.indexOf('/', idx + 3);
            lower = slashIdx > 0 ? lower.substring(slashIdx) : "/";
        }
        // Strip trailing slash for comparison
        if (lower.length() > 1 && lower.endsWith("/")) {
            lower = lower.substring(0, lower.length() - 1);
        }
        return lower;
    }

    private static String safeBodyString(HttpRequestResponse rr) {
        try {
            return rr.response().bodyToString();
        } catch (Exception e) {
            return null;
        }
    }

    // ==================== REQUEST BUILDERS ====================

    /**
     * Builds a request with the CSRF token removed entirely.
     */
    private HttpRequest buildRemovedRequest(HttpRequest original, CsrfTarget target) {
        if ("header".equals(target.location)) {
            return original.withRemovedHeader(target.name);
        }
        return removeParameter(original, target);
    }

    /**
     * Builds a request with the CSRF token value replaced.
     */
    private HttpRequest buildModifiedRequest(HttpRequest original, CsrfTarget target, String newValue) {
        if ("header".equals(target.location)) {
            return original.withRemovedHeader(target.name).withAddedHeader(target.name, newValue);
        }
        return replaceParameter(original, target, newValue);
    }

    /**
     * Moves the token to a different location (body param → URL param, URL param → body, etc.)
     */
    private HttpRequest buildRelocatedRequest(HttpRequest original, CsrfTarget target) {
        if ("header".equals(target.location)) {
            // Header → body parameter
            HttpRequest withoutHeader = original.withRemovedHeader(target.name);
            return withoutHeader.withAddedParameters(
                    HttpParameter.bodyParameter(target.name, target.value));
        }

        if (target.paramType == HttpParameterType.BODY) {
            // Body → URL query parameter
            HttpRequest withoutBody = removeParameter(original, target);
            return withoutBody.withAddedParameters(
                    HttpParameter.urlParameter(target.name, target.value));
        }

        if (target.paramType == HttpParameterType.URL) {
            // URL → body parameter
            HttpRequest withoutUrl = removeParameter(original, target);
            return withoutUrl.withAddedParameters(
                    HttpParameter.bodyParameter(target.name, target.value));
        }

        return null;
    }

    /**
     * Changes the HTTP method: POST → GET (moving body params to query string) or GET → POST.
     */
    private HttpRequest buildMethodChangedRequest(HttpRequest original) {
        String method = original.method().toUpperCase();
        if ("POST".equals(method)) {
            // POST → GET: move body parameters to URL query string
            List<ParsedHttpParameter> bodyParams = new ArrayList<>();
            for (ParsedHttpParameter p : original.parameters()) {
                if (p.type() == HttpParameterType.BODY) {
                    bodyParams.add(p);
                }
            }

            HttpRequest getRequest = original.withMethod("GET")
                    .withRemovedHeader("Content-Type")
                    .withBody("");

            for (ParsedHttpParameter p : bodyParams) {
                getRequest = getRequest.withAddedParameters(
                        HttpParameter.urlParameter(p.name(), p.value()));
            }
            return getRequest;

        } else if ("GET".equals(method)) {
            // GET → POST: move URL query params to body
            List<ParsedHttpParameter> urlParams = new ArrayList<>();
            for (ParsedHttpParameter p : original.parameters()) {
                if (p.type() == HttpParameterType.URL) {
                    urlParams.add(p);
                }
            }

            // Build body string
            StringBuilder body = new StringBuilder();
            for (ParsedHttpParameter p : urlParams) {
                if (body.length() > 0) body.append("&");
                body.append(p.name()).append("=").append(p.value());
            }

            // Strip query string from URL
            String url = original.url();
            int qIdx = url.indexOf('?');
            String baseUrl = qIdx > 0 ? url.substring(0, qIdx) : url;

            return original.withMethod("POST")
                    .withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
                    .withBody(body.toString());
        }

        return null;
    }

    // ==================== PARAMETER HELPERS ====================

    private HttpRequest replaceParameter(HttpRequest request, CsrfTarget target, String newValue) {
        if (target.paramType == HttpParameterType.BODY) {
            return request.withUpdatedParameters(HttpParameter.bodyParameter(target.name, newValue));
        } else if (target.paramType == HttpParameterType.URL) {
            return request.withUpdatedParameters(HttpParameter.urlParameter(target.name, newValue));
        } else if (target.paramType == HttpParameterType.COOKIE) {
            return request.withUpdatedParameters(HttpParameter.cookieParameter(target.name, newValue));
        }
        return request;
    }

    private HttpRequest removeParameter(HttpRequest request, CsrfTarget target) {
        if (target.paramType == HttpParameterType.BODY) {
            return request.withRemovedParameters(HttpParameter.bodyParameter(target.name, target.value));
        } else if (target.paramType == HttpParameterType.URL) {
            return request.withRemovedParameters(HttpParameter.urlParameter(target.name, target.value));
        } else if (target.paramType == HttpParameterType.COOKIE) {
            return request.withRemovedParameters(HttpParameter.cookieParameter(target.name, target.value));
        }
        return request;
    }

    // ==================== EVIDENCE BUILDERS ====================

    private String buildEvidenceString(String testName, CsrfTarget target,
                                        int baselineStatus, int baselineBodyLen,
                                        int resultStatus, int resultBodyLen) {
        return "Test: " + testName
                + "\nToken: " + target.name + " (" + getLocationName(target) + ")"
                + "\nOriginal value: " + truncate(target.value, 80)
                + "\n\nBaseline response: " + baselineStatus + " (" + baselineBodyLen + " bytes)"
                + "\nManipulated response: " + resultStatus + " (" + resultBodyLen + " bytes)"
                + "\nVerdict: ACCEPTED — CSRF protection may be bypassed";
    }

    private String buildDescription(String testName, String testDescription, CsrfTarget target,
                                     int baselineStatus, int baselineBodyLen,
                                     int resultStatus, int resultBodyLen) {
        return "<b>CSRF Token Manipulation Test</b><br><br>"
                + "<b>Test:</b> " + testName + "<br>"
                + "<b>Description:</b> " + testDescription + "<br><br>"
                + "<b>Token parameter:</b> <code>" + target.name + "</code> "
                + "(" + getLocationName(target) + ")<br>"
                + "<b>Original token value:</b> <code>" + truncate(target.value, 80) + "</code><br><br>"
                + "<table border='1' cellpadding='4' cellspacing='0'>"
                + "<tr><th></th><th>Status Code</th><th>Body Length</th></tr>"
                + "<tr><td><b>Baseline</b></td><td>" + baselineStatus + "</td><td>" + baselineBodyLen + " bytes</td></tr>"
                + "<tr><td><b>Manipulated</b></td><td>" + resultStatus + "</td><td>" + resultBodyLen + " bytes</td></tr>"
                + "</table><br>"
                + "The manipulated request received a response similar to the baseline, "
                + "suggesting the CSRF token is not being properly validated for this test case.";
    }

    // ==================== SEVERITY MAPPING ====================

    private Severity determineSeverity(String testName) {
        if (testName.startsWith("1.")) return Severity.HIGH;   // Remove token entirely
        if (testName.startsWith("2.")) return Severity.HIGH;   // Empty token
        if (testName.startsWith("3.")) return Severity.HIGH;   // Random token
        if (testName.startsWith("11.")) return Severity.MEDIUM; // Method change
        if (testName.startsWith("9.")) return Severity.MEDIUM;  // Remove Referer/Origin
        if (testName.startsWith("10.")) return Severity.MEDIUM; // Token relocation
        return Severity.LOW; // Tests 4-7 (truncated, one char, case, static) are weaker signals
    }

    // ==================== UTILITY ====================

    private HttpRequestResponse sendRequest(HttpRequest request) {
        try {
            return api.http().sendRequest(request);
        } catch (Exception e) {
            api.logging().logToError("[CsrfManipulator] Request failed: " + e.getMessage());
            return null;
        }
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config != null ? config.getInt("csrf.delay.ms", 200) : 200;
        if (delay > 0) Thread.sleep(delay);
    }

    private static String randomString(int length) {
        if (length <= 0) length = 16;
        String chars = "abcdef0123456789";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(RANDOM.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private static String flipLastChar(String value) {
        if (value == null || value.isEmpty()) return "X";
        char last = value.charAt(value.length() - 1);
        char flipped = Character.isDigit(last) ? (char) ('0' + ((last - '0' + 1) % 10))
                : Character.isLetter(last) ? (char) (last ^ 0x20) // toggle case
                : 'X';
        return value.substring(0, value.length() - 1) + flipped;
    }

    private static String swapCase(String value) {
        if (value == null) return "";
        StringBuilder sb = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            if (Character.isUpperCase(c)) sb.append(Character.toLowerCase(c));
            else if (Character.isLowerCase(c)) sb.append(Character.toUpperCase(c));
            else sb.append(c);
        }
        // If nothing changed (all digits/symbols), just uppercase it
        String result = sb.toString();
        return result.equals(value) ? value.toUpperCase() : result;
    }

    /** Returns true if the string contains only hex characters (0-9, a-f, A-F) */
    private static boolean isHexOnly(String value) {
        if (value == null || value.isEmpty()) return false;
        for (char c : value.toCharArray()) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    private static String getLocationName(CsrfTarget target) {
        if ("header".equals(target.location)) return "header";
        if (target.paramType == HttpParameterType.BODY) return "body parameter";
        if (target.paramType == HttpParameterType.URL) return "URL parameter";
        if (target.paramType == HttpParameterType.COOKIE) return "cookie";
        return "unknown";
    }

    private static String extractPath(String url) {
        if (url == null) return "";
        int qIdx = url.indexOf('?');
        return qIdx > 0 ? url.substring(0, qIdx) : url;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    // ==================== INNER CLASSES ====================

    /**
     * Represents a detected CSRF token — its name, value, and where it lives in the request.
     */
    private static class CsrfTarget {
        final String name;
        final String value;
        final HttpParameterType paramType; // non-null for URL/body/cookie params
        final String location;             // "header" or null (for params, use paramType)

        CsrfTarget(String name, String value, HttpParameterType paramType, String location) {
            this.name = name;
            this.value = value != null ? value : "";
            this.paramType = paramType;
            this.location = location;
        }

        @Override
        public String toString() {
            return name + "=" + truncate(value, 20)
                    + " (" + (location != null ? location : paramType) + ")";
        }

        private static String truncate(String s, int max) {
            if (s == null) return "";
            return s.length() > max ? s.substring(0, max) + "..." : s;
        }
    }
}
