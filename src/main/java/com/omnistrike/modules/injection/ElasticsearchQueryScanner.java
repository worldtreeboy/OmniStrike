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
 * MODULE: Elasticsearch Query Injection Scanner
 *
 * This module CANNOT be manually triggered by the user. It is an active module
 * that passively gates on Elasticsearch indicators in responses. Only when
 * Elasticsearch is confirmed does it fire query injection payloads.
 *
 * Flow:
 *   1. Receives request/response via processHttpFlow() during active scanning
 *   2. Checks the RESPONSE body and URL for Elasticsearch indicators
 *   3. If NO ES indicators -> returns empty (zero payloads sent)
 *   4. If ES detected -> reports INFO finding, then injects query payloads
 *   5. 4 attack phases: Query Injection, Index Enumeration, Field Exposure, Script Injection
 *
 * All methods are READ-ONLY (search queries, _cat, _mapping — no PUT/POST/DELETE to indices).
 *
 * Stop-scan: Respects ScanState.isCancelled() and Thread.isInterrupted().
 */
public class ElasticsearchQueryScanner implements ScanModule {

    private static final String MODULE_ID = "elasticsearch-query-scanner";

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    // ── Elasticsearch detection patterns (passive gate) ─────────────────────

    // Error messages that confirm Elasticsearch — only ES-exclusive patterns
    // Excluded: maxBooleanClauses (shared with Solr/Lucene), ParseException (generic Java)
    private static final Pattern ES_ERROR_PATTERN = Pattern.compile(
            "ElasticsearchException|"
                    + "org\\.elasticsearch\\.|"
                    + "ElasticSearchParseException|"
                    + "SearchPhaseExecutionException|"
                    + "index_not_found_exception|"
                    + "search_phase_execution_exception|"
                    + "query_shard_exception|"
                    + "mapper_parsing_exception|"
                    + "illegal_argument_exception.*elasticsearch|"
                    + "all shards failed|"
                    + "elastic\\.co/guide",
            Pattern.CASE_INSENSITIVE);

    // URL patterns that strongly indicate Elasticsearch endpoints
    private static final Pattern ES_URL_PATTERN = Pattern.compile(
            "/_search\\b|"
                    + "/_cat/|"
                    + "/_mapping|"
                    + "/_cluster/|"
                    + "/_nodes/|"
                    + "/_aliases|"
                    + "/_analyze|"
                    + "/_settings",
            Pattern.CASE_INSENSITIVE);

    // ES-specific response body markers for Check 2 (URL + body)
    private static final Pattern ES_BODY_MARKER = Pattern.compile(
            "\"hits\"\\s*:\\s*\\{|"
                    + "\"_shards\"\\s*:|"
                    + "\"_index\"\\s*:|"
                    + "\"_source\"\\s*:|"
                    + "\"timed_out\"\\s*:",
            Pattern.CASE_INSENSITIVE);

    // ── ES query parameter names ───────────────────────────────────────────

    private static final Set<String> ES_PARAM_NAMES = Set.of(
            "q", "query", "search", "filter", "source", "_source");

    // ES query syntax indicators in parameter values
    private static final Pattern ES_SYNTAX_PATTERN = Pattern.compile(
            "\\*:\\*|\\w+:\\w+|\\bAND\\b|\\bOR\\b|\\bNOT\\b|\"query\"\\s*:",
            Pattern.CASE_INSENSITIVE);

    // ── Phase 2: Sensitive index names ────────────────────────────────────

    // Only admin-restricted / security-relevant indices — no user-accessible ones
    private static final String[] SENSITIVE_INDICES = {
            ".security", ".kibana", ".tasks", ".watches",
            ".monitoring-es-", ".apm-agent-configuration",
            "users", "credentials", "secrets", "logs", "audit"
    };

    // ── ScanModule interface ──────────────────────────────────────────────

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "Elasticsearch Query Injection"; }
    @Override public String getDescription() {
        return "Detects Elasticsearch and tests for query injection, index enumeration, "
                + "field exposure, and script injection. "
                + "Only activates when Elasticsearch indicators are detected in responses.";
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

        // PASSIVE GATE: Check response for Elasticsearch indicators
        ESDetection detection = detectElasticsearch(requestResponse);
        if (detection == null) return Collections.emptyList();

        // ES confirmed — report INFO finding
        if (dedup.markIfNew(MODULE_ID, urlPath, "es-detected")) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Elasticsearch Detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(detection.evidence)
                    .description("The target application is running Elasticsearch. "
                            + "Query injection testing will be performed automatically.")
                    .requestResponse(requestResponse)
                    .build());
            api.logging().logToOutput("[ES] Elasticsearch detected: " + url + " | " + detection.evidence);
        }

        // ACTIVE ATTACK: Inject query payloads
        try {
            testEsInjection(requestResponse, detection, url, urlPath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return Collections.emptyList();
    }

    // ── Elasticsearch Detection (passive gate) ─────────────────────────────

    private ESDetection detectElasticsearch(HttpRequestResponse reqResp) {
        String body = reqResp.response().bodyToString();
        if (body == null) body = "";
        String url = reqResp.request().url();

        // Check 1: Error messages in response body (strongest signal — standalone)
        if (ES_ERROR_PATTERN.matcher(body).find()) {
            return new ESDetection("Elasticsearch error pattern in response body");
        }

        // Check 2: URL pattern + ES-specific body markers (require both)
        if (ES_URL_PATTERN.matcher(url).find()) {
            if (ES_BODY_MARKER.matcher(body).find()) {
                return new ESDetection("Elasticsearch URL pattern (" + url + ") + ES body markers");
            }
        }

        return null;
    }

    // ── Active ES Injection Testing ───────────────────────────────────────

    private void testEsInjection(HttpRequestResponse original, ESDetection detection,
                                  String url, String urlPath) throws InterruptedException {
        HttpRequest request = original.request();

        List<InjectableParam> targets = identifyTargets(request);
        if (targets.isEmpty()) return;

        for (InjectableParam target : targets) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            if (!dedup.markIfNew(MODULE_ID, urlPath, target.name)) continue;

            api.logging().logToOutput("[ES] Testing parameter '" + target.name + "' on " + url);

            // Phase 1: Query Injection (match-all, tautology)
            testQueryInjection(original, target, url);

            // Phase 2: Index Enumeration
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testIndexEnumeration(original, url, urlPath);

            // Phase 3: Field/Mapping Exposure
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testFieldExposure(original, target, url);

            // Phase 4: Script Injection Probe
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testScriptInjection(original, target, url);
        }
    }

    // ── Phase 1: Query Injection ──────────────────────────────────────────

    private void testQueryInjection(HttpRequestResponse original, InjectableParam target,
                                     String url) throws InterruptedException {
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        int baselineHits = extractTotalHits(baselineBody);

        // Test 1: Inject *:* (match all documents) via query string syntax
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            HttpRequestResponse result = sendPayload(original, target, "*:*");
            if (result != null && result.response() != null
                    && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";
                    int resultHits = extractTotalHits(resultBody);

                    // Guard: both must be parseable (>= 0) to avoid FP when baseline has no total
                    if (resultHits > baselineHits + 2
                            && baselineHits >= 0 && resultHits >= 0
                            && resultBody.contains("\"hits\"")
                            && resultBody.contains("\"_source\"")
                            && result.response().statusCode() == 200
                            && !resultBody.equals(baselineBody)) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Elasticsearch Query Injection — Match All (*:*)",
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("Injected *:* returned total_hits=" + resultHits
                                        + " vs baseline total_hits=" + baselineHits
                                        + ". Response contains ES JSON format markers.")
                                .payload("*:*")
                                .requestResponse(result)
                                .build());
                        perHostDelay();
                        return;
                    }
                }
            }
            perHostDelay();
        }

        // Test 2: JSON DSL body injection — if the request has a JSON body with "query", try match_all
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String requestBody = original.request().bodyToString();
            if (requestBody != null && requestBody.contains("\"query\"") && requestBody.contains("{")) {
                String matchAllBody = requestBody.replaceFirst(
                        "\"query\"\\s*:\\s*\\{[^}]*\\}",
                        "\"query\":{\"match_all\":{}}");
                if (!matchAllBody.equals(requestBody)) {
                    HttpRequest modified = original.request().withBody(matchAllBody);
                    HttpRequestResponse result = sendModifiedRequest(original, modified);
                    if (result != null && result.response() != null
                            && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
                        if (ResponseGuard.isUsableResponse(result)) {
                            String resultBody = result.response().bodyToString();
                            if (resultBody == null) resultBody = "";
                            int resultHits = extractTotalHits(resultBody);

                            if (resultHits > baselineHits + 2
                                    && baselineHits >= 0 && resultHits >= 0
                                    && resultBody.contains("\"hits\"")
                                    && resultBody.contains("\"_source\"")
                                    && result.response().statusCode() == 200
                                    && !resultBody.equals(baselineBody)) {
                                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                                "Elasticsearch Query Injection — JSON DSL match_all",
                                                Severity.HIGH, Confidence.FIRM)
                                        .url(url).parameter("request body (JSON DSL)")
                                        .evidence("Replaced query with match_all:{} returned total_hits=" + resultHits
                                                + " vs baseline total_hits=" + baselineHits
                                                + ". JSON query DSL injection confirmed.")
                                        .payload("{\"query\":{\"match_all\":{}}}")
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
        }

        // Test 3: Tautology — append OR *:* to existing query
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String tautologyPayload = target.originalValue + " OR *:*";
            HttpRequestResponse result = sendPayload(original, target, tautologyPayload);
            if (result != null && result.response() != null
                    && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";
                    int resultHits = extractTotalHits(resultBody);

                    // Guard: both must be parseable (>= 0)
                    if (resultHits > baselineHits + 2
                            && baselineHits >= 0 && resultHits >= 0
                            && resultBody.contains("\"hits\"")
                            && resultBody.contains("\"_source\"")
                            && result.response().statusCode() == 200
                            && !resultBody.equals(baselineBody)) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Elasticsearch Query Injection — Tautology (OR *:*)",
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("Appended ' OR *:*' returned total_hits=" + resultHits
                                        + " vs baseline total_hits=" + baselineHits
                                        + ". Query tautology bypassed the original filter.")
                                .payload(tautologyPayload)
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

    // ── Phase 2: Index Enumeration ────────────────────────────────────────

    private void testIndexEnumeration(HttpRequestResponse original, String url,
                                       String urlPath) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, urlPath, "index-enum")) return;

        String baseUrl = extractBaseUrl(url);

        // Probe 1: /_cat/indices — lists all indices
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String probeUrl = baseUrl + "/_cat/indices?v&format=json";
            HttpRequestResponse result = sendProbeRequest(original, probeUrl);
            if (result != null && result.response() != null) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    // Require ES-specific markers: "index" + "docs.count" or "health"+"status"+"index"
                    boolean hasCatMarkers = (resultBody.contains("\"index\"") && resultBody.contains("\"docs.count\""))
                            || (resultBody.contains("\"health\"") && resultBody.contains("\"status\"")
                            && resultBody.contains("\"index\""));
                    if (result.response().statusCode() == 200 && hasCatMarkers) {

                        // Differential: compare against a nonexistent endpoint
                        HttpRequestResponse control = sendProbeRequest(original,
                                baseUrl + "/_cat/nonexistent_" + System.currentTimeMillis());
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
                                            "Elasticsearch Index Listing Exposed — _cat/indices",
                                            Severity.HIGH, Confidence.FIRM)
                                    .url(probeUrl)
                                    .evidence("/_cat/indices endpoint returned index listing with ES-specific markers. "
                                            + "Differential probe confirmed unique response.")
                                    .payload(probeUrl)
                                    .requestResponse(result)
                                    .build());
                        }
                    }
                }
            }
            perHostDelay();
        }

        // Probe 2: /_cluster/health — cluster status
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String probeUrl = baseUrl + "/_cluster/health";
            HttpRequestResponse result = sendProbeRequest(original, probeUrl);
            if (result != null && result.response() != null) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    // Require ES-specific: "cluster_name" + "number_of_nodes"
                    if (result.response().statusCode() == 200
                            && resultBody.contains("\"cluster_name\"")
                            && resultBody.contains("\"number_of_nodes\"")) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Elasticsearch Cluster Health Exposed",
                                        Severity.MEDIUM, Confidence.FIRM)
                                .url(probeUrl)
                                .evidence("/_cluster/health endpoint returned cluster metadata "
                                        + "including cluster_name and node count.")
                                .payload(probeUrl)
                                .requestResponse(result)
                                .build());
                    }
                }
            }
            perHostDelay();
        }

        // Probe 3: /_nodes — node info (may leak internal IPs, JVM versions)
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String probeUrl = baseUrl + "/_nodes?filter_path=nodes.*.name,nodes.*.transport_address,nodes.*.version";
            HttpRequestResponse result = sendProbeRequest(original, probeUrl);
            if (result != null && result.response() != null) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    // Require ES-specific marker: "transport_address" (not just "version" which is too generic)
                    if (result.response().statusCode() == 200
                            && resultBody.contains("\"nodes\"")
                            && resultBody.contains("\"transport_address\"")) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Elasticsearch Node Info Exposed — _nodes",
                                        Severity.MEDIUM, Confidence.FIRM)
                                .url(probeUrl)
                                .evidence("/_nodes endpoint returned node metadata "
                                        + "potentially including internal IPs, versions, and JVM info.")
                                .payload(probeUrl)
                                .requestResponse(result)
                                .build());
                    }
                }
            }
            perHostDelay();
        }
    }

    // ── Phase 3: Field/Mapping Exposure ───────────────────────────────────

    private void testFieldExposure(HttpRequestResponse original, InjectableParam target,
                                    String url) throws InterruptedException {
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Test: Inject _source=* or source_includes=* to return all fields
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            HttpRequestResponse result = sendWithExtraParam(original, "_source", "*");
            if (result != null && result.response() != null
                    && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
                if (ResponseGuard.isUsableResponse(result)) {
                    String resultBody = result.response().bodyToString();
                    if (resultBody == null) resultBody = "";

                    int newFieldCount = countNewJsonKeys(baselineBody, resultBody);
                    // Require ES body markers to avoid FP from response non-determinism
                    if (newFieldCount >= 3 && result.response().statusCode() == 200
                            && resultBody.contains("\"hits\"") && resultBody.contains("\"_source\"")) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Elasticsearch Field Exposure — _source=* exposed " + newFieldCount + " extra fields",
                                        Severity.MEDIUM, Confidence.FIRM)
                                .url(url).parameter("_source")
                                .evidence("Injected _source=* returned " + newFieldCount
                                        + " additional JSON keys not in baseline response.")
                                .payload("_source=*")
                                .requestResponse(result)
                                .build());
                    }
                }
            }
            perHostDelay();
        }

        // Test 2: Probe _mapping endpoint for the current index
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String baseUrl = extractBaseUrl(url);
            String index = extractIndexFromUrl(url);
            if (index != null && !index.isEmpty()) {
                String mappingUrl = baseUrl + "/" + index + "/_mapping";
                HttpRequestResponse result = sendProbeRequest(original, mappingUrl);
                if (result != null && result.response() != null) {
                    if (ResponseGuard.isUsableResponse(result)) {
                        String resultBody = result.response().bodyToString();
                        if (resultBody == null) resultBody = "";

                        // Require ES mapping markers: "mappings" + "properties"
                        if (result.response().statusCode() == 200
                                && resultBody.contains("\"mappings\"")
                                && resultBody.contains("\"properties\"")
                                && resultBody.length() > 50) {
                            findingsStore.addFinding(Finding.builder(MODULE_ID,
                                            "Elasticsearch Mapping Exposed — " + index,
                                            Severity.INFO, Confidence.FIRM)
                                    .url(mappingUrl)
                                    .evidence("/_mapping endpoint for index '" + index + "' returned "
                                            + "schema with field definitions.")
                                    .payload(mappingUrl)
                                    .requestResponse(result)
                                    .build());
                        }
                    }
                }
                perHostDelay();
            }
        }
    }

    // ── Phase 4: Script Injection Probe ───────────────────────────────────

    private void testScriptInjection(HttpRequestResponse original, InjectableParam target,
                                      String url) throws InterruptedException {
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Test: Inject a script_fields canary via _source parameter
        // This tests if the ES endpoint allows script execution via query params
        String canaryPayload = target.originalValue + " OR _exists_:_omnistrike_canary_field";
        HttpRequestResponse result = sendPayload(original, target, canaryPayload);
        if (result != null && result.response() != null
                && !(result.response().statusCode() >= 400 && result.response().statusCode() < 500)) {
            if (ResponseGuard.isUsableResponse(result)) {
                String resultBody = result.response().bodyToString();
                if (resultBody == null) resultBody = "";

                // If ES processes the _exists_ query without error and returns different results,
                // it confirms query syntax is being interpreted
                if (result.response().statusCode() == 200
                        && !resultBody.equals(baselineBody)
                        && resultBody.contains("\"hits\"")
                        && !resultBody.contains("\"error\"")) {

                    // Compare hit counts — _exists_ with nonexistent field should return FEWER hits
                    // (OR keeps some, but the nonexistent field clause returns 0).
                    // Require resultHits < baselineHits to avoid FP from natural index churn.
                    int baselineHits = extractTotalHits(baselineBody);
                    int resultHits = extractTotalHits(resultBody);
                    if (resultHits < baselineHits && baselineHits >= 0 && resultHits >= 0
                            && (baselineHits - resultHits) >= 2) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Elasticsearch Query Syntax Interpreted — _exists_ operator",
                                        Severity.MEDIUM, Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("Injected _exists_ query operator changed hit count from "
                                        + baselineHits + " to " + resultHits
                                        + ". Confirms ES query syntax is being parsed from user input.")
                                .payload(canaryPayload)
                                .requestResponse(result)
                                .build());
                    }
                }
            }
        }
        perHostDelay();
    }

    // ── Target Identification ─────────────────────────────────────────────

    private List<InjectableParam> identifyTargets(HttpRequest request) {
        List<InjectableParam> targets = new ArrayList<>();

        for (var param : request.parameters()) {
            String name = param.name().toLowerCase();
            String value = param.value();
            if (value == null || value.isEmpty()) continue;

            // Priority 1: Parameter value contains ES query syntax
            if (ES_SYNTAX_PATTERN.matcher(value).find()) {
                targets.add(0, new InjectableParam(param.name(), value, param.type(), true));
                continue;
            }

            // Priority 2: Parameter name matches known ES parameter names
            if (ES_PARAM_NAMES.contains(name)) {
                targets.add(new InjectableParam(param.name(), value, param.type(), false));
            }
        }

        return targets;
    }

    // ── HTTP Request Sending ──────────────────────────────────────────────

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
     * Send a pre-modified request (used for JSON body injection where we replace the body directly).
     */
    private HttpRequestResponse sendModifiedRequest(HttpRequestResponse original, HttpRequest modified) {
        if (ScanState.isCancelled()) return null;

        try {
            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

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

            HttpRequestResponse result = api.http().sendRequest(probe);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    // ── Utility Methods ──────────────────────────────────────────────────

    /**
     * Extract total hits from an Elasticsearch JSON response.
     * Handles both ES 6.x format ("hits":{"total":N,...}) and
     * ES 7.x+ format ("hits":{"total":{"value":N,"relation":"eq"},...}).
     */
    private int extractTotalHits(String body) {
        if (body == null) return -1;
        // ES 7.x+: "hits":{..."total":{"value":N — anchored to hits context to avoid matching aggregations
        java.util.regex.Matcher m7 = Pattern.compile("\"hits\"\\s*:\\s*\\{\\s*\"total\"\\s*:\\s*\\{\\s*\"value\"\\s*:\\s*(\\d+)").matcher(body);
        if (m7.find()) {
            try { return Integer.parseInt(m7.group(1)); } catch (NumberFormatException e) { return -1; }
        }
        // ES 6.x: "total":N (bare integer after "hits" context)
        java.util.regex.Matcher m6 = Pattern.compile("\"hits\"\\s*:\\s*\\{[^}]*\"total\"\\s*:\\s*(\\d+)").matcher(body);
        if (m6.find()) {
            try { return Integer.parseInt(m6.group(1)); } catch (NumberFormatException e) { return -1; }
        }
        return -1;
    }

    private int countNewJsonKeys(String baseline, String result) {
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

    /**
     * Extract the index name from an ES URL like /myindex/_search?q=test
     */
    private String extractIndexFromUrl(String url) {
        try {
            // Find path after host
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return null;
            int pathStart = url.indexOf('/', schemeEnd + 3);
            if (pathStart < 0) return null;
            String path = url.substring(pathStart);
            // Remove query string
            int qIdx = path.indexOf('?');
            if (qIdx >= 0) path = path.substring(0, qIdx);
            // Split by / and find first non-empty, non-underscore-prefixed segment
            String[] segments = path.split("/");
            for (String seg : segments) {
                if (!seg.isEmpty() && !seg.startsWith("_")) {
                    return seg;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("elasticsearch.perHostDelay", 500);
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

    private static class ESDetection {
        final String evidence;
        ESDetection(String evidence) {
            this.evidence = evidence;
        }
    }

    private static class InjectableParam {
        final String name;
        final String originalValue;
        final HttpParameterType paramType;
        final boolean hasEsSyntax;

        InjectableParam(String name, String originalValue,
                         HttpParameterType paramType, boolean hasEsSyntax) {
            this.name = name;
            this.originalValue = originalValue;
            this.paramType = paramType;
            this.hasEsSyntax = hasEsSyntax;
        }
    }
}
