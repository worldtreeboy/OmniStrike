package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Server-Side Prototype Pollution Scanner
 * Targets JSON-body requests only. Injects __proto__ and constructor.prototype
 * pollution payloads, checks if canary values persist across subsequent requests
 * (indicating server-side object pollution).
 */
public class PrototypePollutionScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    @Override
    public String getId() { return "proto-pollution"; }

    @Override
    public String getName() { return "Server-Side Prototype Pollution Scanner"; }

    @Override
    public String getDescription() {
        return "Detects server-side prototype pollution via __proto__ and constructor.prototype injection in JSON bodies, with persistence checks and known gadget testing.";
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
        HttpRequest request = requestResponse.request();

        // Gate: only process JSON body requests
        if (!isJsonRequest(request)) return Collections.emptyList();

        String body = request.bodyToString();
        if (body == null || body.isBlank()) return Collections.emptyList();

        // Verify it parses as JSON object
        try {
            com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(body);
            if (!el.isJsonObject()) return Collections.emptyList();
        } catch (Exception e) {
            return Collections.emptyList();
        }

        String urlPath = extractPath(request.url());
        if (!dedup.markIfNew("proto-pollution", urlPath, "__proto__")) return Collections.emptyList();

        try {
            String url = request.url();

            // Phase 1: __proto__ detection
            testProtoInjection(requestResponse, url);

            // Phase 2: constructor.prototype alternative vector
            testConstructorPrototype(requestResponse, url);

            // Phase 3: Known gadgets (Express/Fastify)
            if (config.getBool("proto.gadgets.enabled", true)) {
                testKnownGadgets(requestResponse, url);
            }

        } catch (Exception e) {
            api.logging().logToError("Prototype pollution test error on " + urlPath + ": " + e.getMessage());
        }

        return Collections.emptyList();
    }

    // ==================== PHASE 1: __PROTO__ INJECTION ====================

    private void testProtoInjection(HttpRequestResponse original, String url) throws InterruptedException {
        String canary = generateCanary();
        String canaryKey = generateCanaryKey(); // Random key per scan

        // Inject __proto__ with canary
        String pollutedBody = injectProtoPayload(original.request().bodyToString(),
                "__proto__", canaryKey, canary);
        if (pollutedBody == null) return;

        HttpRequestResponse result = sendWithBody(original, pollutedBody);
        if (result == null || result.response() == null) return;

        // Discard if server rejected the payload (400/422 = input validation)
        int statusCode = result.response().statusCode();
        if (statusCode == 400 || statusCode == 422) return;

        String responseBody = result.response().bodyToString();

        // Discard if the app echoes back the entire request body (check non-proto properties)
        if (responseBody != null && isEchoingRequestBody(original.request().bodyToString(), responseBody)) return;

        // Check persistence: send a clean GET to the same host
        boolean persisted = checkPersistence(original, canary);

        if (persisted) {
            findingsStore.addFinding(Finding.builder("proto-pollution",
                            "Server-Side Prototype Pollution Confirmed (__proto__)",
                            Severity.HIGH, Confidence.CERTAIN)
                    .url(url).parameter("__proto__." + canaryKey)
                    .evidence("Canary key: " + canaryKey + " | Canary value: " + canary
                            + " | Injected via __proto__ | Canary persisted in follow-up request")
                    .description("Server-side prototype pollution confirmed. The injected __proto__ property "
                            + "persisted across requests, meaning the server's Object.prototype was polluted. "
                            + "This can lead to denial of service, authentication bypass, or remote code "
                            + "execution depending on how the polluted properties are used.")
                    .remediation("Use Object.create(null) for user-controlled objects. Use Map instead of plain "
                            + "objects. Filter __proto__ and constructor keys from user input. Use --frozen-intrinsics "
                            + "in Node.js.")
                    .payload(pollutedBody)
                    .responseEvidence(canary)
                    .requestResponse(result)
                    .build());

            // Cleanup and verify
            if (config.getBool("proto.cleanupEnabled", true)) {
                cleanupPollution(original, canaryKey);
                // Verify cleanup
                if (checkPersistence(original, canary)) {
                    api.logging().logToOutput("[ProtoPollution] WARNING: Cleanup failed for " + canaryKey
                            + " — canary still persists after cleanup");
                }
            }
        }
        // Note: Same-request reflection without persistence is NOT reported — it's just
        // normal JSON serialization echoing back the __proto__ object, not actual pollution.
        perHostDelay();
    }

    // ==================== PHASE 2: CONSTRUCTOR.PROTOTYPE ====================

    private void testConstructorPrototype(HttpRequestResponse original, String url) throws InterruptedException {
        String canary = generateCanary();
        String canaryKey = generateCanaryKey();

        // Build constructor.prototype payload manually
        String body = original.request().bodyToString();
        try {
            com.google.gson.JsonObject root = com.google.gson.JsonParser.parseString(body).getAsJsonObject();
            com.google.gson.JsonObject prototype = new com.google.gson.JsonObject();
            prototype.addProperty(canaryKey, canary);
            com.google.gson.JsonObject constructor = new com.google.gson.JsonObject();
            constructor.add("prototype", prototype);
            root.add("constructor", constructor);

            String pollutedBody = new com.google.gson.Gson().toJson(root);
            HttpRequestResponse result = sendWithBody(original, pollutedBody);
            if (result == null || result.response() == null) return;

            // Discard if server rejected the payload
            int statusCode = result.response().statusCode();
            if (statusCode == 400 || statusCode == 422) return;

            // Discard if app echoes back the entire request body
            String responseBody = result.response().bodyToString();
            if (responseBody != null && isEchoingRequestBody(body, responseBody)) return;

            boolean persisted = checkPersistence(original, canary);
            if (persisted) {
                findingsStore.addFinding(Finding.builder("proto-pollution",
                                "Server-Side Prototype Pollution Confirmed (constructor.prototype)",
                                Severity.HIGH, Confidence.CERTAIN)
                        .url(url).parameter("constructor.prototype." + canaryKey)
                        .evidence("Canary key: " + canaryKey + " | Canary value: " + canary
                                + " | Injected via constructor.prototype | Persisted")
                        .description("Server-side prototype pollution confirmed via constructor.prototype vector. "
                                + "This bypasses __proto__ filters but achieves the same effect.")
                        .remediation("Filter both __proto__ and constructor keys from user input. "
                                + "Use Object.create(null) or Map for user-controlled objects.")
                        .payload(pollutedBody)
                        .responseEvidence(canary)
                        .requestResponse(result)
                        .build());

                if (config.getBool("proto.cleanupEnabled", true)) {
                    cleanupPollution(original, canaryKey);
                    if (checkPersistence(original, canary)) {
                        api.logging().logToOutput("[ProtoPollution] WARNING: Cleanup failed for constructor.prototype." + canaryKey);
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Constructor.prototype test failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== PHASE 3: KNOWN GADGETS ====================

    private void testKnownGadgets(HttpRequestResponse original, String url) throws InterruptedException {
        // Gadget 1: __proto__.status = 510 (Express/Fastify default status override)
        testStatusGadget(original, url);

        // Gadget 2: __proto__.content-type = text/omnistrike
        testContentTypeGadget(original, url);

        // Gadget 3: __proto__["json spaces"] = 10 (Express JSON formatting)
        testJsonSpacesGadget(original, url);
    }

    private void testStatusGadget(HttpRequestResponse original, String url) throws InterruptedException {
        // Get baseline status
        HttpRequestResponse baseline;
        try {
            baseline = api.http().sendRequest(original.request());
        } catch (Exception e) { return; }
        if (baseline == null || baseline.response() == null) return;
        int baselineStatus = baseline.response().statusCode();

        // Skip if baseline already errors — can't distinguish pollution from existing issues
        if (baselineStatus >= 400) return;

        // Inject __proto__.status = 510
        String pollutedBody = injectProtoPayload(original.request().bodyToString(),
                "__proto__", "status", "510");
        if (pollutedBody == null) return;

        HttpRequestResponse result = sendWithBody(original, pollutedBody);
        if (result == null || result.response() == null) return;
        perHostDelay();

        // Send clean probe to check if status changed globally
        try {
            HttpRequestResponse probe = api.http().sendRequest(original.request());
            if (probe != null && probe.response() != null && probe.response().statusCode() == 510
                    && baselineStatus != 510) {
                findingsStore.addFinding(Finding.builder("proto-pollution",
                                "Prototype Pollution Gadget: Status Code Override",
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter("__proto__.status")
                        .evidence("Injected __proto__.status=510 | Follow-up probe returned HTTP 510 "
                                + "(baseline was " + baselineStatus + ")")
                        .description("Prototype pollution gadget confirmed. The __proto__.status property "
                                + "was injected and subsequent responses returned HTTP 510, indicating "
                                + "the Express/Fastify default status was overridden via prototype pollution.")
                        .payload(pollutedBody)
                        .responseEvidence("510")
                        .requestResponse(result)
                        .build());

                // Cleanup
                if (config.getBool("proto.cleanupEnabled", true)) {
                    cleanupPollution(original, "status");
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Status gadget probe failed: " + e.getMessage());
        }
        perHostDelay();
    }

    private void testContentTypeGadget(HttpRequestResponse original, String url) throws InterruptedException {
        String marker = "text/omnistrike";

        // Get baseline content-type for comparison
        String baselineContentType = null;
        try {
            HttpRequestResponse baselineProbe = api.http().sendRequest(original.request());
            if (baselineProbe != null && baselineProbe.response() != null) {
                for (var h : baselineProbe.response().headers()) {
                    if (h.name().equalsIgnoreCase("Content-Type")) {
                        baselineContentType = h.value();
                        break;
                    }
                }
            }
        } catch (Exception e) { /* proceed */ }

        // If baseline already contains marker, skip (should never happen but guard)
        if (baselineContentType != null && baselineContentType.contains(marker)) return;

        String pollutedBody = injectProtoPayload(original.request().bodyToString(),
                "__proto__", "content-type", marker);
        if (pollutedBody == null) return;

        HttpRequestResponse result = sendWithBody(original, pollutedBody);
        if (result == null || result.response() == null) return;
        perHostDelay();

        // Check if follow-up response has the modified content-type
        try {
            HttpRequestResponse probe = api.http().sendRequest(original.request());
            if (probe != null && probe.response() != null) {
                for (var h : probe.response().headers()) {
                    if (h.name().equalsIgnoreCase("Content-Type") && h.value().contains(marker)) {
                        findingsStore.addFinding(Finding.builder("proto-pollution",
                                        "Prototype Pollution Gadget: Content-Type Override",
                                        Severity.MEDIUM, Confidence.CERTAIN)
                                .url(url).parameter("__proto__.content-type")
                                .evidence("Injected __proto__.content-type=" + marker
                                        + " | Follow-up response Content-Type confirmed changed to: " + h.value()
                                        + " (baseline was: " + (baselineContentType != null ? baselineContentType : "unknown") + ")")
                                .description("Prototype pollution gadget confirmed. The Content-Type header was "
                                        + "overridden via __proto__ pollution. This can be leveraged for XSS by setting "
                                        + "Content-Type to text/html on JSON endpoints.")
                                .payload(pollutedBody)
                                .responseEvidence(marker)
                                .requestResponse(result)
                                .build());

                        if (config.getBool("proto.cleanupEnabled", true)) {
                            cleanupPollution(original, "content-type");
                        }
                        break;
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Content-Type gadget probe failed: " + e.getMessage());
        }
        perHostDelay();
    }

    private void testJsonSpacesGadget(HttpRequestResponse original, String url) throws InterruptedException {
        // Get baseline JSON formatting
        HttpRequestResponse baseline;
        try {
            baseline = api.http().sendRequest(original.request());
        } catch (Exception e) { return; }
        if (baseline == null || baseline.response() == null) return;
        String baselineBody = baseline.response().bodyToString();
        if (baselineBody == null || !baselineBody.trim().startsWith("{")) return; // Only test JSON responses

        // Count leading indentation in baseline
        boolean baselineHasIndent = baselineBody.contains("\n  ") || baselineBody.contains("\n\t");

        // Inject __proto__["json spaces"] = 10 (Express json spaces gadget)
        String pollutedBody = injectProtoPayload(original.request().bodyToString(),
                "__proto__", "json spaces", "10");
        if (pollutedBody == null) return;

        HttpRequestResponse result = sendWithBody(original, pollutedBody);
        if (result == null || result.response() == null) return;
        if (result.response().statusCode() == 400 || result.response().statusCode() == 422) return;
        perHostDelay();

        // Check if subsequent JSON response has altered indentation
        try {
            HttpRequestResponse probe = api.http().sendRequest(original.request());
            if (probe != null && probe.response() != null) {
                String probeBody = probe.response().bodyToString();
                if (probeBody != null && probeBody.trim().startsWith("{")) {
                    // Check for 10-space indentation (our injected value)
                    boolean hasWideIndent = probeBody.contains("\n          "); // 10 spaces
                    if (hasWideIndent && !baselineHasIndent) {
                        findingsStore.addFinding(Finding.builder("proto-pollution",
                                        "Prototype Pollution Gadget: JSON Spaces Override (Express)",
                                        Severity.MEDIUM, Confidence.CERTAIN)
                                .url(url).parameter("__proto__[\"json spaces\"]")
                                .evidence("Injected __proto__[\"json spaces\"]=10 | Follow-up JSON response "
                                        + "now has 10-space indentation (baseline had no indentation)")
                                .description("Prototype pollution gadget confirmed. The Express 'json spaces' "
                                        + "setting was overridden via __proto__, changing JSON formatting. "
                                        + "This confirms prototype pollution is effective on this Express app.")
                                .payload(pollutedBody)
                                .requestResponse(result)
                                .build());

                        if (config.getBool("proto.cleanupEnabled", true)) {
                            cleanupPollution(original, "json spaces");
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("JSON spaces gadget probe failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== HELPERS ====================

    private boolean isJsonRequest(HttpRequest request) {
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                return h.value().contains("application/json");
            }
        }
        return false;
    }

    /**
     * Inject a __proto__ (or other root-level key) payload into a JSON body.
     */
    private String injectProtoPayload(String jsonBody, String protoKey, String propertyName, String propertyValue) {
        try {
            com.google.gson.JsonObject root = com.google.gson.JsonParser.parseString(jsonBody).getAsJsonObject();
            com.google.gson.JsonObject protoObj = new com.google.gson.JsonObject();
            // Try to set as number if it looks like one, otherwise string
            try {
                int numVal = Integer.parseInt(propertyValue);
                protoObj.addProperty(propertyName, numVal);
            } catch (NumberFormatException e) {
                protoObj.addProperty(propertyName, propertyValue);
            }
            root.add(protoKey, protoObj);
            return new com.google.gson.Gson().toJson(root);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Send a clean GET probe to the same host to check if canary persists.
     */
    private boolean checkPersistence(HttpRequestResponse original, String canary) {
        try {
            // Probe with the same method as the original request — POST endpoints often
            // return 404/405 for GET, causing false negatives. Send a clean body-less
            // request using the original method and all original headers (auth, cookies).
            String probeUrl = original.request().url();
            String method = original.request().method();
            HttpRequest probe;
            if ("GET".equalsIgnoreCase(method)) {
                probe = HttpRequest.httpRequestFromUrl(probeUrl);
            } else {
                // Re-send the original request unchanged (with the original JSON body)
                // so the endpoint routes correctly. The canary detection checks the response.
                probe = original.request();
            }

            HttpRequestResponse result = api.http().sendRequest(probe);
            if (result != null && result.response() != null) {
                String body = result.response().bodyToString();
                if (body != null && body.contains(canary)) return true;
                // Also check headers
                for (var h : result.response().headers()) {
                    if (h.value().contains(canary)) return true;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Persistence probe failed: " + e.getMessage());
        }
        return false;
    }

    /**
     * Send a cleanup request setting the polluted property to null.
     */
    private void cleanupPollution(HttpRequestResponse original, String propertyName) {
        try {
            com.google.gson.JsonObject root = com.google.gson.JsonParser.parseString(
                    original.request().bodyToString()).getAsJsonObject();
            com.google.gson.JsonObject protoObj = new com.google.gson.JsonObject();
            protoObj.add(propertyName, com.google.gson.JsonNull.INSTANCE);
            root.add("__proto__", protoObj);
            String cleanupBody = new com.google.gson.Gson().toJson(root);
            sendWithBody(original, cleanupBody);
            api.logging().logToOutput("[ProtoPollution] Sent cleanup for property: " + propertyName);
        } catch (Exception e) {
            api.logging().logToError("Prototype pollution cleanup failed: " + e.getMessage());
        }
    }

    private HttpRequestResponse sendWithBody(HttpRequestResponse original, String body) {
        try {
            HttpRequest modified = original.request().withBody(body);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private String generateCanary() {
        return "omniproto" + String.format("%06x", ThreadLocalRandom.current().nextInt(0, 0xFFFFFF));
    }

    /**
     * Generate a random canary key to avoid matching cached or coincidental content.
     */
    private String generateCanaryKey() {
        return "omnistrike_canary_" + String.format("%04x", ThreadLocalRandom.current().nextInt(0, 0xFFFF));
    }

    /**
     * Check if the application echoes back the entire request body.
     * If non-proto properties from the original body also appear in the response,
     * any canary match is meaningless (the app just mirrors input).
     */
    private boolean isEchoingRequestBody(String requestBody, String responseBody) {
        if (requestBody == null || responseBody == null) return false;
        try {
            com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(requestBody);
            if (!el.isJsonObject()) return false;
            com.google.gson.JsonObject obj = el.getAsJsonObject();
            int echoedCount = 0;
            int totalProps = 0;
            for (String key : obj.keySet()) {
                if (key.equals("__proto__") || key.equals("constructor")) continue;
                totalProps++;
                com.google.gson.JsonElement val = obj.get(key);
                if (val.isJsonPrimitive()) {
                    String valStr = val.getAsString();
                    if (valStr.length() > 3 && responseBody.contains(valStr)) {
                        echoedCount++;
                    }
                }
            }
            // If more than half of non-proto properties are echoed, app is mirroring input
            return totalProps > 0 && echoedCount > totalProps / 2;
        } catch (Exception e) {
            return false;
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
        int delay = config.getInt("proto.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }
}
