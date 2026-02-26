package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Host Header Injection Scanner
 * Tests 4 attack scenarios: password reset poisoning (via Collaborator),
 * routing SSRF to internal hosts, duplicate Host headers, and override headers.
 */
public class HostHeaderScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Password reset / auth-related endpoint pattern
    private static final Pattern RESET_ENDPOINT_PATTERN = Pattern.compile(
            "/reset|/forgot|/password|/register|/signup|/login|/auth|/account/recover|/recover|/verify|/activate|/invitation|/invite|/confirm",
            Pattern.CASE_INSENSITIVE
    );

    // Internal host payloads for routing SSRF
    private static final String[] INTERNAL_HOSTS = {
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "169.254.169.254",
            "metadata.google.internal",
            "[::1]",
    };

    // Override headers
    private static final String[] OVERRIDE_HEADERS = {
            "X-Forwarded-Host",
            "X-Host",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "Forwarded",
    };

    @Override
    public String getId() { return "host-header"; }

    @Override
    public String getName() { return "Host Header Injection Scanner"; }

    @Override
    public String getDescription() {
        return "Detects Host header injection: password reset poisoning, routing SSRF, duplicate Host, and override headers (X-Forwarded-Host, etc.).";
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
        String urlPath = extractPath(request.url());

        if (!dedup.markIfNew("host-header", urlPath, "Host")) return Collections.emptyList();

        try {
            String url = request.url();

            // Phase 1: Password reset poisoning (only on reset-like endpoints)
            if (config.getBool("host.oob.enabled", true) && RESET_ENDPOINT_PATTERN.matcher(urlPath).find()) {
                testPasswordResetPoisoning(requestResponse, url);
            }

            // Phase 2: Routing SSRF via Host header
            if (config.getBool("host.internal.enabled", true)) {
                testRoutingSsrf(requestResponse, url);
            }

            // Phase 3: Duplicate Host headers
            testDuplicateHost(requestResponse, url);

            // Phase 4: Override headers
            testOverrideHeaders(requestResponse, url);

        } catch (Exception e) {
            api.logging().logToError("Host header test error on " + urlPath + ": " + e.getMessage());
        }

        return Collections.emptyList();
    }

    // ==================== PHASE 1: PASSWORD RESET POISONING ====================

    private void testPasswordResetPoisoning(HttpRequestResponse original, String url) throws InterruptedException {
        if (collaboratorManager == null || !collaboratorManager.isAvailable()) return;

        AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
        AtomicReference<String> sentHost = new AtomicReference<>();
        String collabPayload = collaboratorManager.generatePayload(
                "host-header", url, "Host", "Password reset poisoning via Host header",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set() — the Collaborator poller
                    // fires on a 5-second interval so this race is rare, but when it happens the 50ms
                    // wait is almost always enough for the sending thread to complete its set() call.
                    for (int _w = 0; _w < 10 && sentRequest.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    findingsStore.addFinding(Finding.builder("host-header",
                                    "Host Header Injection: Password Reset Poisoning",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter("Host")
                            .evidence("Collaborator " + interaction.type().name() + " interaction from "
                                    + interaction.clientIp() + " at " + interaction.timeStamp())
                            .description("Password reset poisoning confirmed. When the Host header was replaced "
                                    + "with a Collaborator domain on a password reset endpoint, the application "
                                    + "generated a reset link pointing to the attacker's domain. A victim clicking "
                                    + "the link would leak their reset token to the attacker.")
                            .remediation("Never use the Host header to generate URLs in emails or password reset links. "
                                    + "Use a hardcoded, server-side configured base URL instead.")
                            .requestResponse(sentRequest.get())  // may be null if callback fires before set() — finding is still reported
                            .payload(sentHost.get())
                            .build());
                    api.logging().logToOutput("[Host Header] Password reset poisoning confirmed! " + url);
                });

        if (collabPayload == null) return;
        sentHost.set(collabPayload);

        try {
            HttpRequest modified = original.request()
                    .withRemovedHeader("Host")
                    .withAddedHeader("Host", collabPayload);
            HttpRequestResponse result = api.http().sendRequest(modified);
            sentRequest.set(result);
        } catch (Exception e) {
            api.logging().logToError("Password reset poisoning test failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== PHASE 2: ROUTING SSRF ====================

    private void testRoutingSsrf(HttpRequestResponse original, String url) throws InterruptedException {
        for (String internalHost : INTERNAL_HOSTS) {
            try {
                HttpRequest modified = original.request()
                        .withRemovedHeader("Host")
                        .withAddedHeader("Host", internalHost);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result == null || result.response() == null) continue;

                // Structural proof: the injected host must appear in a security-sensitive location
                String sensitiveLocation = findHostInSensitiveLocation(result, internalHost);
                if (sensitiveLocation != null) {
                    findingsStore.addFinding(Finding.builder("host-header",
                                    "Host Header Injection: Routing to Internal Host (" + internalHost + ")",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url).parameter("Host")
                            .evidence("Host: " + internalHost + " | " + sensitiveLocation)
                            .description("Setting the Host header to '" + internalHost + "' caused the "
                                    + "injected value to appear in a security-sensitive location in the response. "
                                    + "This confirms the server uses the Host header for routing or URL generation, "
                                    + "enabling potential access to internal services or SSRF.")
                            .remediation("Configure the web server to reject requests with unexpected Host headers. "
                                    + "Use a whitelist of allowed Host values.")
                            .requestResponse(result)
                            .payload(internalHost)
                            .build());
                    return;
                }
            } catch (Exception e) {
                api.logging().logToError("Host routing SSRF test failed for " + internalHost + ": " + e.getMessage());
            }
            perHostDelay();
        }
    }

    /**
     * Checks if the injected host value appears in a security-sensitive location in the response:
     * (1) Location redirect header, (2) absolute URL in body (href=, src=, action=, url(, content="),
     * (3) password reset / account verification link in body.
     * Returns a description of where it was found, or null if not found in any sensitive location.
     */
    private String findHostInSensitiveLocation(HttpRequestResponse result, String injectedValue) {
        // Check Location header
        for (var h : result.response().headers()) {
            if (h.name().equalsIgnoreCase("Location") && h.value().contains(injectedValue)) {
                return "Injected value found in Location redirect header: " + h.value();
            }
        }

        String body = result.response().bodyToString();
        if (body == null || body.isEmpty()) return null;

        // Check absolute URLs in body
        String bodyLower = body.toLowerCase();
        String valueLower = injectedValue.toLowerCase();

        // Pattern: href="...injectedValue...", src="...injectedValue...", action="...injectedValue..."
        String[] urlPrefixes = {"href=", "src=", "action=", "url(", "content=\"http"};
        for (String prefix : urlPrefixes) {
            int searchFrom = 0;
            while (true) {
                int prefixIdx = bodyLower.indexOf(prefix, searchFrom);
                if (prefixIdx < 0) break;
                // Check if the injected value appears within the next 500 chars (URL length limit)
                int endIdx = Math.min(prefixIdx + prefix.length() + 500, body.length());
                String urlSpan = bodyLower.substring(prefixIdx, endIdx);
                if (urlSpan.contains(valueLower)) {
                    // Extract the actual URL snippet for evidence
                    int snippetEnd = Math.min(prefixIdx + prefix.length() + 200, body.length());
                    String snippet = body.substring(prefixIdx, snippetEnd);
                    int quoteEnd = snippet.indexOf('"', prefix.length() + 1);
                    if (quoteEnd < 0) quoteEnd = snippet.indexOf('\'', prefix.length() + 1);
                    if (quoteEnd < 0) quoteEnd = Math.min(100, snippet.length());
                    return "Injected value found in body URL attribute: " + snippet.substring(0, Math.min(quoteEnd + 1, snippet.length()));
                }
                searchFrom = prefixIdx + 1;
            }
        }

        // Check for password reset / verification links containing the injected value
        String[] resetIndicators = {"reset", "verify", "activate", "confirm", "invitation", "token=", "recover"};
        for (String indicator : resetIndicators) {
            int idx = bodyLower.indexOf(indicator);
            if (idx >= 0) {
                // Check nearby context (500 chars around) for the injected value
                int start = Math.max(0, idx - 200);
                int end = Math.min(body.length(), idx + 500);
                if (bodyLower.substring(start, end).contains(valueLower)) {
                    return "Injected value found near password reset/verification link containing '" + indicator + "'";
                }
            }
        }

        return null;
    }

    // ==================== PHASE 3: DUPLICATE HOST HEADERS ====================

    private void testDuplicateHost(HttpRequestResponse original, String url) throws InterruptedException {
        String originalHost = "";
        for (var h : original.request().headers()) {
            if (h.name().equalsIgnoreCase("Host")) {
                originalHost = h.value();
                break;
            }
        }
        if (originalHost.isEmpty()) return;

        // Get baseline to check if attacker string already exists
        String baselineBody = "";
        try {
            HttpRequestResponse baseline = api.http().sendRequest(original.request());
            if (baseline != null && baseline.response() != null) {
                baselineBody = baseline.response().bodyToString();
                if (baselineBody == null) baselineBody = "";
            }
        } catch (Exception e) { /* proceed with empty baseline */ }

        String attackerHost = "attacker.com";
        try {
            // Add a second Host header (keep the original, add attacker's)
            HttpRequest modified = original.request()
                    .withAddedHeader("Host", attackerHost);
            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result == null || result.response() == null) return;

            // Structural proof: injected host must appear in security-sensitive location
            if (result.response().statusCode() < 400) {
                String sensitiveLocation = findHostInSensitiveLocation(result, attackerHost);
                if (sensitiveLocation != null && !baselineBody.contains(attackerHost)) {
                    findingsStore.addFinding(Finding.builder("host-header",
                                    "Host Header Injection: Duplicate Host Header Accepted",
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(url).parameter("Host")
                            .evidence("Original Host: " + originalHost + " | Injected second Host: " + attackerHost
                                    + " | " + sensitiveLocation)
                            .description("The server accepted a request with two Host headers and used the "
                                    + "attacker-controlled value in a security-sensitive location. This can lead "
                                    + "to cache poisoning, password reset poisoning, or SSRF.")
                            .remediation("Configure the web server/reverse proxy to reject requests with "
                                    + "duplicate Host headers.")
                            .requestResponse(result)
                            .payload(attackerHost)
                            .responseEvidence(attackerHost)
                            .build());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Duplicate Host test failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== PHASE 4: OVERRIDE HEADERS ====================

    private void testOverrideHeaders(HttpRequestResponse original, String url) throws InterruptedException {
        String attackerValue = "attacker.com";

        // Get baseline response for comparison
        String baselineBody = "";
        try {
            HttpRequestResponse baseline = api.http().sendRequest(original.request());
            if (baseline != null && baseline.response() != null) {
                baselineBody = baseline.response().bodyToString();
                if (baselineBody == null) baselineBody = "";
            }
        } catch (Exception e) { /* proceed with empty baseline */ }

        for (String header : OVERRIDE_HEADERS) {
            try {
                // Test 1: Simple reflection test
                String headerValue = header.equals("Forwarded")
                        ? "host=attacker.com"
                        : attackerValue;

                HttpRequest modified = original.request()
                        .withRemovedHeader(header)
                        .withAddedHeader(header, headerValue);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result != null && result.response() != null && result.response().statusCode() < 400) {
                    // Structural proof: injected value must appear in security-sensitive location
                    String sensitiveLocation = findHostInSensitiveLocation(result, attackerValue);
                    if (sensitiveLocation != null && !baselineBody.contains(attackerValue)) {
                        findingsStore.addFinding(Finding.builder("host-header",
                                        "Host Header Override via " + header,
                                        Severity.MEDIUM, Confidence.FIRM)
                                .url(url).parameter(header)
                                .evidence(header + ": " + headerValue + " | " + sensitiveLocation)
                                .description("The override header '" + header + "' is processed by the server "
                                        + "and its value appears in a security-sensitive location. This can be used "
                                        + "for cache poisoning, password reset poisoning, or open redirect attacks.")
                                .remediation("Ignore or strip override headers unless they come from a trusted "
                                        + "reverse proxy. Configure the web server to only trust these headers "
                                        + "from specific upstream IPs.")
                                .requestResponse(result)
                                .payload(headerValue)
                                .responseEvidence(attackerValue)
                                .build());
                    }
                }
                perHostDelay();

                // Test 2: OOB test via Collaborator
                if (config.getBool("host.oob.enabled", true)
                        && collaboratorManager != null && collaboratorManager.isAvailable()) {
                    AtomicReference<HttpRequestResponse> oobSent = new AtomicReference<>();
                    AtomicReference<String> oobPayloadRef = new AtomicReference<>();
                    String collabPayload = collaboratorManager.generatePayload(
                            "host-header", url, header, "Host override OOB via " + header,
                            interaction -> {
                                findingsStore.addFinding(Finding.builder("host-header",
                                                "Host Header Override (OOB Confirmed) via " + header,
                                                Severity.CRITICAL, Confidence.CERTAIN)
                                        .url(url).parameter(header)
                                        .evidence("Collaborator " + interaction.type().name() + " interaction from "
                                                + interaction.clientIp() + " via " + header)
                                        .description("The server followed the override header '" + header + "' "
                                                + "and made an external request to the Collaborator server. "
                                                + "This confirms the header is actively used for routing or URL generation.")
                                        .remediation("Strip or ignore override headers from untrusted sources.")
                                        .requestResponse(oobSent.get())
                                        .payload(oobPayloadRef.get())
                                        .build());
                            });

                    if (collabPayload != null) {
                        String oobHeaderValue = header.equals("Forwarded")
                                ? "host=" + collabPayload
                                : collabPayload;
                        oobPayloadRef.set(oobHeaderValue);
                        HttpRequest oobModified = original.request()
                                .withRemovedHeader(header)
                                .withAddedHeader(header, oobHeaderValue);
                        oobSent.set(api.http().sendRequest(oobModified));
                        perHostDelay();
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Override header test failed for " + header + ": " + e.getMessage());
            }
        }
    }

    // ==================== HELPERS ====================

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("host.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }
}
