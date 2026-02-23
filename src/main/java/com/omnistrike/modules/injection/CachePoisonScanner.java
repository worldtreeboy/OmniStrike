package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;

import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Web Cache Poisoning Scanner
 * Injects canary values in unkeyed headers and query parameters, checks for
 * reflection in responses and cacheability indicators to detect cache poisoning vectors.
 */
public class CachePoisonScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Unkeyed headers commonly ignored by caches
    private static final String[] UNKEYED_HEADERS = {
            "X-Forwarded-Host",
            "X-Forwarded-Scheme",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-Port",
            "X-Host",
            "X-Forwarded-Server",
            "True-Client-IP",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Forwarded-Proto",
            "X-Forwarded-Prefix",
            "X-Custom-IP-Authorization",
            "X-Original-Host",
            "X-Proxy-URL",
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-Forwarded-Path",
            "Forwarded",
            "X-Client-IP",
            "CF-Connecting-IP",
            "Fastly-Client-IP",
            "X-Azure-ClientIP",
            "X-Cluster-Client-IP",
            "X-Original-Forwarded-For",
            "Via",
            "Transfer-Encoding",
            "X-Wap-Profile",
            "X-Arbitrary",
            "X-HTTP-DestinationURL",
    };

    // Unkeyed query parameters commonly ignored by caches
    private static final String[] UNKEYED_PARAMS = {
            "_omnistrike",
            "utm_content",
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_term",
            "fbclid",
            "gclid",
            "cb",
            "dnt",
            "ref",
            "mc_cid",
            "mc_eid",
            "msclkid",
            "twclid",
            "li_fat_id",
            "_ga",
            "_gl",
            "__cf_chl_jschl_tk__",
            "__cf_chl_captcha_tk__",
            "_hsenc",
            "_hsmi",
            "_openstat",
            "yclid",
            "origin",
            "cache_buster",
            "nocache",
            "_dc",
            "t",
    };

    @Override
    public String getId() { return "cache-poison"; }

    @Override
    public String getName() { return "Web Cache Poisoning Scanner"; }

    @Override
    public String getDescription() {
        return "Detects web cache poisoning via unkeyed headers and parameters — reflection detection, cacheability analysis, and optional poison confirmation.";
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
        String url = request.url();

        // Test unkeyed headers
        if (config.getBool("cache.headers.enabled", true)) {
            for (String header : UNKEYED_HEADERS) {
                if (!dedup.markIfNew("cache-poison", urlPath, header)) continue;
                try {
                    testUnkeyedHeader(requestResponse, header, url);
                } catch (Exception e) {
                    api.logging().logToError("Cache poison header test error (" + header + "): " + e.getMessage());
                }
            }
        }

        // Test unkeyed query parameters
        if (config.getBool("cache.params.enabled", true)) {
            for (String param : UNKEYED_PARAMS) {
                if (!dedup.markIfNew("cache-poison", urlPath, "param:" + param)) continue;
                try {
                    testUnkeyedParam(requestResponse, param, url);
                } catch (Exception e) {
                    api.logging().logToError("Cache poison param test error (" + param + "): " + e.getMessage());
                }
            }
        }

        return Collections.emptyList();
    }

    // ==================== HEADER REFLECTION TEST ====================

    private void testUnkeyedHeader(HttpRequestResponse original, String headerName, String url) throws InterruptedException {
        String canary = generateCanary();

        // Phase 1: Reflection detection
        HttpRequestResponse result = sendWithHeader(original, headerName, canary);
        if (result == null || result.response() == null) return;

        boolean reflected = isCanaryReflected(result, canary);
        if (!reflected) {
            perHostDelay();
            return;
        }

        // Phase 2: Cacheability check
        CacheInfo cacheInfo = analyzeCacheability(result);

        // Phase 3: Confirm cache poisoning (optional)
        if (cacheInfo.cacheable && config.getBool("cache.confirmPoison", false)) {
            boolean confirmed = confirmPoisoning(original, headerName, url);
            if (confirmed) {
                findingsStore.addFinding(Finding.builder("cache-poison",
                                "Web Cache Poisoning Confirmed via " + headerName,
                                Severity.HIGH, Confidence.CERTAIN)
                        .url(url).parameter(headerName)
                        .evidence("Canary: " + canary + " | Header: " + headerName
                                + " | Cache indicators: " + cacheInfo.headerSummary
                                + " | Canary persisted in clean follow-up request")
                        .description("Web cache poisoning confirmed. The unkeyed header '" + headerName
                                + "' is reflected in the response and the poisoned response was served "
                                + "from cache to a subsequent clean request.")
                        .remediation("Include the header in the cache key (Vary header), or strip/ignore "
                                + "unkeyed headers before processing. Review CDN/cache configuration.")
                        .requestResponse(result)
                        .build());
                perHostDelay();
                return;
            }
        }

        // Report based on reflection + cacheability
        if (cacheInfo.cacheable) {
            findingsStore.addFinding(Finding.builder("cache-poison",
                            "Potential Web Cache Poisoning via " + headerName,
                            Severity.MEDIUM, Confidence.FIRM)
                    .url(url).parameter(headerName)
                    .evidence("Canary: " + canary + " | Header: " + headerName
                            + " | Reflected: yes | Cache indicators: " + cacheInfo.headerSummary)
                    .description("The unkeyed header '" + headerName + "' is reflected in the response "
                            + "and the response appears cacheable. If this header is not part of the "
                            + "cache key, an attacker can poison the cache with malicious content.")
                    .remediation("Include the header in the cache key (Vary header), or strip/ignore "
                            + "unkeyed headers. Test with cache.confirmPoison=true for confirmation.")
                    .requestResponse(result)
                    .build());
        } else {
            findingsStore.addFinding(Finding.builder("cache-poison",
                            "Unkeyed Header Reflected (Not Cacheable): " + headerName,
                            Severity.INFO, Confidence.TENTATIVE)
                    .url(url).parameter(headerName)
                    .evidence("Canary: " + canary + " | Header: " + headerName
                            + " | Reflected: yes | Cache indicators: " + cacheInfo.headerSummary)
                    .description("The unkeyed header '" + headerName + "' is reflected in the response "
                            + "but the response does not appear cacheable. This may still be exploitable "
                            + "depending on intermediary cache configurations.")
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PARAM REFLECTION TEST ====================

    private void testUnkeyedParam(HttpRequestResponse original, String paramName, String url) throws InterruptedException {
        String canary = generateCanary();

        // Append the unkeyed param to the URL
        HttpRequestResponse result = sendWithQueryParam(original, paramName, canary);
        if (result == null || result.response() == null) return;

        boolean reflected = isCanaryReflected(result, canary);
        if (!reflected) {
            perHostDelay();
            return;
        }

        CacheInfo cacheInfo = analyzeCacheability(result);

        if (cacheInfo.cacheable) {
            findingsStore.addFinding(Finding.builder("cache-poison",
                            "Potential Cache Poisoning via Unkeyed Parameter: " + paramName,
                            Severity.MEDIUM, Confidence.FIRM)
                    .url(url).parameter(paramName)
                    .evidence("Canary: " + canary + " | Param: " + paramName
                            + " | Reflected: yes | Cache indicators: " + cacheInfo.headerSummary)
                    .description("The query parameter '" + paramName + "' is reflected in the cacheable "
                            + "response but may not be part of the cache key. An attacker can poison "
                            + "the cached response by adding this parameter.")
                    .remediation("Include all reflected query parameters in the cache key, or strip "
                            + "unknown parameters before caching.")
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== CACHE POISONING CONFIRMATION ====================

    /**
     * Confirm cache poisoning by:
     * 1. Sending a poisoned request (header with new canary)
     * 2. Sending a clean request to the same URL
     * 3. Checking if the canary persists in the clean response
     */
    private boolean confirmPoisoning(HttpRequestResponse original, String headerName, String url) throws InterruptedException {
        String confirmCanary = generateCanary();

        // Send poisoned request
        sendWithHeader(original, headerName, confirmCanary);
        perHostDelay();

        // Send clean request (no injected header)
        try {
            HttpRequestResponse cleanResult = api.http().sendRequest(original.request());
            if (cleanResult != null && cleanResult.response() != null) {
                return isCanaryReflected(cleanResult, confirmCanary);
            }
        } catch (Exception e) {
            api.logging().logToError("Cache poison confirmation failed: " + e.getMessage());
        }
        return false;
    }

    // ==================== CACHEABILITY ANALYSIS ====================

    private CacheInfo analyzeCacheability(HttpRequestResponse response) {
        boolean cacheable = false;
        List<String> indicators = new ArrayList<>();

        for (var h : response.response().headers()) {
            String name = h.name().toLowerCase();
            String value = h.value().toLowerCase().trim();

            switch (name) {
                case "cache-control":
                    if (value.contains("no-store") || value.contains("private")) {
                        indicators.add("Cache-Control: " + h.value() + " (not cacheable)");
                    } else if (value.contains("public") || value.contains("max-age")
                            || value.contains("s-maxage")) {
                        cacheable = true;
                        indicators.add("Cache-Control: " + h.value() + " (cacheable)");
                    }
                    break;
                case "pragma":
                    if (value.contains("no-cache")) {
                        indicators.add("Pragma: no-cache");
                    }
                    break;
                case "age":
                    cacheable = true;
                    indicators.add("Age: " + h.value() + " (served from cache)");
                    break;
                case "x-cache":
                    if (value.contains("hit")) {
                        cacheable = true;
                        indicators.add("X-Cache: " + h.value() + " (cached)");
                    } else if (value.contains("miss")) {
                        indicators.add("X-Cache: " + h.value() + " (not cached)");
                    }
                    break;
                case "cf-cache-status":
                    if (value.contains("hit")) {
                        cacheable = true;
                        indicators.add("CF-Cache-Status: " + h.value() + " (cached)");
                    } else if (value.contains("miss") || value.contains("dynamic") || value.contains("bypass")) {
                        indicators.add("CF-Cache-Status: " + h.value() + " (not cached)");
                    }
                    break;
                case "x-cache-status":
                    cacheable = true;
                    indicators.add("X-Cache-Status: " + h.value());
                    break;
                case "vary":
                    indicators.add("Vary: " + h.value());
                    break;
                case "expires":
                    if (!value.equals("0") && !value.equals("-1")) {
                        cacheable = true;
                        indicators.add("Expires: " + h.value());
                    }
                    break;
            }
        }

        if (indicators.isEmpty()) {
            indicators.add("No cache indicators found");
        }

        return new CacheInfo(cacheable, String.join(" | ", indicators));
    }

    // ==================== HELPERS ====================

    private HttpRequestResponse sendWithHeader(HttpRequestResponse original, String headerName, String value) {
        try {
            HttpRequest modified = original.request()
                    .withRemovedHeader(headerName)
                    .withAddedHeader(headerName, value);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private HttpRequestResponse sendWithQueryParam(HttpRequestResponse original, String paramName, String value) {
        try {
            HttpRequest modified = original.request()
                    .withUpdatedParameters(
                            burp.api.montoya.http.message.params.HttpParameter.urlParameter(paramName, PayloadEncoder.encode(value)));
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isCanaryReflected(HttpRequestResponse response, String canary) {
        // Skip error responses — servers often echo input in error pages
        int statusCode = response.response().statusCode();
        if (statusCode >= 400) return false;

        // Check response body
        String body = response.response().bodyToString();
        if (body != null && body.contains(canary)) return true;

        // Check response headers
        for (var h : response.response().headers()) {
            if (h.value().contains(canary)) return true;
        }
        return false;
    }

    private String generateCanary() {
        return "omni" + String.format("%06x", ThreadLocalRandom.current().nextInt(0, 0xFFFFFF));
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
        int delay = config.getInt("cache.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }

    // Inner class for cache analysis result
    private static class CacheInfo {
        final boolean cacheable;
        final String headerSummary;

        CacheInfo(boolean cacheable, String headerSummary) {
            this.cacheable = cacheable;
            this.headerSummary = headerSummary;
        }
    }
}
