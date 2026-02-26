package com.omnistrike.modules.recon;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.SharedDataBus;
import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE 2: Hidden Endpoint Finder
 * Extracts API endpoints and paths from JavaScript, HTML, and JSON responses.
 */
public class HiddenEndpointFinder implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private SharedDataBus dataBus;

    // Discovered endpoints: path -> EndpointInfo
    private final ConcurrentHashMap<String, EndpointInfo> endpoints = new ConcurrentHashMap<>();

    private static final Set<String> IGNORED_EXTENSIONS = Set.of(
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".map", ".bmp", ".webp"
    );

    // Compiled regex patterns for endpoint extraction
    private static final Pattern[] JS_PATTERNS = {
            Pattern.compile("[\"'](/[a-zA-Z0-9_/\\-\\.]{2,})[\"']"),
            Pattern.compile("https?://[a-zA-Z0-9._\\-]+(/[a-zA-Z0-9_/\\-\\.?&=]*)"),
            Pattern.compile("[\"'](api/[a-zA-Z0-9_/\\-\\.]+)[\"']"),
            Pattern.compile("[\"'](v[0-9]+/[a-zA-Z0-9_/\\-\\.]+)[\"']"),
            Pattern.compile("fetch\\([\"']([^\"']+)[\"']\\)"),
            Pattern.compile("axios\\.(get|post|put|delete|patch)\\([\"']([^\"']+)[\"']\\)"),
            Pattern.compile("path:\\s*[\"']([^\"']+)[\"']"),
            Pattern.compile("route\\([\"']([^\"']+)[\"']\\)"),
            Pattern.compile("[\"'](/graphql[a-zA-Z0-9_/\\-\\.]*)[\"']"),
            Pattern.compile("\\.open\\([\"'][A-Z]+[\"'],\\s*[\"']([^\"']+)[\"']"),
            Pattern.compile("url:\\s*[\"']([^\"']+)[\"']"),
            Pattern.compile("endpoint:\\s*[\"']([^\"']+)[\"']"),
            Pattern.compile("href:\\s*[\"']([^\"']+)[\"']"),
    };

    private static final Pattern HTML_ATTR_PATTERN = Pattern.compile(
            "(?:href|src|action|data-url|data-api|data-endpoint)\\s*=\\s*[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern JSON_URL_PATTERN = Pattern.compile(
            "\"([^\"]*(?:/api/|/v[0-9]+/)[^\"]*)\""
    );

    public static class EndpointInfo {
        public final String path;
        public volatile String sourceUrl;
        public volatile String method;
        public volatile boolean inSitemap;

        public EndpointInfo(String path, String sourceUrl, String method) {
            this.path = path;
            this.sourceUrl = sourceUrl;
            this.method = method;
            this.inSitemap = false;
        }
    }

    @Override
    public String getId() { return "endpoint-finder"; }

    @Override
    public String getName() { return "Hidden Endpoint Finder"; }

    @Override
    public String getDescription() {
        return "Extracts API endpoints and paths from JavaScript, HTML, and JSON responses.";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.RECON; }

    @Override
    public boolean isPassive() { return true; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    /**
     * Set the shared data bus for inter-module communication.
     * Discovered endpoints will be published to the "discovered-endpoints" channel.
     */
    public void setSharedDataBus(SharedDataBus dataBus) {
        this.dataBus = dataBus;
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        List<Finding> findings = new ArrayList<>();
        HttpResponse response = requestResponse.response();
        if (response == null) return findings;

        String contentType = "";
        for (var h : response.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                contentType = h.value().toLowerCase();
                break;
            }
        }

        String url = requestResponse.request().url();
        String body;
        try {
            body = response.bodyToString();
        } catch (Exception e) {
            return findings;
        }
        if (body == null || body.isBlank()) return findings;

        Set<String> discovered = new HashSet<>();

        if (contentType.contains("javascript") || contentType.contains("text/html")) {
            // JavaScript and inline script extraction
            for (Pattern pattern : JS_PATTERNS) {
                Matcher m = pattern.matcher(body);
                while (m.find()) {
                    String path = m.group(m.groupCount());
                    if (path != null) discovered.add(path);
                }
            }
        }

        if (contentType.contains("text/html")) {
            Matcher m = HTML_ATTR_PATTERN.matcher(body);
            while (m.find()) {
                discovered.add(m.group(1));
            }

            // Extract paths from inline <script> blocks
            Matcher scriptMatcher = Pattern.compile("<script[^>]*>(.*?)</script>", Pattern.DOTALL)
                    .matcher(body);
            while (scriptMatcher.find()) {
                String scriptContent = scriptMatcher.group(1);
                for (Pattern pattern : JS_PATTERNS) {
                    Matcher jsm = pattern.matcher(scriptContent);
                    while (jsm.find()) {
                        String path = jsm.group(jsm.groupCount());
                        if (path != null) discovered.add(path);
                    }
                }
            }
        }

        if (contentType.contains("application/json")) {
            Matcher m = JSON_URL_PATTERN.matcher(body);
            while (m.find()) {
                discovered.add(m.group(1));
            }
            // Also run JS patterns on JSON since APIs often return URLs
            for (Pattern pattern : JS_PATTERNS) {
                Matcher jm = pattern.matcher(body);
                while (jm.find()) {
                    String path = jm.group(jm.groupCount());
                    if (path != null) discovered.add(path);
                }
            }
        }

        // Filter and normalize
        for (String raw : discovered) {
            String normalized = normalize(raw, url);
            if (normalized != null && !endpoints.containsKey(normalized)) {
                String method = guessMethod(raw, body);
                EndpointInfo info = new EndpointInfo(normalized, url, method);
                if (endpoints.putIfAbsent(normalized, info) == null) {
                    // Publish discovered endpoint to SharedDataBus for other modules
                    if (dataBus != null) {
                        dataBus.addToSet("discovered-endpoints", normalized);
                    }
                    findings.add(Finding.builder("endpoint-finder",
                                    "Discovered endpoint: " + normalized,
                                    Severity.INFO, Confidence.FIRM)
                            .url(url)
                            .evidence(normalized)
                            .responseEvidence(normalized)
                            .description("Found endpoint path in " + contentType + " response")
                            .build());
                }
            }
        }

        return findings;
    }

    private String normalize(String raw, String sourceUrl) {
        if (raw == null || raw.isBlank()) return null;
        raw = raw.trim();

        // Skip data URIs, mailto, tel, etc.
        if (raw.startsWith("data:") || raw.startsWith("mailto:") ||
                raw.startsWith("tel:") || raw.startsWith("javascript:") || raw.startsWith("#")) {
            return null;
        }

        // Skip static file extensions
        String lower = raw.toLowerCase();
        for (String ext : IGNORED_EXTENSIONS) {
            if (lower.endsWith(ext)) return null;
        }

        // Skip single chars, numeric-only, regex-like patterns
        if (raw.length() <= 1) return null;
        if (raw.matches("^[0-9]+$")) return null;
        if (raw.contains("*") || raw.contains("\\d") || raw.contains("\\w")) return null;

        // Remove trailing slash for dedup
        if (raw.endsWith("/") && raw.length() > 1) {
            raw = raw.substring(0, raw.length() - 1);
        }

        // Resolve relative paths against source URL
        if (!raw.startsWith("http://") && !raw.startsWith("https://") && !raw.startsWith("/")) {
            try {
                // Strip query string from source URL before resolving relative path
                String baseUrl = sourceUrl;
                int queryIdx = baseUrl.indexOf('?');
                if (queryIdx >= 0) {
                    baseUrl = baseUrl.substring(0, queryIdx);
                }
                String base = baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
                raw = base + raw;
            } catch (Exception e) {
                raw = "/" + raw;
            }
        }

        // Strip full URL to just the path for dedup
        if (raw.startsWith("http://") || raw.startsWith("https://")) {
            try {
                int pathStart = raw.indexOf('/', raw.indexOf("://") + 3);
                if (pathStart > 0) {
                    raw = raw.substring(pathStart);
                } else {
                    return null;
                }
            } catch (Exception e) {
                return null;
            }
        }

        return raw;
    }

    private String guessMethod(String raw, String context) {
        String lower = context.toLowerCase();
        int idx = lower.indexOf(raw.toLowerCase());
        if (idx < 0) return "GET";

        // Check surrounding context for HTTP method hints
        String surrounding = lower.substring(Math.max(0, idx - 50), Math.min(lower.length(), idx + raw.length() + 50));
        if (surrounding.contains("post")) return "POST";
        if (surrounding.contains("put")) return "PUT";
        if (surrounding.contains("delete")) return "DELETE";
        if (surrounding.contains("patch")) return "PATCH";
        return "GET";
    }

    @Override
    public void destroy() {}

    public ConcurrentHashMap<String, EndpointInfo> getEndpoints() { return endpoints; }

    public void clearAll() { endpoints.clear(); }
}
