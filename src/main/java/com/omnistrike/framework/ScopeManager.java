package com.omnistrike.framework;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Manages the user-configured target scope.
 * Only requests/responses matching these domains will be processed by modules.
 */
public class ScopeManager {

    // Volatile reference swap for atomic updates — no TOCTOU gap
    private volatile Set<String> targetDomains = Collections.emptySet();

    // URL path exclusion list — URLs containing any of these substrings are completely skipped
    // (both active AND passive scanning). Volatile reference swap like targetDomains.
    private volatile List<String> excludedPaths = Collections.emptyList();

    // URL inclusion list — when non-empty, ONLY URLs matching at least one entry are scanned.
    // Entries can be full paths (/api/v1/users) or path prefixes (/api/v1/).
    // Matching is substring-based on the URL path component (same as excludedPaths).
    // Priority: exclusions ALWAYS win over inclusions (safety first).
    private volatile List<String> includedPaths = Collections.emptyList();

    public void setTargetDomains(String commaSeparated) {
        if (commaSeparated == null || commaSeparated.isBlank()) {
            targetDomains = Collections.emptySet();
            return;
        }
        // Build new set first, then swap atomically
        Set<String> newSet = Arrays.stream(commaSeparated.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(ScopeManager::extractHost)
                .filter(h -> h != null && !h.isEmpty())
                .filter(ScopeManager::isValidScopeDomain)
                .collect(Collectors.toUnmodifiableSet());
        targetDomains = newSet;
    }

    /**
     * Validates that a scope domain entry is specific enough to be safe.
     * Rejects bare TLDs (e.g., "com", "net") that would match too broadly.
     * Allows IP addresses (no dot required for IPv4/IPv6 literals).
     */
    private static boolean isValidScopeDomain(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        // Allow IP addresses (contain digits and dots, or are IPv6)
        if (domain.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return true; // IPv4
        if (domain.contains(":")) return true; // IPv6
        // Reject entries without a dot (bare TLDs like "com", "org", "net")
        return domain.contains(".");
    }

    public Set<String> getTargetDomains() {
        return targetDomains;
    }

    public boolean isInScope(String host) {
        if (host == null) return false;
        Set<String> domains = targetDomains;
        if (domains.isEmpty()) return false;
        String lowerHost = host.toLowerCase();
        for (String domain : domains) {
            if (lowerHost.equals(domain) || lowerHost.endsWith("." + domain)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sets the list of included URLs and/or endpoints.
     * When non-empty, ONLY URLs matching at least one entry will be scanned.
     * When empty, all in-scope URLs are scanned (default behaviour).
     *
     * Entries can be:
     *   - Endpoints (paths):  /api/v1/users, /admin/settings, fdsfds.php
     *     → matched against the URL's path component (substring match)
     *   - Full URLs:          https://example.com/api/v1/users
     *     → matched against the full URL (substring match, scheme+host+path)
     *
     * Query parameters are stripped from entries — matching focuses on the endpoint/path.
     * Example: entering "fdsfds.php?fds=fds" is treated as "fdsfds.php",
     * so it matches fdsfds.php regardless of what parameters it has.
     *
     * Comma or newline separated.
     */
    public void setIncludedPaths(String text) {
        if (text == null || text.isBlank()) {
            includedPaths = Collections.emptyList();
            return;
        }
        List<String> entries = Arrays.stream(text.split("[\\n\\r,]+"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(String::toLowerCase)
                .map(ScopeManager::stripQueryParams)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableList());
        includedPaths = entries;
    }

    public List<String> getIncludedPaths() {
        return includedPaths;
    }

    /**
     * Sets the list of excluded URLs and/or endpoints.
     * Each entry is a path substring (e.g., "/logout", "/admin/delete")
     * or a full URL (e.g., "https://example.com/api/health").
     *
     * Query parameters are stripped — matching focuses on the endpoint/path.
     * Example: "logout.php?action=bye" becomes "logout.php" and excludes
     * that endpoint regardless of parameters.
     *
     * Comma or newline separated.
     */
    public void setExcludedPaths(String text) {
        if (text == null || text.isBlank()) {
            excludedPaths = Collections.emptyList();
            return;
        }
        List<String> paths = Arrays.stream(text.split("[\\n\\r,]+"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(String::toLowerCase)
                .map(ScopeManager::stripQueryParams)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableList());
        excludedPaths = paths;
    }

    public List<String> getExcludedPaths() {
        return excludedPaths;
    }

    /**
     * Returns true if the given URL should be excluded from ALL scanning (active + passive).
     *
     * Each exclusion entry is tested as:
     *   - Full URL match: if the entry starts with http:// or https://, match against full URL
     *   - Endpoint match: otherwise, match against the URL's path component
     *
     * Match is substring-based — "/api" excludes "/api/v1/users", "/api/health", etc.
     */
    public boolean isExcludedPath(String url) {
        List<String> entries = excludedPaths;
        if (entries.isEmpty() || url == null) return false;
        String lowerUrl = url.toLowerCase();
        String path = extractUrlPath(url);

        for (String entry : entries) {
            if (matchEntry(entry, lowerUrl, path)) return true;
        }
        return false;
    }

    /**
     * Returns true if the URL is allowed by the inclusion list.
     * If the inclusion list is empty → everything is allowed (default).
     * If the inclusion list is non-empty → the URL must match at least one entry.
     *
     * Each inclusion entry is tested as:
     *   - Full URL match: if the entry starts with http:// or https://, match against full URL
     *   - Endpoint match: otherwise, match against the URL's path component
     *
     * Exclusions always take priority over inclusions. A URL matching both will be EXCLUDED.
     */
    public boolean isIncludedPath(String url) {
        List<String> entries = includedPaths;
        if (entries.isEmpty()) return true; // No inclusion list → everything allowed
        if (url == null) return false;
        String lowerUrl = url.toLowerCase();
        String path = extractUrlPath(url);

        for (String entry : entries) {
            if (matchEntry(entry, lowerUrl, path)) return true;
        }
        return false;
    }

    /**
     * Combined scope check for a URL: must pass domain check, inclusion filter,
     * and exclusion filter.
     *
     * @return true if the URL should be scanned
     */
    public boolean isUrlInScope(String url, String host) {
        if (!isInScope(host)) return false;
        if (isExcludedPath(url)) return false;
        if (!isIncludedPath(url)) return false;
        return true;
    }

    /**
     * Match a single include/exclude entry against a URL.
     * Query params are already stripped from entries at set-time, so matching
     * is always path-focused regardless of what parameters the URL has.
     *
     * @param entry    the user-specified pattern (lowercase, query-stripped)
     * @param lowerUrl the full URL being tested (lowercase)
     * @param path     the extracted path component of the URL (lowercase, no query string)
     * @return true if the entry matches
     */
    private static boolean matchEntry(String entry, String lowerUrl, String path) {
        if (entry.startsWith("http://") || entry.startsWith("https://")) {
            // Full URL entry — match against the complete URL without query string
            String urlNoQuery = lowerUrl;
            int q = urlNoQuery.indexOf('?');
            if (q >= 0) urlNoQuery = urlNoQuery.substring(0, q);
            return urlNoQuery.contains(entry);
        } else {
            // Endpoint/path entry — match against the path component only
            return path.contains(entry);
        }
    }

    /**
     * Strip query parameters from a user-entered entry.
     * "fdsfds.php?fds=fds" → "fdsfds.php"
     * "https://example.com/api?key=val" → "https://example.com/api"
     */
    private static String stripQueryParams(String entry) {
        int q = entry.indexOf('?');
        return q >= 0 ? entry.substring(0, q) : entry;
    }

    /** Extract the path component from a URL (lowercase, no query string). */
    private static String extractUrlPath(String url) {
        String lower = url.toLowerCase();
        String path;
        int schemeEnd = lower.indexOf("://");
        if (schemeEnd >= 0) {
            int pathStart = lower.indexOf('/', schemeEnd + 3);
            path = pathStart >= 0 ? lower.substring(pathStart) : "/";
        } else {
            path = lower;
        }
        int qIdx = path.indexOf('?');
        if (qIdx >= 0) path = path.substring(0, qIdx);
        return path;
    }

    /**
     * Extract host from a URL string. Handles IPv6 bracket notation.
     */
    public static String extractHost(String url) {
        if (url == null) return null;
        try {
            String stripped = url;
            if (stripped.contains("://")) {
                stripped = stripped.substring(stripped.indexOf("://") + 3);
            }
            // Strip userinfo (user:pass@) to prevent bypass via http://attacker@target.com/
            int atSign = stripped.indexOf('@');
            int slashBeforeAt = stripped.indexOf('/');
            if (atSign > 0 && (slashBeforeAt < 0 || atSign < slashBeforeAt)) {
                stripped = stripped.substring(atSign + 1);
            }
            // Handle IPv6 bracket notation [::1]
            if (stripped.startsWith("[")) {
                int closeBracket = stripped.indexOf(']');
                if (closeBracket > 0) {
                    return stripped.substring(1, closeBracket).toLowerCase();
                }
            }
            int slashIdx = stripped.indexOf('/');
            if (slashIdx > 0) stripped = stripped.substring(0, slashIdx);
            int colonIdx = stripped.lastIndexOf(':');
            // Only strip port if there's a colon and what follows looks like a port number
            if (colonIdx > 0) {
                String afterColon = stripped.substring(colonIdx + 1);
                if (afterColon.matches("\\d+")) {
                    stripped = stripped.substring(0, colonIdx);
                }
            }
            return stripped.toLowerCase();
        } catch (Exception e) {
            return null;
        }
    }
}
