package com.omnistrike.framework;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Manages the user-configured target scope.
 * Only requests/responses matching these domains will be processed by modules.
 */
public class ScopeManager {

    // Volatile reference swap for atomic updates — no TOCTOU gap
    private volatile Set<String> targetDomains = Collections.emptySet();

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
