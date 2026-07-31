package com.omnistrike.framework;

import java.net.URI;
import java.util.Locale;

/** Builds stable, cross-module identities for active-scan targets. */
public final class ScanTargetIdentity {
    private ScanTargetIdentity() {}

    public static String build(String url, String method, String targetType, String targetName) {
        return endpoint(url) + "|"
                + (method == null ? "GET" : method.toUpperCase(Locale.ROOT))
                + "|" + safe(targetType) + "|" + safe(targetName);
    }

    /** Normalized scheme, authority, port and path, without query or fragment. */
    public static String endpoint(String url) {
        return normalizeEndpoint(url);
    }

    /** Normalized scheme and authority, retaining non-default ports. */
    public static String origin(String url) {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme() == null ? "http" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost();
            if (host == null) throw new IllegalArgumentException("URL has no host");
            host = host.toLowerCase(Locale.ROOT);
            if (host.contains(":")) host = "[" + host + "]";
            int port = uri.getPort();
            boolean defaultPort = port < 0 || (port == 80 && scheme.equals("http"))
                    || (port == 443 && scheme.equals("https"));
            return scheme + "://" + host + (defaultPort ? "" : ":" + port);
        } catch (Exception ignored) {
            String endpoint = normalizeEndpoint(url);
            int schemeEnd = endpoint.indexOf("://");
            int path = schemeEnd < 0 ? -1 : endpoint.indexOf('/', schemeEnd + 3);
            return path < 0 ? endpoint : endpoint.substring(0, path);
        }
    }

    static String normalizeEndpoint(String url) {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme() == null ? "http" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost();
            if (host == null) throw new IllegalArgumentException("URL has no host");
            host = host.toLowerCase(Locale.ROOT);
            if (host.contains(":")) host = "[" + host + "]";
            int port = uri.getPort();
            boolean defaultPort = port < 0 || (port == 80 && scheme.equals("http"))
                    || (port == 443 && scheme.equals("https"));
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            return scheme + "://" + host + (defaultPort ? "" : ":" + port) + path;
        } catch (Exception ignored) {
            if (url == null) return "";
            int end = url.length();
            int query = url.indexOf('?');
            int fragment = url.indexOf('#');
            if (query >= 0) end = Math.min(end, query);
            if (fragment >= 0) end = Math.min(end, fragment);
            return url.substring(0, end);
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
