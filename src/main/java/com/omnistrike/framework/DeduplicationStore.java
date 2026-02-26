package com.omnistrike.framework;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared deduplication map. Ensures each module+endpoint+parameter combination
 * is only tested once. Thread-safe via ConcurrentHashMap.
 */
public class DeduplicationStore {

    private static final int MAX_ENTRIES = 500_000;

    private final ConcurrentHashMap<String, Boolean> seen = new ConcurrentHashMap<>();

    /**
     * Mark this combination as seen. Returns true if this is the FIRST time
     * (not yet tested), false if already seen.
     * Synchronized to prevent TOCTOU race between size check and putIfAbsent.
     */
    public synchronized boolean markIfNew(String moduleId, String urlPath, String parameterName) {
        if (seen.size() >= MAX_ENTRIES) return false;
        String normalizedPath = normalizePath(urlPath);
        String key = moduleId + ":" + normalizedPath + ":" + (parameterName != null ? parameterName : "");
        return seen.putIfAbsent(key, Boolean.TRUE) == null;
    }

    /**
     * Mark this combination as seen, including HTTP method in the key.
     * Use this when GET and POST to the same path should be tested separately.
     * Synchronized to prevent TOCTOU race between size check and putIfAbsent.
     */
    public synchronized boolean markIfNew(String moduleId, String method, String urlPath, String parameterName) {
        if (seen.size() >= MAX_ENTRIES) return false;
        String normalizedPath = normalizePath(urlPath);
        String m = method != null ? method.toUpperCase() : "GET";
        String key = moduleId + ":" + m + ":" + normalizedPath + ":" + (parameterName != null ? parameterName : "");
        return seen.putIfAbsent(key, Boolean.TRUE) == null;
    }

    /** @deprecated Use markIfNew instead — name better communicates the side effect */
    @Deprecated
    public boolean isNew(String moduleId, String urlPath, String parameterName) {
        return markIfNew(moduleId, urlPath, parameterName);
    }

    /**
     * Mark a raw key as seen. Returns true if first time.
     * Synchronized to prevent TOCTOU race between size check and putIfAbsent.
     */
    public synchronized boolean markIfNewRaw(String rawKey) {
        if (seen.size() >= MAX_ENTRIES) return false;
        return seen.putIfAbsent(rawKey, Boolean.TRUE) == null;
    }

    /** @deprecated Use markIfNewRaw instead */
    @Deprecated
    public boolean isNewRaw(String rawKey) {
        return markIfNewRaw(rawKey);
    }

    public boolean hasBeenTested(String moduleId, String urlPath, String parameterName) {
        String normalizedPath = normalizePath(urlPath);
        String key = moduleId + ":" + normalizedPath + ":" + (parameterName != null ? parameterName : "");
        return seen.containsKey(key);
    }

    public synchronized void clear() {
        seen.clear();
    }

    public synchronized void clearModule(String moduleId) {
        seen.keySet().removeIf(k -> k.startsWith(moduleId + ":"));
    }

    public int size() {
        return seen.size();
    }

    /**
     * Normalize URL path for dedup — strips query parameters and fragments
     * so /api/users?id=1 and /api/users?id=2 resolve to the same key.
     */
    private static String normalizePath(String urlPath) {
        if (urlPath == null) return "";
        int qIdx = urlPath.indexOf('?');
        if (qIdx > 0) urlPath = urlPath.substring(0, qIdx);
        int fIdx = urlPath.indexOf('#');
        if (fIdx > 0) urlPath = urlPath.substring(0, fIdx);
        return urlPath;
    }
}
