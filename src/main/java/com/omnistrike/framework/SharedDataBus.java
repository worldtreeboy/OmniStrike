package com.omnistrike.framework;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Inter-module data sharing bus. Modules can publish and consume shared data
 * without directly referencing each other.
 *
 * Common channels:
 *   "discovered-params"  -> Set of parameter names (from param-miner)
 *   "discovered-endpoints" -> Set of URL paths (from endpoint-finder)
 *   "discovered-subdomains" -> Set of subdomains (from subdomain-collector)
 */
public class SharedDataBus {

    private static final int MAX_SET_SIZE = 50_000;
    private static final int MAX_OBJECTS = 1_000;

    private final ConcurrentHashMap<String, Set<String>> stringSets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> objects = new ConcurrentHashMap<>();

    /**
     * Add a value to a named set channel. Capped at MAX_SET_SIZE per channel
     * to prevent unbounded memory growth during long-running scans.
     */
    public void addToSet(String channel, String value) {
        Set<String> set = stringSets.computeIfAbsent(channel, k -> ConcurrentHashMap.newKeySet());
        if (set.size() < MAX_SET_SIZE) {
            set.add(value);
        }
    }

    /**
     * Get all values from a named set channel.
     */
    public Set<String> getSet(String channel) {
        Set<String> set = stringSets.get(channel);
        return set != null ? Collections.unmodifiableSet(set) : Collections.emptySet();
    }

    /**
     * Store an arbitrary object. Capped at MAX_OBJECTS total entries.
     * Existing keys can always be updated (overwritten); only new keys are rejected at cap.
     */
    public void putObject(String key, Object value) {
        if (objects.size() >= MAX_OBJECTS && !objects.containsKey(key)) {
            return; // reject new keys at cap, but allow updates to existing keys
        }
        objects.put(key, value);
    }

    /**
     * Retrieve an arbitrary object.
     */
    @SuppressWarnings("unchecked")
    public <T> T getObject(String key, Class<T> clazz) {
        Object obj = objects.get(key);
        if (obj != null && clazz.isInstance(obj)) {
            return (T) obj;
        }
        return null;
    }

    public void clear() {
        stringSets.clear();
        objects.clear();
    }
}
