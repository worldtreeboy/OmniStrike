package com.omnistrike.framework;

import java.util.Set;
import java.util.concurrent.ConcurrentMap;

/** Small helper for long-lived passive-scanner dedup maps. */
public final class BoundedDeduplication {
    public static final int DEFAULT_MAX_ENTRIES = 50_000;

    private BoundedDeduplication() {}

    public static boolean markIfNew(ConcurrentMap<String, Boolean> map, String key) {
        boolean added = map.putIfAbsent(key, Boolean.TRUE) == null;
        if (added) trimToSize(map, DEFAULT_MAX_ENTRIES);
        return added;
    }

    public static boolean markIfNew(Set<String> set, String key) {
        boolean added = set.add(key);
        if (added) trimToSize(set, DEFAULT_MAX_ENTRIES);
        return added;
    }

    public static <K, V> void trimToSize(ConcurrentMap<K, V> map, int maximum) {
        if (maximum < 1) throw new IllegalArgumentException("maximum must be positive");
        int excess = map.size() - maximum;
        if (excess <= 0) return;
        for (K key : map.keySet()) {
            if (excess-- <= 0) break;
            map.remove(key);
        }
    }

    public static <T> void trimToSize(Set<T> set, int maximum) {
        if (maximum < 1) throw new IllegalArgumentException("maximum must be positive");
        int excess = set.size() - maximum;
        if (excess <= 0) return;
        for (T value : set) {
            if (excess-- <= 0) break;
            set.remove(value);
        }
    }
}
