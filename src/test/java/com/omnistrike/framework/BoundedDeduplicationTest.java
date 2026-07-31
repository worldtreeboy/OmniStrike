package com.omnistrike.framework;

import org.junit.jupiter.api.Test;

import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

class BoundedDeduplicationTest {

    @Test
    void marksAtomicallyAndTrimsLongLivedMaps() {
        ConcurrentHashMap<String, Boolean> map = new ConcurrentHashMap<>();
        assertTrue(BoundedDeduplication.markIfNew(map, "one"));
        assertFalse(BoundedDeduplication.markIfNew(map, "one"));

        for (int i = 0; i < 20; i++) map.put("key-" + i, Boolean.TRUE);
        BoundedDeduplication.trimToSize(map, 5);
        assertTrue(map.size() <= 5);
    }

    @Test
    void trimsConcurrentSetToConfiguredMaximum() {
        java.util.Set<String> set = ConcurrentHashMap.newKeySet();
        for (int i = 0; i < 20; i++) set.add("key-" + i);

        BoundedDeduplication.trimToSize(set, 7);

        assertTrue(set.size() <= 7);
    }
}
