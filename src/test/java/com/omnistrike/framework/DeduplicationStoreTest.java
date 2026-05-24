package com.omnistrike.framework;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the dedup keying logic that decides whether a (module, endpoint, param)
 * combination has already been scanned. This is the gate that prevents redundant
 * probes, so its keying must be exact.
 */
class DeduplicationStoreTest {

    @Test
    void firstSightIsNewSecondIsNot() {
        DeduplicationStore d = new DeduplicationStore();
        assertTrue(d.markIfNew("sqli", "/users", "id"), "first sighting should be new");
        assertFalse(d.markIfNew("sqli", "/users", "id"), "repeat sighting should not be new");
    }

    @Test
    void queryStringAndFragmentAreStrippedFromKey() {
        DeduplicationStore d = new DeduplicationStore();
        // Same path, different query/fragment → same dedup key.
        assertTrue(d.markIfNew("sqli", "/users?id=1", "id"));
        assertFalse(d.markIfNew("sqli", "/users?id=2", "id"));
        assertFalse(d.markIfNew("sqli", "/users#frag", "id"));
    }

    @Test
    void differentModuleParamOrPathAreDistinct() {
        DeduplicationStore d = new DeduplicationStore();
        assertTrue(d.markIfNew("sqli", "/users", "id"));
        assertTrue(d.markIfNew("xss", "/users", "id"), "different module is distinct");
        assertTrue(d.markIfNew("sqli", "/posts", "id"), "different path is distinct");
        assertTrue(d.markIfNew("sqli", "/users", "name"), "different param is distinct");
    }

    @Test
    void nullParameterIsTreatedConsistently() {
        DeduplicationStore d = new DeduplicationStore();
        assertTrue(d.markIfNew("recon", "/x", null));
        assertFalse(d.markIfNew("recon", "/x", null));
        // null and "" collapse to the same key.
        assertFalse(d.markIfNew("recon", "/x", ""));
    }

    @Test
    void methodAwareKeySeparatesGetAndPost() {
        DeduplicationStore d = new DeduplicationStore();
        assertTrue(d.markIfNew("cmdi", "GET", "/run", "cmd"));
        assertTrue(d.markIfNew("cmdi", "POST", "/run", "cmd"), "GET and POST are separate");
        assertFalse(d.markIfNew("cmdi", "GET", "/run", "cmd"));
        // method is case-normalized
        assertFalse(d.markIfNew("cmdi", "get", "/run", "cmd"));
    }

    @Test
    void rawKeyDedup() {
        DeduplicationStore d = new DeduplicationStore();
        assertTrue(d.markIfNewRaw("custom-key"));
        assertFalse(d.markIfNewRaw("custom-key"));
    }

    @Test
    void bypassReportsNewButStillRecordsAndIsThreadLocal() throws Exception {
        DeduplicationStore d = new DeduplicationStore();
        assertTrue(d.markIfNew("sqli", "/x", "id"));
        assertFalse(d.markIfNew("sqli", "/x", "id"), "already seen on this thread");

        d.setBypass(true);
        try {
            assertTrue(d.markIfNew("sqli", "/x", "id"), "bypass forces 'new'");
        } finally {
            d.setBypass(false);
        }
        assertFalse(d.isBypass(), "bypass reset");

        // Bypass must not leak to other threads.
        final boolean[] otherThreadBypass = {true};
        Thread t = new Thread(() -> otherThreadBypass[0] = d.isBypass());
        t.start();
        t.join();
        assertFalse(otherThreadBypass[0], "bypass is thread-local");
    }

    @Test
    void hasBeenTestedReflectsState() {
        DeduplicationStore d = new DeduplicationStore();
        assertFalse(d.hasBeenTested("sqli", "/x", "id"));
        d.markIfNew("sqli", "/x", "id");
        assertTrue(d.hasBeenTested("sqli", "/x", "id"));
    }

    @Test
    void clearResetsState() {
        DeduplicationStore d = new DeduplicationStore();
        d.markIfNew("sqli", "/x", "id");
        assertEquals(1, d.size());
        d.clear();
        assertEquals(0, d.size());
        assertTrue(d.markIfNew("sqli", "/x", "id"), "new again after clear");
    }

    @Test
    void clearModuleOnlyDropsThatModule() {
        DeduplicationStore d = new DeduplicationStore();
        d.markIfNew("sqli", "/x", "id");
        d.markIfNew("xss", "/x", "id");
        d.clearModule("sqli");
        assertTrue(d.markIfNew("sqli", "/x", "id"), "sqli cleared");
        assertFalse(d.markIfNew("xss", "/x", "id"), "xss retained");
    }
}
