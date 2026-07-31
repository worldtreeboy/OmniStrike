package com.omnistrike.framework;

import com.omnistrike.model.Confidence;
import com.omnistrike.model.Finding;
import com.omnistrike.model.Severity;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests lossless dedup semantics: exact repeats within one module are removed,
 * while distinct titles and evidence from different modules are retained.
 */
class FindingsStoreTest {

    /** Builds a CORS-category finding (title contains "cors") on a fixed URL/param. */
    private static Finding corsFinding(String moduleId, String title, Severity severity) {
        return Finding.builder(moduleId, title, severity, Confidence.CERTAIN)
                .url("https://example.com/api")
                .parameter("Origin")
                .build();
    }

    @Test
    void sameModuleDistinctTitlesAreBothRetained() {
        FindingsStore store = new FindingsStore();
        store.addFinding(corsFinding("cors-scanner", "CORS Reflected Origin", Severity.INFO));
        store.addFinding(corsFinding("cors-scanner", "CORS Null Origin Trusted with Credentials", Severity.HIGH));
        assertEquals(2, store.getCount(), "same-module findings with distinct titles must both survive");
    }

    @Test
    void crossModuleInfoThenHighKeepsBoth() {
        FindingsStore store = new FindingsStore();
        store.addFinding(corsFinding("header-analyzer", "CORS Reflected Origin", Severity.INFO));
        store.addFinding(corsFinding("cors-scanner", "CORS Null Origin Trusted with Credentials", Severity.HIGH));
        assertEquals(2, store.getCount(), "cross-module evidence must never suppress a HIGH");
        assertEquals(1, store.getCountBySeverity(Severity.HIGH));
    }

    @Test
    void crossModuleHighThenInfoKeepsBoth() {
        FindingsStore store = new FindingsStore();
        store.addFinding(corsFinding("cors-scanner", "CORS Null Origin Trusted with Credentials", Severity.HIGH));
        store.addFinding(corsFinding("header-analyzer", "CORS Reflected Origin", Severity.INFO));
        assertEquals(2, store.getCount(), "module-specific evidence is independently useful");
        assertEquals(1, store.getCountBySeverity(Severity.HIGH));
    }

    @Test
    void trueDuplicatesAreStillDeduped() {
        FindingsStore store = new FindingsStore();
        Finding f = corsFinding("cors-scanner", "CORS Null Origin Trusted with Credentials", Severity.HIGH);
        store.addFinding(f);
        // Same module + title + url + param: an exact duplicate.
        store.addFinding(corsFinding("cors-scanner", "CORS Null Origin Trusted with Credentials", Severity.HIGH));
        assertEquals(1, store.getCount(), "exact duplicate should be deduped");
    }

    @Test
    void clearModuleRemovesOnlyItsKeysAndAllowsRescan() {
        FindingsStore store = new FindingsStore();
        store.addFinding(corsFinding("header-analyzer", "CORS Reflected Origin", Severity.INFO));
        store.addFinding(corsFinding("cors-scanner", "CORS Null Origin Trusted", Severity.HIGH));

        store.clearModule("header-analyzer");
        store.addFinding(corsFinding("header-analyzer", "CORS Reflected Origin", Severity.INFO));

        assertEquals(2, store.getCount());
        assertEquals(1, store.getCountByModule("header-analyzer"));
        assertEquals(1, store.getCountByModule("cors-scanner"));
    }
}
