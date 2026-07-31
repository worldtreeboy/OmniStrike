package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SsrfScannerTest {
    @Test
    void internalMarkerMustBeNewRelativeToBaseline() {
        assertNull(SsrfScanner.findNewInternalEvidence(
                "Documentation example root:x:0:0:",
                "Longer reflected page with Documentation example root:x:0:0:"));
        assertEquals("root:x:0:0:", SsrfScanner.findNewInternalEvidence(
                "ordinary baseline", "prefix root:x:0:0:root:/root:/bin/bash"));
    }
}
