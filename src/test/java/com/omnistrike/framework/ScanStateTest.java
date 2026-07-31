package com.omnistrike.framework;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanStateTest {
    @AfterEach
    void cleanUp() {
        ScanState.clearTaskBinding();
        ScanState.reset();
    }

    @Test
    void oldTaskRemainsCancelledAfterNewScanResetsGlobalFlag() {
        long oldEpoch = ScanState.currentEpoch();
        ScanState.bindTask(oldEpoch);
        ScanState.cancel();
        ScanState.reset();

        assertTrue(ScanState.isCancelled());
        ScanState.clearTaskBinding();
        assertFalse(ScanState.isCancelled());
    }
}
