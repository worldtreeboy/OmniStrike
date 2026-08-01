package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Dynamics365ScannerTest {

    @Test
    void requiresPopulatedODataValueArray() {
        assertTrue(Dynamics365Scanner.hasNonEmptyValueArray(
                "{\"@odata.context\":\"x\",\"value\":[{\"id\":1}]}"));
        assertFalse(Dynamics365Scanner.hasNonEmptyValueArray(
                "{\"@odata.context\":\"x\",\"value\": [\n ]}"));
        assertFalse(Dynamics365Scanner.hasNonEmptyValueArray(
                "{\"@odata.context\":\"x\",\"value\":null}"));
        assertFalse(Dynamics365Scanner.hasNonEmptyValueArray("not json"));
    }
}
