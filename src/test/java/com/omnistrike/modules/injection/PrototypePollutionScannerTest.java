package com.omnistrike.modules.injection;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PrototypePollutionScannerTest {

    @Test
    void acceptsVendorJsonAndRejectsUnrelatedContentTypes() {
        assertTrue(PrototypePollutionScanner.isJsonContentType("application/json; charset=utf-8"));
        assertTrue(PrototypePollutionScanner.isJsonContentType("application/problem+json"));
        assertFalse(PrototypePollutionScanner.isJsonContentType("text/plain"));
    }

    @Test
    void structurallyAddsCanaryWithoutCorruptingExistingJson() {
        String modified = PrototypePollutionScanner.injectProtoPayload(
                "{\"profile\":{\"name\":\"alice\"}}", "__proto__", "marker", "$1 \\\" quoted");

        var root = JsonParser.parseString(modified).getAsJsonObject();
        assertEquals("alice", root.getAsJsonObject("profile").get("name").getAsString());
        assertEquals("$1 \\\" quoted", root.getAsJsonObject("__proto__").get("marker").getAsString());
    }
}
