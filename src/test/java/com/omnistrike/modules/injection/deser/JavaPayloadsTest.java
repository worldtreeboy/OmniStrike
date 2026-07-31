package com.omnistrike.modules.injection.deser;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JavaPayloadsTest {
    @Test
    void urlDnsPayloadGeneratesOnJava17WithoutOpeningJdkModules() {
        byte[] payload = DeserPayloadGenerator.generate(
                DeserPayloadGenerator.Language.JAVA,
                "URLDNS", "http://callback.invalid/proof",
                DeserPayloadGenerator.Encoding.RAW);

        assertTrue(payload.length > 32);
        assertEquals((byte) 0xAC, payload[0]);
        assertEquals((byte) 0xED, payload[1]);
    }
}
