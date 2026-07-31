package com.omnistrike.modules.ai.llm;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ApiKeyBackendTest {
    @Test
    void boundedReaderAcceptsResponseAtLimit() throws Exception {
        byte[] body = "hello".getBytes(StandardCharsets.UTF_8);
        assertEquals("hello", ApiKeyBackend.readBoundedUtf8(
                new ByteArrayInputStream(body), body.length));
    }

    @Test
    void boundedReaderRejectsOversizedResponse() {
        byte[] body = "too-large".getBytes(StandardCharsets.UTF_8);
        assertThrows(LlmException.class, () -> ApiKeyBackend.readBoundedUtf8(
                new ByteArrayInputStream(body), body.length - 1));
    }
}
