package com.omnistrike.modules.ai.llm;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CliBackendTest {
    @Test
    void boundedReaderDrainsInputAndCapsCapturedText() throws Exception {
        StringBuilder output = new StringBuilder();
        boolean truncated = CliBackend.readUtf8Bounded(
                new ByteArrayInputStream("abcdefgh".getBytes(StandardCharsets.UTF_8)), output, 5);

        assertTrue(truncated);
        assertEquals("abcde", output.toString());
    }

    @Test
    void boundedReaderPreservesNormalUtf8Output() throws Exception {
        StringBuilder output = new StringBuilder();
        boolean truncated = CliBackend.readUtf8Bounded(
                new ByteArrayInputStream("hello 世界".getBytes(StandardCharsets.UTF_8)), output, 20);

        assertFalse(truncated);
        assertEquals("hello 世界", output.toString());
    }
}
