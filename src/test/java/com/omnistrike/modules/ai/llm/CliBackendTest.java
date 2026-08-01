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

    @Test
    void codexPrefersDedicatedFinalMessageOverNoisyTranscript() {
        String transcript = "Codex banner\nuser\n{\"findings\":[]}\nassistant\n{\"payloads\":[]}";

        assertEquals("{\"findings\":[{\"title\":\"confirmed\"}]}",
                CliBackend.selectCodexResponse(
                        "  {\"findings\":[{\"title\":\"confirmed\"}]}  ", transcript));
    }

    @Test
    void codexFallbackSelectsLastValidJsonObjectInsteadOfPromptExample() {
        String transcript = "Codex banner\nuser prompt schema: {\"findings\":[]}\n"
                + "assistant\n```json\n{\"payloads\":[{\"payload\":\"' OR 1=1--\"}]}\n```\n"
                + "tokens used: 123";

        assertEquals("{\"payloads\":[{\"payload\":\"' OR 1=1--\"}]}",
                CliBackend.selectCodexResponse("", transcript));
    }

    @Test
    void codexFallbackPreservesPlainTextWhenNoJsonExists() {
        assertEquals("plain assistant response",
                CliBackend.selectCodexResponse(null, "  plain assistant response  "));
    }
}
