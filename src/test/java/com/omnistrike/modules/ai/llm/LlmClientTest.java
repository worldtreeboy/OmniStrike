package com.omnistrike.modules.ai.llm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LlmClientTest {
    @Test
    void leavingApiModeErasesApiConfiguration() {
        LlmClient client = new LlmClient();
        client.configureApiKey(ApiKeyProvider.OPENAI, "secret-value", "gpt-test");
        client.setConnectionMode(AiConnectionMode.API_KEY);
        assertTrue(client.isConfigured());

        client.setConnectionMode(AiConnectionMode.NONE);
        client.setConnectionMode(AiConnectionMode.API_KEY);
        assertFalse(client.isConfigured());
    }
}
