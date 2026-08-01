package com.omnistrike.modules.ai;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AiVulnAnalyzerJsonTest {

    @Test
    void replacesNestedAndArrayValuesByJsonPointer() {
        String json = "{\"user\":{\"name\":\"alice\"},\"items\":[{\"id\":1},{\"id\":2}]}";

        String nested = AiVulnAnalyzer.injectJsonValue(json, "/user/name", "${7*7} \" $1");
        String array = AiVulnAnalyzer.injectJsonValue(nested, "/items/1/id", "payload");

        var root = JsonParser.parseString(array).getAsJsonObject();
        assertEquals("${7*7} \" $1", root.getAsJsonObject("user").get("name").getAsString());
        assertEquals("payload", root.getAsJsonArray("items").get(1).getAsJsonObject().get("id").getAsString());
    }

    @Test
    void refusesAmbiguousLeafNames() {
        String json = "{\"primary\":{\"id\":1},\"secondary\":{\"id\":2}}";

        assertEquals(json, AiVulnAnalyzer.injectJsonValue(json, "id", "attack"));
    }

    @Test
    void acceptsAUniqueLeafNameAndFailsClosedOnInvalidJson() {
        String json = "{\"profile\":{\"email\":\"old@example.test\"}}";
        String modified = AiVulnAnalyzer.injectJsonValue(json, "email", "new@example.test");

        assertEquals("new@example.test", JsonParser.parseString(modified).getAsJsonObject()
                .getAsJsonObject("profile").get("email").getAsString());
        assertEquals("not-json", AiVulnAnalyzer.injectJsonValue("not-json", "email", "payload"));
    }

    @Test
    void aiPayloadLimitsAreAlwaysBoundedAndTargetedScansHaveAHardCeiling() {
        AiVulnAnalyzer analyzer = new AiVulnAnalyzer();

        assertEquals(12, analyzer.getMaxPayloadsPerRequest());
        assertEquals(12, analyzer.getEffectivePayloadLimit("cmdi-scanner"));
        assertFalse(analyzer.hasOobCapability());

        analyzer.setMaxPayloadsPerRequest(5);
        assertEquals(5, analyzer.getEffectivePayloadLimit("cmdi-scanner"));

        analyzer.setMaxPayloadsPerRequest(500);
        assertEquals(50, analyzer.getMaxPayloadsPerRequest());
        assertEquals(12, analyzer.getEffectivePayloadLimit("cmdi-scanner"));
        assertEquals(50, analyzer.getEffectivePayloadLimit(null));

        analyzer.setMaxPayloadsPerRequest(0);
        assertEquals(12, analyzer.getMaxPayloadsPerRequest());
    }

    @Test
    void commandInjectionPromptIsFocusedAndUsesTheTargetedLimit() {
        AiVulnAnalyzer analyzer = new AiVulnAnalyzer();
        analyzer.setMaxPayloadsPerRequest(50);

        String prompt = analyzer.buildFuzzPrompt("cmdi-scanner");

        assertTrue(prompt.contains("Generate ONLY Command Injection payloads"));
        assertTrue(prompt.contains("Generate at most 12 total payloads"));
        assertTrue(prompt.contains("attack_type set to exactly \"cmdi\""));
        assertTrue(prompt.contains("Do NOT generate ANY payloads for SQLi"));
        assertTrue(prompt.contains("OOB TESTING IS MANDATORY"));
        assertTrue(prompt.contains("Never exfiltrate target data"));
    }
}
