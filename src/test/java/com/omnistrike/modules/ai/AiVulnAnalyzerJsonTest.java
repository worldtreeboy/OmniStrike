package com.omnistrike.modules.ai;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
}
