package com.omnistrike.framework;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonScanSupportTest {
    @Test
    void extractsAndMutatesObjectsArraysDottedKeysAndUnusualNumbers() {
        String json = "{\"user.name\":-1,\"jobs\":[{\"command\":1e5}]}";
        List<JsonScanSupport.Target> targets = JsonScanSupport.extractTargets(json);

        assertEquals(List.of("[\"user.name\"]", "jobs[0].command"),
                targets.stream().map(JsonScanSupport.Target::displayName).toList());

        String changed = JsonScanSupport.replaceValue(json,
                List.of("jobs", 0, "command"), "${7*7}");
        assertEquals("${7*7}", JsonParser.parseString(changed).getAsJsonObject()
                .getAsJsonArray("jobs").get(0).getAsJsonObject().get("command").getAsString());
    }

    @Test
    void handlesManyMixedNestingLayersWithoutRecursiveTraversal() {
        String json = "\"safe\"";
        List<Object> path = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            json = "{\"level" + i + "\":[" + json + "]}";
            path.add(0, 0);
            path.add(0, "level" + i);
        }

        List<JsonScanSupport.Target> targets = JsonScanSupport.extractTargets(json);
        assertEquals(1, targets.size());
        String changed = JsonScanSupport.replaceValue(json, path, "payload");

        JsonElement current = JsonParser.parseString(changed);
        for (Object part : path) {
            current = part instanceof String key
                    ? current.getAsJsonObject().get(key)
                    : current.getAsJsonArray().get((Integer) part);
        }
        assertEquals("payload", current.getAsString());
    }

    @Test
    void includesBooleanAndNullTargets() {
        List<JsonScanSupport.Target> targets = JsonScanSupport.extractTargets(
                "{\"enabled\":true,\"optional\":null}");
        assertEquals(List.of("enabled", "optional"),
                targets.stream().map(JsonScanSupport.Target::displayName).toList());
    }

    @Test
    void replacesScalarWithARealJsonObjectRatherThanAQuotedString() {
        var operator = new com.google.gson.JsonObject();
        operator.addProperty("$ne", "canary");
        String changed = JsonScanSupport.replaceElement(
                "{\"username\":\"alice\"}", List.of("username"), operator);

        JsonElement value = JsonParser.parseString(changed).getAsJsonObject().get("username");
        assertTrue(value.isJsonObject());
        assertEquals("canary", value.getAsJsonObject().get("$ne").getAsString());
    }

    @Test
    void rejectsPathologicalNestingBeforeParsing() {
        String json = "[".repeat(129) + "0" + "]".repeat(129);
        assertThrows(IllegalArgumentException.class, () -> JsonScanSupport.extractTargets(json));
    }
}
