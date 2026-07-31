package com.omnistrike.modules.injection;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class CommandInjectionScannerTest {

    @Test
    void replacesNegativeAndExponentNumbersStructurally() {
        String negative = CommandInjectionScanner.replaceJsonValue(
                "{\"amount\":-1}", List.of("amount"), ";id;");
        String exponent = CommandInjectionScanner.replaceJsonValue(
                "{\"amount\":1e5}", List.of("amount"), "$(id)");

        assertEquals(";id;", parse(negative).getAsJsonObject().get("amount").getAsString());
        assertEquals("$(id)", parse(exponent).getAsJsonObject().get("amount").getAsString());
    }

    @Test
    void distinguishesLiteralDottedKeyFromNestedPath() {
        String json = "{\"user.name\":\"literal\",\"user\":{\"name\":\"nested\"}}";

        String changed = CommandInjectionScanner.replaceJsonValue(
                json, List.of("user.name"), "payload");
        JsonElement parsed = parse(changed);

        assertEquals("payload", parsed.getAsJsonObject().get("user.name").getAsString());
        assertEquals("nested", parsed.getAsJsonObject().getAsJsonObject("user").get("name").getAsString());
    }

    @Test
    void replacesValuesInsideNestedArrays() {
        String json = "{\"jobs\":[{\"command\":\"safe\"}]}";

        String changed = CommandInjectionScanner.replaceJsonValue(
                json, List.of("jobs", 0, "command"), "&& whoami");

        assertEquals("&& whoami", parse(changed).getAsJsonObject().getAsJsonArray("jobs")
                .get(0).getAsJsonObject().get("command").getAsString());
    }

    @Test
    void replacesAValueAcrossManyMixedNestingLayers() {
        String json = "{\"a\":[{\"b\":{\"c\":[{\"d\":{\"e\":[{\"command\":\"safe\"}]}}]}}]}";

        String changed = CommandInjectionScanner.replaceJsonValue(json,
                List.of("a", 0, "b", "c", 0, "d", "e", 0, "command"), "|whoami");

        JsonElement command = parse(changed);
        for (Object part : List.of("a", 0, "b", "c", 0, "d", "e", 0, "command")) {
            command = part instanceof String key
                    ? command.getAsJsonObject().get(key)
                    : command.getAsJsonArray().get((Integer) part);
        }
        assertEquals("|whoami", command.getAsString());
    }

    @Test
    void targetIdentityIncludesHostMethodAndLocationButNotQueryValues() {
        String base = CommandInjectionScanner.buildTargetIdentity(
                "https://one.example/api/run?id=1", "GET", "QUERY", "id");

        assertNotEquals(base, CommandInjectionScanner.buildTargetIdentity(
                "https://two.example/api/run?id=1", "GET", "QUERY", "id"));
        assertNotEquals(base, CommandInjectionScanner.buildTargetIdentity(
                "https://one.example/api/run?id=1", "POST", "QUERY", "id"));
        assertNotEquals(base, CommandInjectionScanner.buildTargetIdentity(
                "https://one.example/api/run?id=1", "GET", "HEADER", "id"));
        assertEquals(base, CommandInjectionScanner.buildTargetIdentity(
                "https://one.example:443/api/run?id=999", "GET", "QUERY", "id"));
    }

    private static JsonElement parse(String json) {
        return JsonParser.parseString(json);
    }
}
