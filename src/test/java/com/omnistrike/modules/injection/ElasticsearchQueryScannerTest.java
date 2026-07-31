package com.omnistrike.modules.injection;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ElasticsearchQueryScannerTest {

    @Test
    void nestedQueryIsReplacedAsValidJsonWithoutLosingSiblingFields() {
        String input = "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"role\":\"admin\"}}]}},\"size\":25}";

        JsonObject changed = JsonParser.parseString(
                ElasticsearchQueryScanner.replaceRootQueryWithMatchAll(input)).getAsJsonObject();

        assertEquals(25, changed.get("size").getAsInt());
        assertEquals(0, changed.getAsJsonObject("query")
                .getAsJsonObject("match_all").size());
    }
}
