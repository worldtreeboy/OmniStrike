package com.omnistrike.modules.injection;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ElasticsearchQueryScannerTest {

    @Test
    void identifiesOnlyReadOnlySearchResourcesForBodyMutation() {
        assertTrue(ElasticsearchQueryScanner.isSearchEndpoint("https://host/index/_search?q=x"));
        assertTrue(ElasticsearchQueryScanner.isSearchEndpoint("https://host/es/index/_search/template"));
        assertFalse(ElasticsearchQueryScanner.isSearchEndpoint("https://host/index/_update/1"));
        assertFalse(ElasticsearchQueryScanner.isSearchEndpoint("https://host/_bulk"));
    }

    @Test
    void preservesReverseProxyPrefixForMappingAndClusterProbes() {
        String url = "https://host.example/es/customer-index/_search?q=x";
        assertEquals("customer-index", ElasticsearchQueryScanner.extractIndexFromUrl(url));
        assertEquals("https://host.example/es/customer-index/_mapping",
                ElasticsearchQueryScanner.buildMappingUrl(url));
        assertEquals("https://host.example/es", ElasticsearchQueryScanner.extractBaseUrl(url));
    }

    @Test
    void buildsSafeScriptFieldsCanaryWithoutDroppingOriginalQuery() {
        String result = ElasticsearchQueryScanner.buildScriptFieldsProbe(
                "{\"query\":{\"term\":{\"active\":true}}}");

        assertNotNull(result);
        assertTrue(result.contains("omnistrike_script_canary"));
        assertTrue(result.contains("\"term\""));
        assertTrue(result.contains("\"script_fields\""));
    }

    @Test
    void rejectsNonJsonScriptProbeBodies() {
        assertNull(ElasticsearchQueryScanner.buildScriptFieldsProbe("q=test"));
    }

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
