package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SolrQueryScannerTest {

    @Test
    void preservesReverseProxyPrefixBeforeSolr() {
        assertEquals("https://example.com/search",
                SolrQueryScanner.extractBaseUrl(
                        "https://example.com/search/solr/products/select?q=test"));
        assertEquals("https://example.com",
                SolrQueryScanner.extractBaseUrl(
                        "https://example.com/solr/products/select?q=test"));
        assertEquals("https://example.com",
                SolrQueryScanner.extractBaseUrl(
                        "https://example.com/solrish/products/select?q=test"));
    }
}
