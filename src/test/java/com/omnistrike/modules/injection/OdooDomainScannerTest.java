package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OdooDomainScannerTest {

    @Test
    void detectsActualSensitiveValuesAcrossAllRecords() {
        String body = "{\"result\":[{\"password\":false},{\"password\":\"s3cret\"}]}";
        assertTrue(OdooDomainScanner.hasNonTrivialValue(body, "password"));
        assertFalse(OdooDomainScanner.hasNonTrivialValue(
                "{\"result\":[{\"password\":false},{\"password\":\"********\"}]}",
                "password"));
    }

    @Test
    void requiresActualRowsForSearchReadEvidence() {
        assertTrue(OdooDomainScanner.hasNonEmptyJsonRpcResultArray(
                "{\"jsonrpc\":\"2.0\",\"result\":[{\"id\":1}]}"));
        assertFalse(OdooDomainScanner.hasNonEmptyJsonRpcResultArray(
                "{\"jsonrpc\":\"2.0\",\"result\":[]}"));
        assertFalse(OdooDomainScanner.hasNonEmptyJsonRpcResultArray(
                "{\"jsonrpc\":\"2.0\",\"error\":{}}"));
    }

    @Test
    void preservesReverseProxyPrefixForCallKw() {
        assertEquals("/odoo/web/dataset/call_kw",
                OdooDomainScanner.deriveOdooCallKwPath(
                        "https://example.com/odoo/web/dataset/call_kw/res.users/search_read"));
        assertEquals("/web/dataset/call_kw",
                OdooDomainScanner.deriveOdooCallKwPath("https://example.com/web/login"));
    }
}
