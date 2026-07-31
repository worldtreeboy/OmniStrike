package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class XxeScannerTest {
    @Test
    void oobConfirmationKeyIsEndpointScopedAndIgnoresQueryValues() {
        assertEquals(XxeScanner.oobEndpointKey("https://one.example/xml?id=1"),
                XxeScanner.oobEndpointKey("https://ONE.example:443/xml?id=2"));
        assertNotEquals(XxeScanner.oobEndpointKey("https://one.example/xml"),
                XxeScanner.oobEndpointKey("https://two.example/xml"));
        assertNotEquals(XxeScanner.oobEndpointKey("https://one.example/xml"),
                XxeScanner.oobEndpointKey("https://one.example/other"));
    }
}
