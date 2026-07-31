package com.omnistrike.framework;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class ScanTargetIdentityTest {
    @Test
    void scopesByOriginMethodTypeAndTargetButIgnoresQueryValues() {
        String base = ScanTargetIdentity.build(
                "https://one.example/api/run?id=1", "GET", "QUERY", "id");
        assertNotEquals(base, ScanTargetIdentity.build(
                "https://two.example/api/run?id=1", "GET", "QUERY", "id"));
        assertNotEquals(base, ScanTargetIdentity.build(
                "https://one.example/api/run?id=1", "POST", "QUERY", "id"));
        assertNotEquals(base, ScanTargetIdentity.build(
                "https://one.example/api/run?id=1", "GET", "HEADER", "id"));
        assertEquals(base, ScanTargetIdentity.build(
                "https://ONE.example:443/api/run?id=999", "GET", "QUERY", "id"));
    }
}
