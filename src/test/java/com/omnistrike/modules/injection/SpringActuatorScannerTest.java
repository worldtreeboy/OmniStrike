package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SpringActuatorScannerTest {

    @Test
    void resolvesCanonicalEndpointsAgainstDiscoveredRoot() {
        assertEquals("/actuator/env",
                SpringActuatorScanner.resolveActuatorEndpoint("/actuator", "/actuator/env"));
        assertEquals("/manage/env",
                SpringActuatorScanner.resolveActuatorEndpoint("/manage", "/actuator/env"));
        assertEquals("/app/actuator/env",
                SpringActuatorScanner.resolveActuatorEndpoint("/app/actuator/", "/actuator/env"));
    }

    @Test
    void extractsObservedActuatorRootIncludingApplicationPrefix() {
        assertEquals("/app/actuator", SpringActuatorScanner.extractActuatorRootFromUrl(
                "https://example.com/app/actuator/health?details=true"));
        assertEquals("/manage", SpringActuatorScanner.extractActuatorRootFromUrl(
                "https://example.com/manage/info"));
        assertNull(SpringActuatorScanner.extractActuatorRootFromUrl(
                "https://example.com/api/health"));
        assertNull(SpringActuatorScanner.extractActuatorRootFromUrl(
                "https://example.com/management/health"));
    }
}
