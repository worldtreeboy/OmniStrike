package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SstiScannerTest {
    @Test
    void expectedMatcherRejectsReflectionAndTokensEmbeddedInPayload() {
        assertNull(SstiScanner.matchExpected("{{7*7}}", "baseline", "{{7*7}}", "49"));
        assertNull(SstiScanner.matchExpected("result 131803", "baseline",
                "{if 133*991==131803}131803{/if}", "131803"));
        assertEquals("131803", SstiScanner.matchExpected(
                "result 131803", "baseline", "{{133*991}}", "131803"));
    }

    @Test
    void safeModeClassifierRecognizesExecutionAndDataExposureProbes() {
        assertTrue(SstiScanner.isAggressivePolyglot(
                "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}"));
        assertTrue(SstiScanner.isAggressivePolyglot("{% debug %}"));
        assertTrue(SstiScanner.isAggressivePolyglot("{{constructor.constructor('return 1')()}}"));
        assertFalse(SstiScanner.isAggressivePolyglot("{{133*991}}"));
    }

    @Test
    void safeModeClassifiesEngineProbesThatExposeRuntimeState() {
        assertTrue(SstiScanner.isAggressiveEngineProbe(
                "{{request.environ}}", "Flask request object"));
        assertTrue(SstiScanner.isAggressiveEngineProbe(
                "${\"freemarker.template.utility.ObjectConstructor\"?new()}", "Freemarker OC"));
        assertTrue(SstiScanner.isAggressiveEngineProbe(
                "{% load log %}{% get_admin_log 10 as log %}{{log}}", "Django admin log"));
        assertFalse(SstiScanner.isAggressiveEngineProbe(
                "{{133|multiply:991}}", "Twig multiply filter"));
    }

    @Test
    void oobTemplatesAreUniqueCorrelatableAndNonPersistent() throws Exception {
        Field field = SstiScanner.class.getDeclaredField("OOB_SSTI_PAYLOADS");
        field.setAccessible(true);
        String[][] payloads = (String[][]) field.get(null);
        Set<String> unique = new HashSet<>();
        for (String[] payload : payloads) {
            assertTrue(payload[0].contains("COLLAB_PLACEHOLDER"), payload[0]);
            assertTrue(unique.add(payload[0]), payload[0]);
            assertFalse(payload[0].contains("Write_File"), payload[0]);
            assertFalse(payload[0].contains("get_admin_log"), payload[0]);
        }
    }
}
