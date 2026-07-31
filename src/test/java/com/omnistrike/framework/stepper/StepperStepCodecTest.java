package com.omnistrike.framework.stepper;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the legacy JSON codec retained for safe migration of old state.
 */
class StepperStepCodecTest {

    @Test
    void roundTripPreservesFlagsAndSteps() {
        StepperStepCodec.StepperState s = new StepperStepCodec.StepperState();
        s.enabled = true;
        s.cookieJarEnabled = false;
        s.stopOnFailure = true;
        s.perRequestMode = true;
        s.cacheTtlSeconds = 42;

        StepperStepCodec.StepData step = new StepperStepCodec.StepData();
        step.name = "Login";
        step.enabled = true;
        step.host = "example.com";
        step.port = 443;
        step.secure = true;
        step.requestB64 = "UE9TVCAvbG9naW4="; // arbitrary base64
        StepperStepCodec.RuleData rule = new StepperStepCodec.RuleData();
        rule.name = "token";
        rule.type = "JSON_PATH";
        rule.pattern = "data.token";
        step.rules.add(rule);
        s.steps.add(step);

        s.pinnedVariables.put("auth", "abc");
        s.pinnedCookies.put("SESSION", "xyz");

        StepperStepCodec.StepperState back =
                StepperStepCodec.fromJson(StepperStepCodec.toJson(s));

        assertTrue(back.enabled);
        assertFalse(back.cookieJarEnabled);
        assertTrue(back.stopOnFailure);
        assertTrue(back.perRequestMode);
        assertEquals(42, back.cacheTtlSeconds);

        assertEquals(1, back.steps.size());
        StepperStepCodec.StepData bs = back.steps.get(0);
        assertEquals("Login", bs.name);
        assertEquals("example.com", bs.host);
        assertEquals(443, bs.port);
        assertTrue(bs.secure);
        assertEquals("UE9TVCAvbG9naW4=", bs.requestB64);
        assertEquals(1, bs.rules.size());
        assertEquals("token", bs.rules.get(0).name);
        assertEquals("JSON_PATH", bs.rules.get(0).type);
        assertEquals("data.token", bs.rules.get(0).pattern);

        assertEquals("abc", back.pinnedVariables.get("auth"));
        assertEquals("xyz", back.pinnedCookies.get("SESSION"));
    }

    @Test
    void fromJsonNullOrBlankYieldsEmptyState() {
        assertTrue(StepperStepCodec.fromJson(null).steps.isEmpty());
        assertTrue(StepperStepCodec.fromJson("").steps.isEmpty());
        assertTrue(StepperStepCodec.fromJson("   ").steps.isEmpty());
    }

    @Test
    void fromJsonGarbageYieldsEmptyStateNotException() {
        StepperStepCodec.StepperState s = StepperStepCodec.fromJson("}{not json");
        assertNotNull(s);
        assertNotNull(s.steps);
        assertTrue(s.steps.isEmpty());
        assertNotNull(s.pinnedVariables);
        assertNotNull(s.pinnedCookies);
    }

    @Test
    void emptyStateHasSaneDefaults() {
        StepperStepCodec.StepperState s = StepperStepCodec.fromJson("{}");
        assertFalse(s.enabled);
        assertTrue(s.cookieJarEnabled, "cookie jar defaults on");
        assertEquals(10, s.cacheTtlSeconds);
        assertNotNull(s.steps);
    }
}
