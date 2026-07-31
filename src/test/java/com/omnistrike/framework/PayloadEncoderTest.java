package com.omnistrike.framework;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PayloadEncoderTest {

    @Test
    void replacesOnlyTheExactCookieName() {
        assertEquals("userid=one; id=attack; theme=dark",
                PayloadEncoder.replaceCookieHeaderValue(
                        "userid=one; id=old; theme=dark", "id", "attack"));
    }

    @Test
    void appendsMissingCookieWithoutDroppingExistingCookies() {
        assertEquals("session=secret; theme=dark; probe=value",
                PayloadEncoder.replaceCookieHeaderValue(
                        "session=secret; theme=dark", "probe", "value"));
    }
}
