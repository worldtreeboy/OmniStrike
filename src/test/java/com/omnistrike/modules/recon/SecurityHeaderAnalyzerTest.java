package com.omnistrike.modules.recon;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecurityHeaderAnalyzerTest {

    @Test
    void cookieFlagsAreParsedAsAttributesNotValueSubstrings() {
        String cookie = "sessionid=contains-secure-and-httponly; Path=/; SameSite=None";

        assertFalse(SecurityHeaderAnalyzer.hasCookieAttribute(cookie, "Secure"));
        assertFalse(SecurityHeaderAnalyzer.hasCookieAttribute(cookie, "HttpOnly"));
        assertEquals("None", SecurityHeaderAnalyzer.cookieAttributeValue(cookie, "SameSite"));
    }

    @Test
    void recognizesCommonSessionNamesWithoutTreatingCsrfCookieAsSession() {
        assertTrue(SecurityHeaderAnalyzer.looksLikeSessionCookie("JSESSIONID"));
        assertTrue(SecurityHeaderAnalyzer.looksLikeSessionCookie("connect.sid"));
        assertTrue(SecurityHeaderAnalyzer.looksLikeSessionCookie("access_token"));
        assertFalse(SecurityHeaderAnalyzer.looksLikeSessionCookie("XSRF-TOKEN"));
    }
}
