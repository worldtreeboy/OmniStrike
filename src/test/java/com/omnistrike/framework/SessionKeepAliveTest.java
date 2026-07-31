package com.omnistrike.framework;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

/** Source-level security rules for Session Keep-Alive. */
class SessionKeepAliveTest {

    @Test
    void credentialsDependOnLoginOriginNotPreviousRedirectHop() {
        String login = "https://login.example:443";
        String attacker = "https://attacker.example:443";

        assertTrue(SessionKeepAlive.maySendCredentials(login, login));
        assertFalse(SessionKeepAlive.maySendCredentials(login, attacker));
        // Models login -> attacker -> attacker. The second target equals the
        // previous hop, but it still must not receive the saved login headers.
        assertFalse(SessionKeepAlive.maySendCredentials(login, attacker));
        assertFalse(SessionKeepAlive.maySendCredentials(login, null));
    }

    @Test
    void only307And308PreserveLoginMethodAndBody() {
        assertFalse(SessionKeepAlive.preservesMethodAndBody(301));
        assertFalse(SessionKeepAlive.preservesMethodAndBody(302));
        assertFalse(SessionKeepAlive.preservesMethodAndBody(303));
        assertTrue(SessionKeepAlive.preservesMethodAndBody(307));
        assertTrue(SessionKeepAlive.preservesMethodAndBody(308));
    }

    @Test
    void redirectHeaderFilterRejectsCredentialsAndHopByHopHeaders() {
        assertFalse(SessionKeepAlive.isSafeRedirectHeader("Authorization"));
        assertFalse(SessionKeepAlive.isSafeRedirectHeader("cookie"));
        assertFalse(SessionKeepAlive.isSafeRedirectHeader("Transfer-Encoding"));
        assertFalse(SessionKeepAlive.isSafeRedirectHeader("Connection"));
        assertTrue(SessionKeepAlive.isSafeRedirectHeader("Content-Type"));
        assertTrue(SessionKeepAlive.isSafeRedirectHeader("X-CSRF-Token"));
    }

    @Test
    void redirectLocationsResolveAgainstTheCurrentDirectory() {
        assertEquals("https://example.test/login/continue",
                SessionKeepAlive.resolveRedirectUrl(
                        "https://example.test/login/start", "continue"));
        assertEquals("https://example.test/continue",
                SessionKeepAlive.resolveRedirectUrl(
                        "https://example.test/login/start", "/continue"));
        assertEquals("https://other.test/next",
                SessionKeepAlive.resolveRedirectUrl(
                        "https://example.test/login/start", "//other.test/next"));
    }

    @Test
    void hostOnlyCookieNeverRidesToSubdomain() {
        assertTrue(SessionKeepAlive.cookieMatches(
                "example.com", "/", true, "example.com", true, "/", true));
        assertFalse(SessionKeepAlive.cookieMatches(
                "api.example.com", "/", true, "example.com", true, "/", true));
    }

    @Test
    void validatedDomainCookieMayRideToSubdomain() {
        assertTrue(SessionKeepAlive.domainMatches("auth.example.com", "example.com"));
        assertTrue(SessionKeepAlive.cookieMatches(
                "api.example.com", "/", true, "example.com", false, "/", true));
        assertFalse(SessionKeepAlive.cookieMatches(
                "notexample.com", "/", true, "example.com", false, "/", true));
        assertFalse(SessionKeepAlive.domainMatches("auth.example.com", "evil.example"));
    }

    @Test
    void secureAndPathScopeAreEnforced() {
        assertFalse(SessionKeepAlive.cookieMatches(
                "example.com", "/app", false, "example.com", true, "/app", true));
        assertTrue(SessionKeepAlive.cookieMatches(
                "example.com", "/app/dashboard", true, "example.com", true, "/app", true));
        assertFalse(SessionKeepAlive.cookieMatches(
                "example.com", "/apple", true, "example.com", true, "/app", true));
    }

    @Test
    void secureAttributeParsingIsCaseInsensitive() {
        assertTrue(SessionKeepAlive.hasSecureAttribute("a=1; Secure; HttpOnly; Path=/"));
        assertTrue(SessionKeepAlive.hasSecureAttribute("a=1; secure"));
        assertFalse(SessionKeepAlive.hasSecureAttribute("a=1; Path=/"));
    }

    @Test
    void originNormalizesSchemeHostAndEffectivePort() throws Exception {
        Method origin = SessionKeepAlive.class.getDeclaredMethod(
                "origin", String.class, String.class, int.class);
        origin.setAccessible(true);

        assertEquals("https://example.com:443", origin.invoke(null, "https", "example.com", -1));
        assertEquals("http://example.com:80", origin.invoke(null, "http", "example.com", -1));
        assertEquals("http://example.com:8080", origin.invoke(null, "http", "example.com", 8080));
        assertNotEquals(origin.invoke(null, "https", "example.com", -1),
                origin.invoke(null, "http", "example.com", -1));
        assertNotEquals(origin.invoke(null, "https", "example.com", -1),
                origin.invoke(null, "https", "example.com", 8443));
    }
}
