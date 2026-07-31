package com.omnistrike.framework.stepper;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the RFC 6265-style scoping in {@link StepperEngine#cookieMatches} that
 * keeps chain-collected cookies from leaking cross-host, cross-scheme, or
 * cross-path. Pinned/manually-added cookies (null origin) stay global.
 */
class StepperEngineCookieMatchTest {

    private static ChainContext.CookieOrigin origin(String host, String domain,
                                                    boolean secure, String path) {
        return new ChainContext.CookieOrigin(host, domain, secure, path);
    }

    @Test
    void hostOnlyCookieNotSentToSubdomain() {
        ChainContext.CookieOrigin o = origin("example.com", null, false, "/");
        assertTrue(StepperEngine.cookieMatches("example.com", "/", false, o));
        assertFalse(StepperEngine.cookieMatches("api.example.com", "/", false, o));
        assertFalse(StepperEngine.cookieMatches("other.com", "/", false, o));
    }

    @Test
    void domainCookieSentToSubdomain() {
        ChainContext.CookieOrigin o = origin("example.com", "example.com", false, "/");
        assertTrue(StepperEngine.cookieMatches("example.com", "/", false, o));
        assertTrue(StepperEngine.cookieMatches("api.example.com", "/", false, o));
        assertTrue(StepperEngine.cookieMatches("deep.api.example.com", "/", false, o));
        assertFalse(StepperEngine.cookieMatches("other.com", "/", false, o));
        // Suffix attack: "notexample.com" is not a subdomain of "example.com".
        assertFalse(StepperEngine.cookieMatches("notexample.com", "/", false, o));
    }

    @Test
    void secureAttributeCookieBlockedOverHttp() {
        ChainContext.CookieOrigin o = origin("example.com", null, true, "/");
        assertTrue(StepperEngine.cookieMatches("example.com", "/", true, o));
        assertFalse(StepperEngine.cookieMatches("example.com", "/", false, o));
    }

    @Test
    void pathMismatchBlocked() {
        ChainContext.CookieOrigin o = origin("example.com", null, false, "/app");
        assertTrue(StepperEngine.cookieMatches("example.com", "/app", false, o));
        assertTrue(StepperEngine.cookieMatches("example.com", "/app/dashboard", false, o));
        assertFalse(StepperEngine.cookieMatches("example.com", "/other", false, o));
        assertFalse(StepperEngine.cookieMatches("example.com", "/", false, o));
        assertFalse(StepperEngine.cookieMatches("example.com", "/apple", false, o),
                "RFC path matching must not treat /app as a prefix of /apple");
    }

    @Test
    void settingHostMustDomainMatchDomainAttribute() {
        assertTrue(StepperEngine.domainMatches("auth.example.com", "example.com"));
        assertFalse(StepperEngine.domainMatches("auth.example.com", "evil.example"));
        assertFalse(StepperEngine.domainMatches("notexample.com", "example.com"));
    }

    @Test
    void sameNameDifferentPathsHaveSeparateStorageKeys() {
        ChainContext ctx = new ChainContext();
        ChainContext.CookieOrigin root = origin("example.com", null, false, "/");
        ChainContext.CookieOrigin app = origin("example.com", null, false, "/app");
        ctx.scopedCookies.put(new ChainContext.CookieKey("sid", "example.com", "/"),
                new ChainContext.ScopedCookie("sid", "root", root, 1));
        ctx.scopedCookies.put(new ChainContext.CookieKey("sid", "example.com", "/app"),
                new ChainContext.ScopedCookie("sid", "app", app, 2));

        assertEquals(2, ctx.scopedCookies.size());
    }

    @Test
    void pinnedCookieWithNullOriginAlwaysAllowed() {
        assertTrue(StepperEngine.cookieMatches("anything.example.com", "/anywhere", false, null));
        assertTrue(StepperEngine.cookieMatches("other.org", "/", true, null));
    }

    @Test
    void cacheRequiresCompleteAndEntirelySuccessfulRun() {
        assertTrue(StepperEngine.shouldStampCache(true, true, true));
        assertFalse(StepperEngine.shouldStampCache(false, true, true));
        assertFalse(StepperEngine.shouldStampCache(true, false, true),
                "one successful step plus one failed step must not stamp the cache");
        assertFalse(StepperEngine.shouldStampCache(true, true, false),
                "an all-disabled chain must not stamp the cache");
    }
}
