package com.omnistrike.framework;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests scope/host parsing. These guard what OmniStrike will touch, so the
 * host-extraction and matching rules are security-relevant (e.g. userinfo
 * bypass prevention, no over-broad subdomain matches).
 */
class ScopeManagerTest {

    @Test
    void emptyScopeMatchesNothing() {
        ScopeManager s = new ScopeManager();
        assertFalse(s.hasScope());
        assertFalse(s.isInScope("example.com"));
    }

    @Test
    void domainAndSubdomainsAreInScope() {
        ScopeManager s = new ScopeManager();
        s.setTargetDomains("example.com");
        assertTrue(s.hasScope());
        assertTrue(s.isInScope("example.com"));
        assertTrue(s.isInScope("api.example.com"));
        assertTrue(s.isInScope("API.Example.COM"), "host match is case-insensitive");
    }

    @Test
    void lookalikeDomainsAreNotInScope() {
        ScopeManager s = new ScopeManager();
        s.setTargetDomains("example.com");
        assertFalse(s.isInScope("notexample.com"));
        assertFalse(s.isInScope("example.com.evil.com"), "suffix-injection must not match");
        assertFalse(s.isInScope(null));
    }

    @Test
    void bareTldIsRejectedAsTooBroad() {
        ScopeManager s = new ScopeManager();
        s.setTargetDomains("com");
        assertFalse(s.hasScope(), "bare TLD should be dropped");
        assertFalse(s.isInScope("example.com"));
    }

    @Test
    void multipleDomainsCommaSeparated() {
        ScopeManager s = new ScopeManager();
        s.setTargetDomains("example.com, test.org");
        assertTrue(s.isInScope("example.com"));
        assertTrue(s.isInScope("test.org"));
        assertTrue(s.isInScope("a.test.org"));
        assertFalse(s.isInScope("other.net"));
    }

    @Test
    void extractHostStripsUserinfo() {
        // http://attacker@target.com/ must resolve to target.com, not attacker.
        assertEquals("target.com", ScopeManager.extractHost("http://user:pass@target.com/path"));
        assertEquals("target.com", ScopeManager.extractHost("http://attacker@target.com/"));
    }

    @Test
    void extractHostStripsPort() {
        assertEquals("example.com", ScopeManager.extractHost("https://example.com:8080/x"));
    }

    @Test
    void extractHostHandlesIpv6Brackets() {
        assertEquals("::1", ScopeManager.extractHost("http://[::1]:8080/x"));
    }

    @Test
    void extractHostNullSafe() {
        assertNull(ScopeManager.extractHost(null));
    }

    @Test
    void excludedPathMatchesRegardlessOfQuery() {
        ScopeManager s = new ScopeManager();
        assertFalse(s.isExcludedPath("https://x.com/logout"), "no exclusions configured");
        s.setExcludedPaths("/logout");
        assertTrue(s.isExcludedPath("https://x.com/logout?next=/home"));
        assertFalse(s.isExcludedPath("https://x.com/login"));
    }

    @Test
    void inclusionListGatesWhenNonEmpty() {
        ScopeManager s = new ScopeManager();
        // Empty inclusion list → everything allowed.
        assertTrue(s.isIncludedPath("https://x.com/anything"));
        s.setIncludedPaths("/api");
        assertTrue(s.isIncludedPath("https://x.com/api/v1/users"));
        assertFalse(s.isIncludedPath("https://x.com/admin"));
    }
}
