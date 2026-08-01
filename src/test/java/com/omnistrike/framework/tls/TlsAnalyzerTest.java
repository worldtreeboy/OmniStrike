package com.omnistrike.framework.tls;

import com.omnistrike.model.Severity;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class TlsAnalyzerTest {

    @Test
    void normalizesDnsUnicodeAndIpTargets() {
        assertEquals("example.com", TlsAnalyzer.normalizeHost(" Example.COM. "));
        assertEquals("xn--bcher-kva.example", TlsAnalyzer.normalizeHost("bücher.example"));
        assertEquals("2001:db8::1", TlsAnalyzer.normalizeHost("[2001:DB8::1]"));
        assertTrue(TlsAnalyzer.isIpLiteral("192.0.2.10"));
        assertTrue(TlsAnalyzer.isIpLiteral("2001:db8::1"));
        assertFalse(TlsAnalyzer.isIpLiteral("999.1.1.1"));
        assertFalse(TlsAnalyzer.isIpLiteral("::::"));
        assertThrows(IllegalArgumentException.class,
                () -> TlsAnalyzer.normalizeHost("https://example.com"));
    }

    @Test
    void formatsIpv6FindingUrlsWithoutAmbiguousAuthorities() {
        assertEquals("https://[2001:db8::1]:8443/",
                TlsAnalyzer.tlsUrl("2001:db8::1", 8443));
        assertEquals("https://example.com/", TlsAnalyzer.tlsUrl("example.com", 443));
    }

    @Test
    void wildcardDnsNamesMatchExactlyOneLabel() {
        assertTrue(TlsAnalyzer.dnsNameMatches("api.example.com", "*.example.com"));
        assertTrue(TlsAnalyzer.dnsNameMatches("api.example.com", "API.EXAMPLE.COM"));
        assertFalse(TlsAnalyzer.dnsNameMatches("example.com", "*.example.com"));
        assertFalse(TlsAnalyzer.dnsNameMatches("v1.api.example.com", "*.example.com"));
        assertFalse(TlsAnalyzer.dnsNameMatches("api.example.com", "api.*.com"));
        assertFalse(TlsAnalyzer.dnsNameMatches("api.com", "*.com"));
    }

    @Test
    void inconclusiveModernProtocolProbesDoNotCreateFalseFindings() {
        TlsResult result = legacyHandshakeResult(
                TlsResult.ProtocolStatus.ERROR,
                TlsResult.ProtocolStatus.BLOCKED_BY_JDK);
        TlsAnalyzer analyzer = new TlsAnalyzer(null, null);
        try {
            analyzer.evaluateIssues(result);
        } finally {
            analyzer.shutdown();
        }

        assertFalse(hasIssue(result, "No modern TLS support"));
        assertFalse(hasIssue(result, "TLS 1.3 not supported"));
    }

    @Test
    void conclusivelyRejectedModernProtocolsAreReported() {
        TlsResult result = legacyHandshakeResult(
                TlsResult.ProtocolStatus.NOT_SUPPORTED,
                TlsResult.ProtocolStatus.NOT_SUPPORTED);
        TlsAnalyzer analyzer = new TlsAnalyzer(null, null);
        try {
            analyzer.evaluateIssues(result);
        } finally {
            analyzer.shutdown();
        }

        assertTrue(hasIssue(result, "No modern TLS support"));
        assertTrue(hasIssue(result, "TLS 1.3 not supported"));
    }

    @Test
    void certificateExpiredLessThanOneDayAgoIsStillExpired() {
        TlsResult result = new TlsResult("example.test", 443);
        long oneHourAgo = result.getTimestampMs() - 3_600_000L;
        result.setHandshakeReached(true);
        result.setCertChain(List.of(cert(0L, oneHourAgo, 0)));
        TlsAnalyzer analyzer = new TlsAnalyzer(null, null);
        try {
            analyzer.evaluateIssues(result);
        } finally {
            analyzer.shutdown();
        }

        TlsResult.Issue issue = result.getIssues().stream()
                .filter(i -> i.title.equals("Certificate expired"))
                .findFirst().orElseThrow();
        assertEquals(Severity.HIGH, issue.severity);
        assertFalse(hasIssue(result, "Certificate expires soon"));
    }

    @Test
    void futureCertificateValidityIsReported() {
        TlsResult result = new TlsResult("example.test", 443);
        long tomorrow = result.getTimestampMs() + 86_400_000L;
        long nextYear = result.getTimestampMs() + 365L * 86_400_000L;
        result.setHandshakeReached(true);
        result.setCertChain(List.of(cert(tomorrow, nextYear, 365)));
        TlsAnalyzer analyzer = new TlsAnalyzer(null, null);
        try {
            analyzer.evaluateIssues(result);
        } finally {
            analyzer.shutdown();
        }

        assertTrue(hasIssue(result, "Certificate is not yet valid"));
    }

    @Test
    void localProtocolClassificationNeverInventsUnsupportedVersions() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);

        Set<String> usable = TlsAnalyzer.jvmSupportedProtocols(context);

        assertTrue(usable.contains("TLSv1.2"));
        assertTrue(usable.stream().allMatch(protocol ->
                List.of(context.createSSLEngine().getSupportedProtocols()).contains(protocol)));
    }

    private static TlsResult legacyHandshakeResult(
            TlsResult.ProtocolStatus tls12, TlsResult.ProtocolStatus tls13) {
        TlsResult result = new TlsResult("example.test", 443);
        result.putProtocol(new TlsResult.ProtocolOutcome(
                "TLSv1.3", tls13, null, "test outcome"));
        result.putProtocol(new TlsResult.ProtocolOutcome(
                "TLSv1.2", tls12, null, "test outcome"));
        result.putProtocol(new TlsResult.ProtocolOutcome(
                "TLSv1.1", TlsResult.ProtocolStatus.SUPPORTED,
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", null));
        result.setHandshakeReached(true);
        return result;
    }

    private static TlsResult.CertInfo cert(long notBeforeMs, long notAfterMs, long days) {
        return new TlsResult.CertInfo(0, "CN=example.test", "CN=Example CA", "01",
                "not-before", "not-after", "SHA256withRSA", "RSA", 2048,
                List.of("example.test"), false, days, notBeforeMs, notAfterMs);
    }

    private static boolean hasIssue(TlsResult result, String title) {
        return result.getIssues().stream().anyMatch(issue -> issue.title.equals(title));
    }
}
