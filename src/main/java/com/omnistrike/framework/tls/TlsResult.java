package com.omnistrike.framework.tls;

import com.omnistrike.model.Severity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Snapshot of one TLS analysis run for a single host:port.
 *
 * Holds:
 *   - per-protocol probe outcomes (TLSv1.3 ... SSLv3, etc.)
 *   - cipher suites the server actually negotiated during probing
 *   - parsed certificate chain (subject, issuer, expiry, signature algorithm,
 *     public-key algorithm and size)
 *   - human-readable issues flagged from the data above (weak protocol, weak
 *     cipher, expired cert, weak signature, ...)
 *
 * Immutable from the engine's perspective once {@link #freeze()} is called.
 */
public class TlsResult {

    public enum ProtocolStatus {
        SUPPORTED,           // server completed handshake
        NOT_SUPPORTED,       // server cleanly refused
        BLOCKED_BY_JDK,      // local JVM disabled the protocol — cannot probe
        ERROR                // network / cert / unexpected error
    }

    public static class ProtocolOutcome {
        public final String protocol;            // e.g. "TLSv1.3"
        public final ProtocolStatus status;
        public final String negotiatedCipher;    // null if not supported
        public final String detail;              // free-text reason for non-success

        public ProtocolOutcome(String protocol, ProtocolStatus status,
                               String negotiatedCipher, String detail) {
            this.protocol = protocol;
            this.status = status;
            this.negotiatedCipher = negotiatedCipher;
            this.detail = detail;
        }
    }

    public static class CertInfo {
        public final int index;
        public final String subject;
        public final String issuer;
        public final String serial;
        public final String notBefore;
        public final String notAfter;
        public final String signatureAlgorithm;
        public final String publicKeyAlgorithm;
        public final int publicKeySize;          // bits, 0 if unknown
        public final List<String> sanEntries;    // SubjectAlternativeName entries
        public final boolean selfSigned;
        public final long daysUntilExpiry;       // negative if expired

        public CertInfo(int index, String subject, String issuer, String serial,
                        String notBefore, String notAfter, String signatureAlgorithm,
                        String publicKeyAlgorithm, int publicKeySize,
                        List<String> sanEntries, boolean selfSigned, long daysUntilExpiry) {
            this.index = index;
            this.subject = subject;
            this.issuer = issuer;
            this.serial = serial;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.signatureAlgorithm = signatureAlgorithm;
            this.publicKeyAlgorithm = publicKeyAlgorithm;
            this.publicKeySize = publicKeySize;
            this.sanEntries = sanEntries == null
                    ? Collections.emptyList() : List.copyOf(sanEntries);
            this.selfSigned = selfSigned;
            this.daysUntilExpiry = daysUntilExpiry;
        }
    }

    public static class Issue {
        public final Severity severity;
        public final String title;
        public final String detail;
        public Issue(Severity severity, String title, String detail) {
            this.severity = severity;
            this.title = title;
            this.detail = detail;
        }
    }

    private final String host;
    private final int port;
    private final long timestampMs;

    // Linked map preserves probe order in the UI (newest protocol first)
    private final Map<String, ProtocolOutcome> protocols = new LinkedHashMap<>();
    private final List<String> supportedCiphers = new ArrayList<>();
    private final List<CertInfo> certChain = new ArrayList<>();
    private final List<Issue> issues = new ArrayList<>();

    private volatile boolean handshakeReached = false;
    private volatile String hostnameMatchError = null;
    private volatile boolean frozen = false;

    public TlsResult(String host, int port) {
        this.host = host;
        this.port = port;
        this.timestampMs = System.currentTimeMillis();
    }

    public String getHost() { return host; }
    public int getPort() { return port; }
    public long getTimestampMs() { return timestampMs; }
    public boolean isHandshakeReached() { return handshakeReached; }
    public String getHostnameMatchError() { return hostnameMatchError; }

    public Map<String, ProtocolOutcome> getProtocols() {
        return Collections.unmodifiableMap(protocols);
    }

    public List<String> getSupportedCiphers() {
        return Collections.unmodifiableList(supportedCiphers);
    }

    public List<CertInfo> getCertChain() {
        return Collections.unmodifiableList(certChain);
    }

    public List<Issue> getIssues() {
        return Collections.unmodifiableList(issues);
    }

    // ── Mutators (engine-side; UI receives a frozen snapshot) ──────────────

    void putProtocol(ProtocolOutcome outcome) {
        if (frozen) return;
        protocols.put(outcome.protocol, outcome);
    }

    void addCipher(String cipher) {
        if (frozen) return;
        if (cipher != null && !supportedCiphers.contains(cipher)) {
            supportedCiphers.add(cipher);
        }
    }

    void setCertChain(List<CertInfo> chain) {
        if (frozen) return;
        certChain.clear();
        if (chain != null) certChain.addAll(chain);
    }

    void setHandshakeReached(boolean reached) {
        if (!frozen) handshakeReached = reached;
    }

    void setHostnameMatchError(String err) {
        if (!frozen) hostnameMatchError = err;
    }

    void addIssue(Issue issue) {
        if (frozen) return;
        if (issue != null) issues.add(issue);
    }

    void freeze() {
        frozen = true;
    }

    /** Returns true iff at least one protocol probe completed a handshake. */
    public boolean hasAnySupportedProtocol() {
        return protocols.values().stream()
                .anyMatch(o -> o.status == ProtocolStatus.SUPPORTED);
    }

    /** Highest protocol observed as SUPPORTED, or null if none. */
    public String getStrongestProtocol() {
        // Iterate in TlsAnalyzer.PROBE_PROTOCOLS order (strongest first).
        for (ProtocolOutcome o : protocols.values()) {
            if (o.status == ProtocolStatus.SUPPORTED) return o.protocol;
        }
        return null;
    }
}
