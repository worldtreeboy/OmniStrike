package com.omnistrike.framework.tls;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.Confidence;
import com.omnistrike.model.Finding;
import com.omnistrike.model.Severity;

import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * TLS / SSL analysis engine.
 *
 * Burp's Montoya API does not expose the negotiated TLS protocol or cipher
 * suite for the connections it makes. To learn what a target supports we open
 * our own {@code SSLSocket} from the plugin process and inspect what JSSE
 * negotiates. Each protocol version is probed individually so we can report
 * the full support matrix (TLSv1.3, TLSv1.2, TLSv1.1, TLSv1, SSLv3) instead
 * of just the single version Burp happens to use.
 *
 * Limitations to call out in the UI:
 *   - Modern JDKs disable SSLv3 / TLSv1 / TLSv1.1 by default. If the local
 *     JVM disables a protocol we cannot probe it; the result reports
 *     {@link TlsResult.ProtocolStatus#BLOCKED_BY_JDK} so the user knows the
 *     server's actual posture is unknown for that version.
 *   - Probes use a permissive {@link X509TrustManager}: the goal is to learn
 *     what the server is willing to negotiate, not to validate its chain.
 *     Chain-issue detection (self-signed, expired, weak signature) is done
 *     after the handshake by inspecting {@link X509Certificate} fields.
 *
 * Analyses run on a small dedicated thread pool. Results are cached per
 * "host:port" so repeating an analysis on the same target reuses the prior
 * snapshot until {@link #invalidate(String, int)} is called.
 */
public class TlsAnalyzer {

    /** Protocols probed, ordered strongest → weakest. */
    public static final List<String> PROBE_PROTOCOLS = List.of(
            "TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"
    );

    private static final Set<String> WEAK_PROTOCOLS = Set.of(
            "SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1"
    );

    private static final int CONNECT_TIMEOUT_MS = 6000;
    private static final int READ_TIMEOUT_MS    = 6000;

    // Lowercase substring → severity.
    // Order matters only insofar as we report the worst issue per cipher.
    private static final Map<String, Severity> CIPHER_RED_FLAGS = new LinkedHashMap<>() {{
        put("_null_",          Severity.CRITICAL);
        put("_anon_",          Severity.CRITICAL);
        put("_export",         Severity.CRITICAL);
        put("_des_",           Severity.HIGH);
        put("_3des_",          Severity.HIGH);
        put("_rc4_",           Severity.HIGH);
        put("_rc2_",           Severity.HIGH);
        put("_md5",            Severity.MEDIUM);
        put("_idea_",          Severity.MEDIUM);
        put("_seed_",          Severity.LOW);
        put("_cbc_",           Severity.LOW);   // CBC w/o AEAD — informational
    }};

    private final MontoyaApi api;
    private final FindingsStore findingsStore;
    private final ExecutorService executor;

    private final ConcurrentHashMap<String, TlsResult> cache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AnalysisHandle> active = new ConcurrentHashMap<>();

    private volatile BiConsumer<String, String> uiLogger;

    public TlsAnalyzer(MontoyaApi api, FindingsStore findingsStore) {
        this.api = api;
        this.findingsStore = findingsStore;
        this.executor = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "OmniStrike-TLSAnalyzer");
            t.setDaemon(true);
            return t;
        });
    }

    public void setUiLogger(BiConsumer<String, String> logger) { this.uiLogger = logger; }

    public TlsResult getCached(String host, int port) {
        return cache.get(key(host, port));
    }

    public void invalidate(String host, int port) {
        cache.remove(key(host, port));
    }

    public void invalidateAll() { cache.clear(); }

    /**
     * Cancel an in-flight analysis for a host:port if one is running.
     * Returns true if a task was cancelled.
     */
    public boolean cancel(String host, int port) {
        AnalysisHandle h = active.remove(key(host, port));
        if (h == null) return false;
        h.cancelled.set(true);
        h.future.cancel(true);
        return true;
    }

    public boolean isRunning(String host, int port) {
        AnalysisHandle h = active.get(key(host, port));
        return h != null && !h.future.isDone();
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    /**
     * Run a full analysis (protocol matrix + cipher enumeration + cert chain
     * + issue flagging) asynchronously. Result is delivered to {@code onComplete}
     * on a background thread; the UI is responsible for marshalling onto the EDT.
     *
     * @param enumerateCiphers if true, probes individual cipher suites — slow
     *                         but produces a complete weak-cipher list. If
     *                         false, only the single cipher negotiated per
     *                         protocol probe is recorded.
     */
    public void analyze(String host, int port, boolean enumerateCiphers,
                        boolean reportFindings,
                        Consumer<TlsResult> onComplete) {
        if (host == null || host.isBlank() || port <= 0 || port > 65535) {
            log("Invalid target: " + host + ":" + port);
            if (onComplete != null) onComplete.accept(null);
            return;
        }
        final String cacheKey = key(host, port);
        AnalysisHandle existing = active.get(cacheKey);
        if (existing != null && !existing.future.isDone()) {
            log("Analysis already in progress for " + cacheKey);
            return;
        }
        AtomicBoolean cancelled = new AtomicBoolean(false);
        Future<?> future = executor.submit(() -> {
            TlsResult result = new TlsResult(host, port);
            try {
                log("Starting TLS analysis: " + host + ":" + port);
                probeProtocols(host, port, result, cancelled);
                if (cancelled.get()) return;

                if (enumerateCiphers && result.hasAnySupportedProtocol()) {
                    log("Enumerating cipher suites for " + cacheKey + " ...");
                    enumerateCipherSuites(host, port, result, cancelled);
                }
                if (cancelled.get()) return;

                fetchCertificateChain(host, port, result, cancelled);
                if (cancelled.get()) return;

                evaluateIssues(result);
                result.freeze();
                cache.put(cacheKey, result);

                if (reportFindings && findingsStore != null) {
                    publishFindings(host, port, result);
                }

                log("Analysis complete: " + cacheKey
                        + " — " + result.getProtocols().size() + " protocols probed, "
                        + result.getSupportedCiphers().size() + " cipher(s), "
                        + result.getCertChain().size() + " cert(s), "
                        + result.getIssues().size() + " issue(s).");
            } catch (Throwable t) {
                log("TLS analysis failed for " + cacheKey + ": " + t.getMessage());
            } finally {
                active.remove(cacheKey);
                if (onComplete != null) onComplete.accept(result);
            }
        });
        active.put(cacheKey, new AnalysisHandle(future, cancelled));
    }

    // ── Protocol probing ───────────────────────────────────────────────────

    private void probeProtocols(String host, int port, TlsResult result,
                                AtomicBoolean cancelled) {
        SSLContext ctx = buildPermissiveContext();
        if (ctx == null) {
            log("Could not build SSLContext — aborting probe");
            return;
        }
        Set<String> jvmEnabled = Set.of(((SSLSocketFactory)
                ctx.getSocketFactory()).getSupportedCipherSuites());

        // Determine which protocols this JVM permits us to enable. Anything
        // outside this set is BLOCKED_BY_JDK.
        Set<String> jvmProtocols = jvmSupportedProtocols(ctx);

        for (String proto : PROBE_PROTOCOLS) {
            if (cancelled.get()) return;
            if (!jvmProtocols.contains(proto)) {
                result.putProtocol(new TlsResult.ProtocolOutcome(
                        proto, TlsResult.ProtocolStatus.BLOCKED_BY_JDK,
                        null, "Disabled in jdk.tls.disabledAlgorithms"));
                continue;
            }
            TlsResult.ProtocolOutcome outcome = singleProtocolProbe(ctx, host, port, proto);
            result.putProtocol(outcome);
            if (outcome.status == TlsResult.ProtocolStatus.SUPPORTED) {
                result.addCipher(outcome.negotiatedCipher);
                result.setHandshakeReached(true);
            }
        }

        // Suppress unused warning — we may surface jvmEnabled later.
        if (jvmEnabled.isEmpty()) { /* no-op */ }
    }

    private TlsResult.ProtocolOutcome singleProtocolProbe(SSLContext ctx, String host,
                                                          int port, String proto) {
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            s.setSoTimeout(READ_TIMEOUT_MS);
            // Set both protocol AND SNI; servers often reject without SNI on TLS 1.2+
            s.setEnabledProtocols(new String[]{proto});
            SSLParameters params = s.getSSLParameters();
            params.setServerNames(List.of(new javax.net.ssl.SNIHostName(host)));
            // Allow every cipher this JVM has — server picks
            params.setCipherSuites(s.getSupportedCipherSuites());
            s.setSSLParameters(params);
            s.startHandshake();
            SSLSession sess = s.getSession();
            return new TlsResult.ProtocolOutcome(proto,
                    TlsResult.ProtocolStatus.SUPPORTED,
                    sess.getCipherSuite(), null);
        } catch (javax.net.ssl.SSLHandshakeException e) {
            return new TlsResult.ProtocolOutcome(proto,
                    TlsResult.ProtocolStatus.NOT_SUPPORTED,
                    null, condense(e.getMessage()));
        } catch (Exception e) {
            return new TlsResult.ProtocolOutcome(proto,
                    TlsResult.ProtocolStatus.ERROR,
                    null, condense(e.getClass().getSimpleName() + ": " + e.getMessage()));
        }
    }

    private Set<String> jvmSupportedProtocols(SSLContext ctx) {
        try {
            SSLEngine engine = ctx.createSSLEngine();
            return new HashSet<>(Arrays.asList(engine.getSupportedProtocols()));
        } catch (Exception e) {
            return Set.of("TLSv1.3", "TLSv1.2"); // safe default
        }
    }

    // ── Cipher enumeration ─────────────────────────────────────────────────

    private void enumerateCipherSuites(String host, int port, TlsResult result,
                                        AtomicBoolean cancelled) {
        SSLContext ctx = buildPermissiveContext();
        if (ctx == null) return;
        String[] allCiphers;
        try {
            allCiphers = ctx.getSocketFactory().getSupportedCipherSuites();
        } catch (Exception e) {
            return;
        }

        // Probe one cipher at a time against each protocol the server actually
        // supports. Linear in #ciphers × #protocols, but bounded by JDK list
        // (typically 30-50 ciphers, 1-2 protocols). Stays under ~100 connections.
        List<String> serverProtocols = new ArrayList<>();
        for (TlsResult.ProtocolOutcome o : result.getProtocols().values()) {
            if (o.status == TlsResult.ProtocolStatus.SUPPORTED) {
                serverProtocols.add(o.protocol);
            }
        }

        for (String cipher : allCiphers) {
            if (cancelled.get()) return;
            for (String proto : serverProtocols) {
                if (probeSingleCipher(ctx, host, port, proto, cipher)) {
                    result.addCipher(cipher);
                    break; // already added — no need to test under other protocols
                }
            }
        }
    }

    private boolean probeSingleCipher(SSLContext ctx, String host, int port,
                                      String protocol, String cipher) {
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            s.setSoTimeout(READ_TIMEOUT_MS);
            try {
                s.setEnabledProtocols(new String[]{protocol});
                s.setEnabledCipherSuites(new String[]{cipher});
            } catch (IllegalArgumentException unsupported) {
                return false;
            }
            SSLParameters params = s.getSSLParameters();
            params.setServerNames(List.of(new javax.net.ssl.SNIHostName(host)));
            s.setSSLParameters(params);
            s.startHandshake();
            return cipher.equals(s.getSession().getCipherSuite());
        } catch (Exception e) {
            return false;
        }
    }

    // ── Certificate chain ──────────────────────────────────────────────────

    private void fetchCertificateChain(String host, int port, TlsResult result,
                                       AtomicBoolean cancelled) {
        if (cancelled.get()) return;
        SSLContext ctx = buildPermissiveContext();
        if (ctx == null) return;

        // First try with hostname verification ON to see whether the cert
        // matches the requested host. Then re-fetch permissively if needed.
        boolean nameMatches = checkHostnameMatch(ctx, host, port, result);
        if (cancelled.get()) return;

        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            s.setSoTimeout(READ_TIMEOUT_MS);
            SSLParameters params = s.getSSLParameters();
            params.setServerNames(List.of(new javax.net.ssl.SNIHostName(host)));
            s.setSSLParameters(params);
            s.startHandshake();

            Certificate[] certs = s.getSession().getPeerCertificates();
            List<TlsResult.CertInfo> chain = new ArrayList<>();
            for (int i = 0; i < certs.length; i++) {
                if (!(certs[i] instanceof X509Certificate)) continue;
                X509Certificate x = (X509Certificate) certs[i];
                chain.add(parseCert(i, x));
            }
            result.setCertChain(chain);

            if (!nameMatches && result.getHostnameMatchError() == null) {
                result.setHostnameMatchError("Hostname '" + host + "' did not match certificate");
            }
        } catch (Exception e) {
            log("Cert fetch failed for " + host + ":" + port + " — " + e.getMessage());
        }
    }

    private boolean checkHostnameMatch(SSLContext ctx, String host, int port, TlsResult result) {
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            s.setSoTimeout(READ_TIMEOUT_MS);
            SSLParameters params = s.getSSLParameters();
            params.setServerNames(List.of(new javax.net.ssl.SNIHostName(host)));
            params.setEndpointIdentificationAlgorithm("HTTPS");
            s.setSSLParameters(params);
            s.startHandshake();
            return true;
        } catch (Exception e) {
            String msg = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
            if (msg.contains("hostname") || msg.contains("subject alternative")
                    || msg.contains("name does not match")) {
                result.setHostnameMatchError(condense(e.getMessage()));
            }
            return false;
        }
    }

    private TlsResult.CertInfo parseCert(int index, X509Certificate x) {
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        long now = System.currentTimeMillis();
        long days = Duration.ofMillis(x.getNotAfter().getTime() - now).toDays();

        String pkAlgo = "unknown";
        int pkSize = 0;
        try {
            PublicKey pk = x.getPublicKey();
            pkAlgo = pk.getAlgorithm();
            if (pk instanceof RSAPublicKey r) pkSize = r.getModulus().bitLength();
            else if (pk instanceof DSAPublicKey d && d.getParams() != null)
                pkSize = d.getParams().getP().bitLength();
            else if (pk instanceof ECPublicKey e && e.getParams() != null)
                pkSize = e.getParams().getCurve().getField().getFieldSize();
        } catch (Exception ignored) {}

        List<String> sans = new ArrayList<>();
        try {
            Collection<List<?>> rawSans = x.getSubjectAlternativeNames();
            if (rawSans != null) {
                for (List<?> entry : rawSans) {
                    if (entry.size() >= 2 && entry.get(1) != null) {
                        sans.add(String.valueOf(entry.get(1)));
                    }
                }
            }
        } catch (Exception ignored) {}

        boolean selfSigned = x.getSubjectX500Principal().equals(x.getIssuerX500Principal());

        return new TlsResult.CertInfo(
                index,
                x.getSubjectX500Principal().getName(),
                x.getIssuerX500Principal().getName(),
                x.getSerialNumber().toString(16),
                fmt.format(x.getNotBefore()),
                fmt.format(x.getNotAfter()),
                x.getSigAlgName(),
                pkAlgo,
                pkSize,
                sans,
                selfSigned,
                days);
    }

    // ── Issue evaluation ───────────────────────────────────────────────────

    private void evaluateIssues(TlsResult r) {
        // Protocol-version issues
        for (TlsResult.ProtocolOutcome o : r.getProtocols().values()) {
            if (o.status != TlsResult.ProtocolStatus.SUPPORTED) continue;
            if ("SSLv3".equals(o.protocol) || "SSLv2Hello".equals(o.protocol)) {
                r.addIssue(new TlsResult.Issue(Severity.HIGH,
                        "Obsolete protocol enabled: " + o.protocol,
                        o.protocol + " is broken (POODLE) and should be disabled."));
            } else if ("TLSv1".equals(o.protocol)) {
                r.addIssue(new TlsResult.Issue(Severity.MEDIUM,
                        "Deprecated protocol enabled: TLSv1.0",
                        "TLS 1.0 was deprecated by IETF in 2021 and fails PCI DSS."));
            } else if ("TLSv1.1".equals(o.protocol)) {
                r.addIssue(new TlsResult.Issue(Severity.MEDIUM,
                        "Deprecated protocol enabled: TLSv1.1",
                        "TLS 1.1 was deprecated by IETF in 2021 and fails PCI DSS."));
            }
        }

        // No support for any modern protocol
        boolean anyModern = false;
        for (TlsResult.ProtocolOutcome o : r.getProtocols().values()) {
            if (o.status == TlsResult.ProtocolStatus.SUPPORTED
                    && ("TLSv1.2".equals(o.protocol) || "TLSv1.3".equals(o.protocol))) {
                anyModern = true; break;
            }
        }
        if (r.isHandshakeReached() && !anyModern) {
            r.addIssue(new TlsResult.Issue(Severity.HIGH,
                    "No modern TLS support",
                    "Server does not advertise TLS 1.2 or TLS 1.3; clients with current security defaults cannot connect."));
        }

        // No TLS 1.3 (informational)
        boolean tls13 = r.getProtocols().containsKey("TLSv1.3")
                && r.getProtocols().get("TLSv1.3").status == TlsResult.ProtocolStatus.SUPPORTED;
        if (r.isHandshakeReached() && !tls13) {
            r.addIssue(new TlsResult.Issue(Severity.LOW,
                    "TLS 1.3 not supported",
                    "Adding TLS 1.3 reduces handshake latency and removes legacy primitives. Best-practice."));
        }

        // Weak ciphers
        for (String cipher : r.getSupportedCiphers()) {
            String lower = cipher.toLowerCase();
            for (Map.Entry<String, Severity> entry : CIPHER_RED_FLAGS.entrySet()) {
                if (lower.contains(entry.getKey())) {
                    r.addIssue(new TlsResult.Issue(entry.getValue(),
                            "Weak cipher accepted: " + cipher,
                            "Cipher matched red-flag pattern '" + entry.getKey() + "'."));
                    break;
                }
            }
        }

        // Cert issues
        if (!r.getCertChain().isEmpty()) {
            TlsResult.CertInfo leaf = r.getCertChain().get(0);

            if (leaf.daysUntilExpiry < 0) {
                r.addIssue(new TlsResult.Issue(Severity.HIGH,
                        "Certificate expired",
                        "Leaf cert expired " + (-leaf.daysUntilExpiry) + " day(s) ago (notAfter "
                                + leaf.notAfter + ")."));
            } else if (leaf.daysUntilExpiry <= 14) {
                r.addIssue(new TlsResult.Issue(Severity.MEDIUM,
                        "Certificate expires soon",
                        "Leaf cert expires in " + leaf.daysUntilExpiry + " day(s) (" + leaf.notAfter + ")."));
            } else if (leaf.daysUntilExpiry <= 30) {
                r.addIssue(new TlsResult.Issue(Severity.LOW,
                        "Certificate expires within 30 days",
                        "Leaf cert notAfter " + leaf.notAfter + "."));
            }

            String sigAlg = leaf.signatureAlgorithm == null ? "" : leaf.signatureAlgorithm.toLowerCase();
            if (sigAlg.contains("md5")) {
                r.addIssue(new TlsResult.Issue(Severity.HIGH,
                        "Weak certificate signature algorithm: MD5",
                        leaf.signatureAlgorithm + " is broken; rotate cert with SHA-256+ signature."));
            } else if (sigAlg.contains("sha1")) {
                r.addIssue(new TlsResult.Issue(Severity.MEDIUM,
                        "Weak certificate signature algorithm: SHA-1",
                        leaf.signatureAlgorithm + " is deprecated; rotate cert with SHA-256+ signature."));
            }

            if ("RSA".equalsIgnoreCase(leaf.publicKeyAlgorithm) && leaf.publicKeySize > 0
                    && leaf.publicKeySize < 2048) {
                r.addIssue(new TlsResult.Issue(Severity.HIGH,
                        "Weak certificate RSA key size: " + leaf.publicKeySize + " bits",
                        "RSA keys below 2048 bits are considered weak; rotate to 2048+ or use ECDSA P-256."));
            }
            if ("EC".equalsIgnoreCase(leaf.publicKeyAlgorithm) && leaf.publicKeySize > 0
                    && leaf.publicKeySize < 224) {
                r.addIssue(new TlsResult.Issue(Severity.MEDIUM,
                        "Weak certificate EC curve size: " + leaf.publicKeySize + " bits",
                        "EC keys below 224 bits are weak; use P-256 or stronger."));
            }

            if (leaf.selfSigned) {
                r.addIssue(new TlsResult.Issue(Severity.LOW,
                        "Self-signed leaf certificate",
                        "Leaf cert subject equals issuer; clients without manual trust will reject."));
            }
        } else if (r.isHandshakeReached()) {
            r.addIssue(new TlsResult.Issue(Severity.INFO,
                    "Certificate chain not retrieved",
                    "Server completed handshake but did not return a parseable cert chain."));
        }

        if (r.getHostnameMatchError() != null) {
            r.addIssue(new TlsResult.Issue(Severity.MEDIUM,
                    "Hostname does not match certificate",
                    r.getHostnameMatchError()));
        }
    }

    // ── Findings publication (FindingsStore + Burp Dashboard) ──────────────

    private void publishFindings(String host, int port, TlsResult r) {
        for (TlsResult.Issue issue : r.getIssues()) {
            try {
                Finding f = Finding.builder("tls-analyzer",
                                "[TLS] " + issue.title + " on " + host + ":" + port,
                                issue.severity, Confidence.CERTAIN)
                        .url("https://" + host + ":" + port + "/")
                        .description(issue.detail
                                + "\n\nTarget: " + host + ":" + port
                                + "\nProtocols supported: " + summarizeProtocols(r)
                                + (r.getCertChain().isEmpty() ? ""
                                        : "\nLeaf cert: " + r.getCertChain().get(0).subject
                                          + "\nIssuer: " + r.getCertChain().get(0).issuer
                                          + "\nValid until: " + r.getCertChain().get(0).notAfter))
                        .evidence(issue.title)
                        .remediation(buildRemediation(issue))
                        .build();
                findingsStore.addFinding(f);
            } catch (Exception e) {
                log("Failed to publish TLS finding: " + e.getMessage());
            }
        }
    }

    private String summarizeProtocols(TlsResult r) {
        StringBuilder sb = new StringBuilder();
        for (TlsResult.ProtocolOutcome o : r.getProtocols().values()) {
            if (o.status == TlsResult.ProtocolStatus.SUPPORTED) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(o.protocol);
            }
        }
        return sb.length() == 0 ? "(none)" : sb.toString();
    }

    private String buildRemediation(TlsResult.Issue issue) {
        String t = issue.title.toLowerCase();
        if (t.contains("sslv3") || t.contains("sslv2"))
            return "Disable SSLv2/SSLv3 in the TLS terminator (nginx ssl_protocols, Apache SSLProtocol, ELB security policies, etc.).";
        if (t.contains("tlsv1.0") || t.contains("tlsv1.1"))
            return "Disable TLS 1.0 and 1.1 in the TLS terminator. Restrict to TLS 1.2 and TLS 1.3.";
        if (t.contains("no modern tls"))
            return "Add TLS 1.2 (minimum) and TLS 1.3 to the TLS terminator's protocol list.";
        if (t.contains("tls 1.3 not supported"))
            return "Enable TLS 1.3 in the terminator. Modern OpenSSL/BoringSSL/JSSE all support it.";
        if (t.contains("weak cipher"))
            return "Restrict the cipher list to AEAD-suite ciphers (ECDHE-*-GCM, ECDHE-*-CHACHA20). Drop NULL/anon/EXPORT/RC4/3DES/DES/MD5.";
        if (t.contains("certificate expired") || t.contains("expires"))
            return "Renew the certificate. Automate renewal via ACME/cert-manager so this never recurs.";
        if (t.contains("md5") || t.contains("sha-1") || t.contains("sha1"))
            return "Re-issue the certificate with a SHA-256 (or stronger) signature.";
        if (t.contains("rsa key size") || t.contains("ec curve"))
            return "Re-issue the certificate with a 2048-bit (or larger) RSA key, or switch to ECDSA P-256.";
        if (t.contains("self-signed"))
            return "Replace with a certificate from a trusted CA (Let's Encrypt, internal PKI, etc.).";
        if (t.contains("hostname does not match"))
            return "Re-issue the certificate with the correct CN/SAN entries for this hostname.";
        return "Review the TLS configuration of the terminator.";
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private SSLContext buildPermissiveContext() {
        // Trust-all manager — we are inspecting, not validating.
        TrustManager[] trustAll = new TrustManager[]{
                new X509ExtendedTrustManager() {
                    @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
                    @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
                    @Override public void checkClientTrusted(X509Certificate[] c, String a, Socket s) {}
                    @Override public void checkServerTrusted(X509Certificate[] c, String a, Socket s) {}
                    @Override public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) {}
                    @Override public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) {}
                }
        };
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new java.security.SecureRandom());
            return ctx;
        } catch (Exception e) {
            log("buildPermissiveContext failed: " + e.getMessage());
            return null;
        }
    }

    private static String condense(String msg) {
        if (msg == null) return "";
        msg = msg.replace('\n', ' ').replace('\r', ' ').trim();
        return msg.length() > 200 ? msg.substring(0, 200) + "..." : msg;
    }

    private static String key(String host, int port) {
        return (host == null ? "?" : host.toLowerCase()) + ":" + port;
    }

    private void log(String msg) {
        try { api.logging().logToOutput("[TLSAnalyzer] " + msg); } catch (Exception ignored) {}
        BiConsumer<String, String> logger = uiLogger;
        if (logger != null) {
            try { logger.accept("TLSAnalyzer", msg); } catch (Exception ignored) {}
        }
        // Suppress unused KeyStore import warning — engine intentionally avoids
        // loading a KeyStore (permissive trust manager).
        if (false) { try { KeyStore.getInstance(KeyStore.getDefaultType()); } catch (Exception ignored) {} }
    }

    private static class AnalysisHandle {
        final Future<?> future;
        final AtomicBoolean cancelled;
        AnalysisHandle(Future<?> f, AtomicBoolean c) { future = f; cancelled = c; }
    }
}
