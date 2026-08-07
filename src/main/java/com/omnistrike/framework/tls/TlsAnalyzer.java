package com.omnistrike.framework.tls;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.Confidence;
import com.omnistrike.model.Finding;
import com.omnistrike.model.Severity;

import javax.net.ssl.*;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.net.IDN;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
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
 * Analyses run on a small dedicated thread pool. Completed snapshots are cached
 * per "host:port" for display/export until {@link #invalidate(String, int)} is called.
 */
public class TlsAnalyzer {

    /** Protocols probed, ordered strongest → weakest. */
    public static final List<String> PROBE_PROTOCOLS = List.of(
            "TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"
    );

    private static final int CONNECT_TIMEOUT_MS = 6000;
    private static final int READ_TIMEOUT_MS    = 6000;
    private static final int MAX_CACHE_ENTRIES  = 2000;

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
        this.executor = new ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(100), r -> {
                    Thread t = new Thread(r, "OmniStrike-TLSAnalyzer");
                    t.setDaemon(true);
                    return t;
                }, new ThreadPoolExecutor.AbortPolicy());
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
        final String targetHost;
        try {
            targetHost = normalizeHost(host);
        } catch (IllegalArgumentException invalidHost) {
            log("Invalid target: " + host + ":" + port);
            if (onComplete != null) onComplete.accept(null);
            return;
        }
        if (port <= 0 || port > 65535) {
            log("Invalid target: " + host + ":" + port);
            if (onComplete != null) onComplete.accept(null);
            return;
        }
        final String cacheKey = key(targetHost, port);
        AtomicBoolean cancelled = new AtomicBoolean(false);
        java.util.concurrent.atomic.AtomicReference<AnalysisHandle> self =
                new java.util.concurrent.atomic.AtomicReference<>();
        FutureTask<Void> task = new FutureTask<>(() -> {
            TlsResult result = new TlsResult(targetHost, port);
            boolean successful = false;
            try {
                log("Starting TLS analysis: " + targetHost + ":" + port);
                probeProtocols(targetHost, port, result, cancelled);
                if (cancelled.get()) return;

                if (enumerateCiphers && result.hasAnySupportedProtocol()) {
                    log("Enumerating cipher suites for " + cacheKey + " ...");
                    enumerateCipherSuites(targetHost, port, result, cancelled);
                }
                if (cancelled.get()) return;

                fetchCertificateChain(targetHost, port, result, cancelled);
                if (cancelled.get()) return;

                evaluateIssues(result);
                result.freeze();
                if (cache.size() >= MAX_CACHE_ENTRIES && !cache.containsKey(cacheKey)) {
                    Enumeration<String> keys = cache.keys();
                    if (keys.hasMoreElements()) cache.remove(keys.nextElement());
                }
                cache.put(cacheKey, result);

                if (reportFindings && findingsStore != null) {
                    publishFindings(targetHost, port, result);
                }
                successful = true;

                log("Analysis complete: " + cacheKey
                        + " — " + result.getProtocols().size() + " protocols probed, "
                        + result.getSupportedCiphers().size() + " cipher(s), "
                        + result.getCertChain().size() + " cert(s), "
                        + result.getIssues().size() + " issue(s).");
            } catch (Throwable t) {
                log("TLS analysis failed for " + cacheKey + ": " + t.getMessage());
            } finally {
                AnalysisHandle ownHandle = self.get();
                if (ownHandle != null) active.remove(cacheKey, ownHandle);
                if (onComplete != null && !cancelled.get()) {
                    try {
                        onComplete.accept(successful ? result : null);
                    } catch (RuntimeException callbackFailure) {
                        log("TLS completion callback failed for " + cacheKey + ": "
                                + callbackFailure.getMessage());
                    }
                }
            }
        }, null);
        AnalysisHandle handle = new AnalysisHandle(task, cancelled);
        self.set(handle);

        while (true) {
            AnalysisHandle existing = active.putIfAbsent(cacheKey, handle);
            if (existing == null) break;
            if (!existing.future.isDone()) {
                log("Analysis already in progress for " + cacheKey);
                if (onComplete != null) onComplete.accept(null);
                return;
            }
            if (active.replace(cacheKey, existing, handle)) break;
        }

        try {
            executor.execute(task);
        } catch (RejectedExecutionException rejected) {
            active.remove(cacheKey, handle);
            log("TLS analysis queue is full; rejected " + cacheKey);
            if (onComplete != null) onComplete.accept(null);
        }
    }

    // ── Protocol probing ───────────────────────────────────────────────────

    private void probeProtocols(String host, int port, TlsResult result,
                                AtomicBoolean cancelled) {
        SSLContext ctx = buildPermissiveContext();
        if (ctx == null) {
            log("Could not build SSLContext — aborting probe");
            return;
        }
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

    }

    private TlsResult.ProtocolOutcome singleProtocolProbe(SSLContext ctx, String host,
                                                          int port, String proto) {
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            s.setSoTimeout(READ_TIMEOUT_MS);
            // Set both protocol AND SNI; servers often reject without SNI on TLS 1.2+
            s.setEnabledProtocols(new String[]{proto});
            SSLParameters params = s.getSSLParameters();
            applySni(params, host);
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

    static Set<String> jvmSupportedProtocols(SSLContext ctx) {
        try {
            SSLEngine engine = ctx.createSSLEngine();
            Set<String> supported = new HashSet<>(Arrays.asList(engine.getSupportedProtocols()));
            supported.removeIf(protocol -> !isProtocolLocallyUsable(ctx, protocol));
            return supported;
        } catch (Exception e) {
            return Collections.emptySet();
        }
    }

    static boolean isProtocolLocallyUsable(SSLContext ctx, String protocol) {
        try {
            SSLEngine engine = ctx.createSSLEngine();
            engine.setUseClientMode(true);
            engine.setEnabledProtocols(new String[]{protocol});
            engine.setEnabledCipherSuites(engine.getSupportedCipherSuites());
            engine.beginHandshake();
            return true;
        } catch (SSLHandshakeException locallyBlocked) {
            return false;
        } catch (IllegalArgumentException unsupported) {
            return false;
        } catch (Exception inconclusive) {
            return true;
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
            applySni(params, host);
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

        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            s.setSoTimeout(READ_TIMEOUT_MS);
            String[] supportedProtocols = result.getProtocols().values().stream()
                    .filter(outcome -> outcome.status == TlsResult.ProtocolStatus.SUPPORTED)
                    .map(outcome -> outcome.protocol)
                    .toArray(String[]::new);
            if (supportedProtocols.length > 0) s.setEnabledProtocols(supportedProtocols);
            SSLParameters params = s.getSSLParameters();
            applySni(params, host);
            s.setSSLParameters(params);
            s.startHandshake();

            SSLSession session = s.getSession();
            Certificate[] certs = session.getPeerCertificates();
            List<TlsResult.CertInfo> chain = new ArrayList<>();
            List<X509Certificate> x509Chain = new ArrayList<>();
            for (int i = 0; i < certs.length; i++) {
                if (!(certs[i] instanceof X509Certificate x)) continue;
                x509Chain.add(x);
                chain.add(parseCert(i, x));
            }
            result.setCertChain(chain);

            boolean nameMatches = !x509Chain.isEmpty()
                    && hostnameMatches(host, x509Chain.get(0));
            if (!nameMatches) {
                result.setHostnameMatchError("Hostname '" + host + "' did not match certificate");
            }

            String trustError = validateCertificateTrust(x509Chain);
            if (trustError != null) result.setCertificateTrustError(trustError);
        } catch (Exception e) {
            log("Cert fetch failed for " + host + ":" + port + " — " + e.getMessage());
        }
    }

    static String validateCertificateTrust(List<X509Certificate> chain) {
        if (chain == null || chain.isEmpty()) return "No X.509 certificate chain was returned";
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            factory.init((java.security.KeyStore) null);
            X509Certificate[] certificates = chain.toArray(X509Certificate[]::new);
            String authType = certificates[0].getPublicKey().getAlgorithm();
            Exception lastFailure = null;
            for (TrustManager manager : factory.getTrustManagers()) {
                if (!(manager instanceof X509TrustManager trustManager)) continue;
                try {
                    trustManager.checkServerTrusted(certificates, authType);
                    return null;
                } catch (Exception untrusted) {
                    lastFailure = untrusted;
                }
            }
            return condense(lastFailure == null
                    ? "No platform X.509 trust manager was available"
                    : lastFailure.getMessage());
        } catch (Exception validationFailure) {
            return condense(validationFailure.getClass().getSimpleName() + ": "
                    + validationFailure.getMessage());
        }
    }

    static boolean hostnameMatches(String host, X509Certificate certificate) {
        if (host == null || certificate == null) return false;
        String normalizedHost;
        try {
            normalizedHost = normalizeHost(host);
        } catch (IllegalArgumentException invalidHost) {
            return false;
        }

        boolean ipTarget = isIpLiteral(normalizedHost);
        boolean hasRelevantSan = false;
        try {
            Collection<List<?>> sans = certificate.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> entry : sans) {
                    if (entry == null || entry.size() < 2 || !(entry.get(0) instanceof Integer type)) {
                        continue;
                    }
                    if (ipTarget && type == 7) {
                        hasRelevantSan = true;
                        if (ipSanMatches(normalizedHost, entry.get(1))) return true;
                    } else if (!ipTarget && type == 2 && entry.get(1) != null) {
                        hasRelevantSan = true;
                        if (dnsNameMatches(normalizedHost, String.valueOf(entry.get(1)))) return true;
                    }
                }
            }
        } catch (Exception malformedSans) {
            return false;
        }
        if (hasRelevantSan || ipTarget) return false;

        try {
            LdapName subject = new LdapName(
                    certificate.getSubjectX500Principal().getName("RFC2253"));
            List<Rdn> rdns = subject.getRdns();
            for (int i = rdns.size() - 1; i >= 0; i--) {
                Rdn rdn = rdns.get(i);
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return dnsNameMatches(normalizedHost, String.valueOf(rdn.getValue()));
                }
            }
        } catch (Exception malformedSubject) {
            return false;
        }
        return false;
    }

    static boolean dnsNameMatches(String normalizedHost, String certificateName) {
        if (normalizedHost == null || certificateName == null || isIpLiteral(normalizedHost)) {
            return false;
        }
        String pattern = certificateName.trim();
        boolean wildcard = pattern.startsWith("*.");
        if (wildcard) pattern = pattern.substring(2);
        if (pattern.indexOf('*') >= 0) return false;
        try {
            pattern = IDN.toASCII(pattern, IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
        } catch (RuntimeException invalidName) {
            return false;
        }
        if (pattern.endsWith(".")) pattern = pattern.substring(0, pattern.length() - 1);
        if (!wildcard) return normalizedHost.equals(pattern);
        if (pattern.indexOf('.') < 0 || !normalizedHost.endsWith("." + pattern)) return false;
        String leftmost = normalizedHost.substring(0,
                normalizedHost.length() - pattern.length() - 1);
        return !leftmost.isEmpty() && leftmost.indexOf('.') < 0;
    }

    private static boolean ipSanMatches(String normalizedHost, Object sanValue) {
        try {
            InetAddress expected = InetAddress.getByName(stripIpv6Zone(normalizedHost));
            InetAddress actual;
            if (sanValue instanceof byte[] raw) {
                actual = InetAddress.getByAddress(raw);
            } else {
                String candidate = String.valueOf(sanValue);
                if (!isIpLiteral(candidate)) return false;
                actual = InetAddress.getByName(stripIpv6Zone(candidate));
            }
            return expected.equals(actual);
        } catch (Exception invalidAddress) {
            return false;
        }
    }

    private static String stripIpv6Zone(String value) {
        int zone = value.indexOf('%');
        return zone < 0 ? value : value.substring(0, zone);
    }

    private TlsResult.CertInfo parseCert(int index, X509Certificate x) {
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        long now = System.currentTimeMillis();
        long notBeforeMs = x.getNotBefore().getTime();
        long notAfterMs = x.getNotAfter().getTime();
        long days = Math.floorDiv(notAfterMs - now, Duration.ofDays(1).toMillis());

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

        boolean selfSigned = isCryptographicallySelfSigned(x);

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
                days,
                notBeforeMs,
                notAfterMs);
    }

    static boolean isCryptographicallySelfSigned(X509Certificate certificate) {
        if (certificate == null
                || !certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (Exception notSelfSigned) {
            return false;
        }
    }

    // ── Issue evaluation ───────────────────────────────────────────────────

    void evaluateIssues(TlsResult r) {
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
        if (r.isHandshakeReached() && !anyModern
                && isConclusiveRejection(r, "TLSv1.2")
                && isConclusiveRejection(r, "TLSv1.3")) {
            r.addIssue(new TlsResult.Issue(Severity.HIGH,
                    "No modern TLS support",
                    "Server does not advertise TLS 1.2 or TLS 1.3; clients with current security defaults cannot connect."));
        }

        // No TLS 1.3 (informational)
        if (r.isHandshakeReached() && isConclusiveRejection(r, "TLSv1.3")) {
            r.addIssue(new TlsResult.Issue(Severity.LOW,
                    "TLS 1.3 not supported",
                    "Adding TLS 1.3 reduces handshake latency and removes legacy primitives. Best-practice."));
        }

        // Weak ciphers
        for (String cipher : r.getSupportedCiphers()) {
            String lower = cipher.toLowerCase(Locale.ROOT);
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

            boolean expired = leaf.notAfterEpochMs > 0
                    ? leaf.notAfterEpochMs < r.getTimestampMs()
                    : leaf.daysUntilExpiry < 0;
            boolean notYetValid = leaf.notBeforeEpochMs > 0
                    && leaf.notBeforeEpochMs > r.getTimestampMs();
            if (expired) {
                r.addIssue(new TlsResult.Issue(Severity.HIGH,
                        "Certificate expired",
                        "Leaf cert expired " + (-leaf.daysUntilExpiry) + " day(s) ago (notAfter "
                                + leaf.notAfter + ")."));
            } else if (notYetValid) {
                r.addIssue(new TlsResult.Issue(Severity.HIGH,
                        "Certificate is not yet valid",
                        "Leaf cert validity begins at " + leaf.notBefore + "."));
            } else if (leaf.daysUntilExpiry <= 14) {
                r.addIssue(new TlsResult.Issue(Severity.MEDIUM,
                        "Certificate expires soon",
                        "Leaf cert expires in " + leaf.daysUntilExpiry + " day(s) (" + leaf.notAfter + ")."));
            } else if (leaf.daysUntilExpiry <= 30) {
                r.addIssue(new TlsResult.Issue(Severity.LOW,
                        "Certificate expires within 30 days",
                        "Leaf cert notAfter " + leaf.notAfter + "."));
            }

            String sigAlg = leaf.signatureAlgorithm == null ? ""
                    : leaf.signatureAlgorithm.toLowerCase(Locale.ROOT);
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
        if (r.getCertificateTrustError() != null) {
            r.addIssue(new TlsResult.Issue(Severity.LOW,
                    "Certificate chain not trusted by local JVM",
                    r.getCertificateTrustError()
                            + ". Trust is evaluated against Burp's Java runtime trust store; "
                            + "an internal client trust store may differ."));
        }
    }

    static boolean isConclusiveRejection(TlsResult result, String protocol) {
        TlsResult.ProtocolOutcome outcome = result.getProtocols().get(protocol);
        return outcome != null && outcome.status == TlsResult.ProtocolStatus.NOT_SUPPORTED;
    }

    // ── Findings publication (FindingsStore + Burp Dashboard) ──────────────

    private void publishFindings(String host, int port, TlsResult r) {
        for (TlsResult.Issue issue : r.getIssues()) {
            try {
                Finding f = Finding.builder("tls-analyzer",
                                "[TLS] " + issue.title + " on " + host + ":" + port,
                                issue.severity, Confidence.CERTAIN)
                        .url(tlsUrl(host, port))
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
        String t = issue.title.toLowerCase(Locale.ROOT);
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
        if (t.contains("not yet valid"))
            return "Deploy a certificate whose validity window includes the current time and verify clock synchronization on the TLS terminator.";
        if (t.contains("md5") || t.contains("sha-1") || t.contains("sha1"))
            return "Re-issue the certificate with a SHA-256 (or stronger) signature.";
        if (t.contains("rsa key size") || t.contains("ec curve"))
            return "Re-issue the certificate with a 2048-bit (or larger) RSA key, or switch to ECDSA P-256.";
        if (t.contains("self-signed"))
            return "Replace with a certificate from a trusted CA (Let's Encrypt, internal PKI, etc.).";
        if (t.contains("hostname does not match"))
            return "Re-issue the certificate with the correct CN/SAN entries for this hostname.";
        if (t.contains("not trusted"))
            return "Serve the complete intermediate chain and use a CA trusted by the intended clients. Verify any required internal CA deployment.";
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

    static String normalizeHost(String host) {
        if (host == null) throw new IllegalArgumentException("host is required");
        String normalized = host.trim();
        if (normalized.startsWith("[") && normalized.endsWith("]")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        if (normalized.isEmpty() || normalized.contains("/") || normalized.contains("\\")
                || normalized.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("invalid host");
        }
        if (isIpLiteral(normalized)) return normalized.toLowerCase(Locale.ROOT);
        try {
            String ascii = IDN.toASCII(normalized, IDN.USE_STD3_ASCII_RULES);
            if (ascii.endsWith(".")) ascii = ascii.substring(0, ascii.length() - 1);
            if (ascii.isEmpty() || ascii.length() > 253) throw new IllegalArgumentException("invalid host");
            return ascii.toLowerCase(Locale.ROOT);
        } catch (RuntimeException invalid) {
            throw new IllegalArgumentException("invalid host", invalid);
        }
    }

    static boolean isIpLiteral(String host) {
        if (host == null || host.isBlank()) return false;
        String value = host;
        if (value.startsWith("[") && value.endsWith("]")) {
            value = value.substring(1, value.length() - 1);
        }
        if (value.indexOf(':') >= 0) {
            int zone = value.indexOf('%');
            String address = zone >= 0 ? value.substring(0, zone) : value;
            String zoneId = zone >= 0 ? value.substring(zone + 1) : "";
            long colons = address.chars().filter(c -> c == ':').count();
            if (colons < 2 || !address.matches("[0-9A-Fa-f:.]+")
                    || (zone >= 0 && (zoneId.isEmpty() || !zoneId.matches("[A-Za-z0-9_.-]+")))) {
                return false;
            }
            try {
                return InetAddress.getByName(address) != null;
            } catch (Exception invalidIpv6) {
                return false;
            }
        }
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3
                    || !part.chars().allMatch(c -> c >= '0' && c <= '9')) {
                return false;
            }
            if (Integer.parseInt(part) > 255) return false;
        }
        return true;
    }

    private static void applySni(SSLParameters parameters, String host) {
        if (!isIpLiteral(host)) {
            parameters.setServerNames(List.of(new SNIHostName(host)));
        }
    }

    static String tlsUrl(String host, int port) {
        String normalized = normalizeHost(host);
        String authority = normalized.indexOf(':') >= 0
                ? "[" + normalized.replace("%", "%25") + "]" : normalized;
        return "https://" + authority + (port == 443 ? "" : ":" + port) + "/";
    }

    private static String key(String host, int port) {
        try {
            String normalized = normalizeHost(host);
            return (normalized.indexOf(':') >= 0 ? "[" + normalized + "]" : normalized)
                    + ":" + port;
        } catch (IllegalArgumentException invalid) {
            return "?:" + port;
        }
    }

    private void log(String msg) {
        try { api.logging().logToOutput("[TLSAnalyzer] " + msg); } catch (Exception ignored) {}
        BiConsumer<String, String> logger = uiLogger;
        if (logger != null) {
            try { logger.accept("TLSAnalyzer", msg); } catch (Exception ignored) {}
        }
    }

    private static class AnalysisHandle {
        final Future<?> future;
        final AtomicBoolean cancelled;
        AnalysisHandle(Future<?> f, AtomicBoolean c) { future = f; cancelled = c; }
    }
}
