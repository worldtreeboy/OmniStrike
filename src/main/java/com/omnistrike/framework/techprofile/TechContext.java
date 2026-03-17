package com.omnistrike.framework.techprofile;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Per-host technology profile with weighted evidence scoring.
 *
 * Instead of a simple CONFIRMED/PROBABLE/UNKNOWN enum, each TechStack
 * accumulates an integer score from independent evidence sources. The score
 * maps to a confidence tier:
 *
 *   0       → UNKNOWN   (no evidence)
 *   1-49    → TENTATIVE (single weak signal — NOT reported, NOT routed)
 *   50-94   → PROBABLE  (multiple corroborating signals — used for routing)
 *   95+     → CONFIRMED (structural proof — used for routing AND filtering)
 *
 * Scores are monotonically increasing — evidence can only accumulate, never be
 * subtracted. This prevents later noise from degrading a strong classification.
 *
 * Thread-safety: ConcurrentHashMap for lock-free reads, synchronized addEvidence()
 * for write linearization. Reads are O(1) and never block.
 */
public final class TechContext {

    // ════════════════════════════════════════════════════════════════════════
    //  Enums
    // ════════════════════════════════════════════════════════════════════════

    public enum TechCategory { OS, LANGUAGE, WEB_SERVER, DATABASE, FRAMEWORK }

    public enum ConfidenceLevel {
        UNKNOWN(0), TENTATIVE(1), PROBABLE(50), CONFIRMED(95);

        private final int threshold;
        ConfidenceLevel(int threshold) { this.threshold = threshold; }
        public int threshold() { return threshold; }

        public static ConfidenceLevel fromScore(int score) {
            if (score >= CONFIRMED.threshold) return CONFIRMED;
            if (score >= PROBABLE.threshold)  return PROBABLE;
            if (score > UNKNOWN.threshold)    return TENTATIVE;
            return UNKNOWN;
        }
    }

    public enum TechStack {
        // ── OS ────────────────────────────────────────────────────────────
        LINUX(TechCategory.OS),
        WINDOWS(TechCategory.OS),
        FREEBSD(TechCategory.OS),

        // ── Language / Runtime ────────────────────────────────────────────
        JAVA(TechCategory.LANGUAGE),
        PHP(TechCategory.LANGUAGE),
        DOTNET(TechCategory.LANGUAGE),
        PYTHON(TechCategory.LANGUAGE),
        RUBY(TechCategory.LANGUAGE),
        NODEJS(TechCategory.LANGUAGE),
        GO(TechCategory.LANGUAGE),
        PERL(TechCategory.LANGUAGE),

        // ── Web Server ───────────────────────────────────────────────────
        APACHE(TechCategory.WEB_SERVER),
        NGINX(TechCategory.WEB_SERVER),
        IIS(TechCategory.WEB_SERVER),
        TOMCAT(TechCategory.WEB_SERVER),
        JETTY(TechCategory.WEB_SERVER),
        UNDERTOW(TechCategory.WEB_SERVER),
        LIGHTTPD(TechCategory.WEB_SERVER),
        CADDY(TechCategory.WEB_SERVER),

        // ── Database ─────────────────────────────────────────────────────
        MYSQL(TechCategory.DATABASE),
        POSTGRESQL(TechCategory.DATABASE),
        MSSQL(TechCategory.DATABASE),
        ORACLE(TechCategory.DATABASE),
        SQLITE(TechCategory.DATABASE),
        MONGODB(TechCategory.DATABASE),
        REDIS(TechCategory.DATABASE),

        // ── Framework ────────────────────────────────────────────────────
        SPRING(TechCategory.FRAMEWORK),
        SPRING_BOOT(TechCategory.FRAMEWORK),
        DJANGO(TechCategory.FRAMEWORK),
        FLASK(TechCategory.FRAMEWORK),
        RAILS(TechCategory.FRAMEWORK),
        LARAVEL(TechCategory.FRAMEWORK),
        SYMFONY(TechCategory.FRAMEWORK),
        EXPRESS(TechCategory.FRAMEWORK),
        ASPNET_MVC(TechCategory.FRAMEWORK),
        ASPNET_CORE(TechCategory.FRAMEWORK),
        STRUTS(TechCategory.FRAMEWORK),
        WORDPRESS(TechCategory.FRAMEWORK),
        DRUPAL(TechCategory.FRAMEWORK),
        ;

        private final TechCategory category;
        TechStack(TechCategory category) { this.category = category; }
        public TechCategory category() { return category; }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Evidence weight constants — calibrated per source reliability
    // ════════════════════════════════════════════════════════════════════════

    /** Server header — easily faked by reverse proxies. Low weight. */
    public static final int W_SERVER_HEADER = 10;

    /** X-Powered-By — can be faked but less commonly. Moderate weight. */
    public static final int W_POWERED_BY = 40;

    /** Specific version header (X-AspNet-Version, X-Drupal-Cache). Hard to fake. */
    public static final int W_VERSION_HEADER = 60;

    /** Cookie name structurally tied to technology (JSESSIONID, PHPSESSID). */
    public static final int W_COOKIE_NAME = 50;

    /** Technology-specific stack trace in error response. Structural proof. */
    public static final int W_STACK_TRACE = 100;

    /** DBMS-specific error message (ORA-xxxxx, pg_query, etc.). Structural proof. */
    public static final int W_DBMS_ERROR = 100;

    /** Default error page (Tomcat 404, Spring Whitelabel, IIS Detailed). */
    public static final int W_DEFAULT_ERROR_PAGE = 80;

    /** Behavioural probe — differential positive match (e.g., {{7*7}} → 49). */
    public static final int W_PROBE_POSITIVE = 70;

    /** Behavioural probe — negative match (confirmed absence of competing tech). */
    public static final int W_PROBE_NEGATIVE = 30;

    /** Cross-module confirmation (scanner module found tech-specific evidence). */
    public static final int W_CROSS_MODULE = 100;

    /** Filesystem path in error message (structural OS proof). */
    public static final int W_PATH_LEAK = 90;

    /** URI-pattern heuristic (e.g., .php extension → PHP). Weak alone. */
    public static final int W_URI_PATTERN = 15;

    /** Proxy/WAF marker detected — reduces trust in Server header. */
    public static final int W_PROXY_DETECTED = -5; // Negative: penalizes Server header trust

    // ════════════════════════════════════════════════════════════════════════
    //  State — lock-free reads, synchronized writes
    // ════════════════════════════════════════════════════════════════════════

    private final String host;

    /** Accumulated evidence score per tech. Lock-free reads via ConcurrentHashMap. */
    private final ConcurrentHashMap<TechStack, Integer> scores = new ConcurrentHashMap<>();

    /** Tracks which evidence sources have already been applied (prevents double-counting). */
    private final Set<String> appliedEvidence = ConcurrentHashMap.newKeySet();

    /** True if a reverse proxy / WAF / CDN was detected masking the origin. */
    private volatile boolean proxyDetected = false;

    private volatile long lastUpdated = System.currentTimeMillis();

    public TechContext(String host) {
        this.host = Objects.requireNonNull(host);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Mutation — monotonic score accumulation
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Add evidence for a tech. The evidence key prevents double-counting from
     * the same source (e.g., seeing the same Server header on multiple responses).
     *
     * @param tech        the technology this evidence supports
     * @param weight      the score weight (use W_* constants)
     * @param evidenceKey unique key for this evidence source (e.g., "header:Server:Apache")
     * @return true if the score actually changed
     */
    public synchronized boolean addEvidence(TechStack tech, int weight, String evidenceKey) {
        if (weight <= 0) return false;
        if (evidenceKey != null && !appliedEvidence.add(evidenceKey)) {
            return false; // Already counted this evidence
        }
        int current = scores.getOrDefault(tech, 0);
        scores.put(tech, current + weight);
        lastUpdated = System.currentTimeMillis();
        return true;
    }

    /**
     * Directly set a tech to CONFIRMED (score = 100). Used for structural proof
     * that is so strong it doesn't need accumulation (e.g., cross-module feedback
     * from a scanner finding a DBMS-specific error).
     */
    public synchronized boolean confirm(TechStack tech, String evidenceKey) {
        return addEvidence(tech, W_CROSS_MODULE, evidenceKey);
    }

    /** Mark that a proxy/WAF/CDN is masking the origin server. */
    public void setProxyDetected(boolean detected) {
        this.proxyDetected = detected;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Queries — all lock-free (ConcurrentHashMap reads)
    // ════════════════════════════════════════════════════════════════════════

    public String host() { return host; }
    public long lastUpdated() { return lastUpdated; }
    public boolean isProxyDetected() { return proxyDetected; }

    /** Raw accumulated score for a tech. */
    public int getScore(TechStack tech) {
        return scores.getOrDefault(tech, 0);
    }

    /** Confidence level derived from accumulated score. */
    public ConfidenceLevel getConfidence(TechStack tech) {
        return ConfidenceLevel.fromScore(getScore(tech));
    }

    public boolean isConfirmed(TechStack tech) {
        return getScore(tech) >= ConfidenceLevel.CONFIRMED.threshold();
    }

    public boolean isProbable(TechStack tech) {
        return getScore(tech) >= ConfidenceLevel.PROBABLE.threshold();
    }

    /** True if no tech in this category has reached PROBABLE. */
    public boolean isUnknown(TechCategory category) {
        for (var entry : scores.entrySet()) {
            if (entry.getKey().category() == category && entry.getValue() >= ConfidenceLevel.PROBABLE.threshold()) {
                return false;
            }
        }
        return true;
    }

    /**
     * True if the category has evidence but hasn't reached CONFIRMED.
     * This is the trigger condition for tie-breaker probes.
     */
    public boolean needsTieBreaker(TechCategory category) {
        boolean hasTentative = false;
        for (var entry : scores.entrySet()) {
            if (entry.getKey().category() != category) continue;
            int score = entry.getValue();
            if (score >= ConfidenceLevel.CONFIRMED.threshold()) return false; // Already certain
            if (score >= ConfidenceLevel.TENTATIVE.threshold()) hasTentative = true;
        }
        return hasTentative;
    }

    /** Returns all techs in a category, ordered by score descending. Only includes score > 0. */
    public List<TechStack> getForCategory(TechCategory category) {
        return scores.entrySet().stream()
                .filter(e -> e.getKey().category() == category && e.getValue() > 0)
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());
    }

    /** Highest-scoring tech for a category, or null if no evidence at all. */
    public TechStack getPrimary(TechCategory category) {
        TechStack best = null;
        int bestScore = 0;
        for (var entry : scores.entrySet()) {
            if (entry.getKey().category() == category && entry.getValue() > bestScore) {
                best = entry.getKey();
                bestScore = entry.getValue();
            }
        }
        return best;
    }

    /** Returns the top two contenders for a category (for tie-breaker logic). */
    public TechStack[] getTopTwo(TechCategory category) {
        List<TechStack> sorted = getForCategory(category);
        return switch (sorted.size()) {
            case 0 -> new TechStack[0];
            case 1 -> new TechStack[]{sorted.get(0)};
            default -> new TechStack[]{sorted.get(0), sorted.get(1)};
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Payload routing support
    // ════════════════════════════════════════════════════════════════════════

    /** Score for routing: CONFIRMED=100, PROBABLE=50, TENTATIVE=10, UNKNOWN=0. */
    public int relevanceScore(TechStack tech) {
        int s = getScore(tech);
        if (s >= ConfidenceLevel.CONFIRMED.threshold()) return 100;
        if (s >= ConfidenceLevel.PROBABLE.threshold())  return 50;
        if (s > 0) return 10;
        return 0;
    }

    /** True if a payload targeting these techs is relevant to this host. */
    public boolean isRelevant(Set<TechStack> payloadTechs) {
        if (payloadTechs == null || payloadTechs.isEmpty()) return true;
        for (TechStack t : payloadTechs) {
            if (isProbable(t)) return true;
        }
        return false;
    }

    /** Unmodifiable snapshot: tech → score. */
    public Map<TechStack, Integer> snapshot() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(scores));
    }

    @Override
    public String toString() {
        if (scores.isEmpty()) return "[" + host + ": no profile]";
        StringBuilder sb = new StringBuilder("[").append(host).append(": ");
        scores.entrySet().stream()
                .filter(e -> e.getValue() > 0)
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .forEach(e -> sb.append(e.getKey()).append('(')
                        .append(e.getValue()).append('/').append(getConfidence(e.getKey())).append(") "));
        sb.setLength(sb.length() - 1);
        return sb.append(']').toString();
    }
}
