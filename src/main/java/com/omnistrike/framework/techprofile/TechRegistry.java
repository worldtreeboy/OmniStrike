package com.omnistrike.framework.techprofile;

import com.omnistrike.framework.techprofile.TechContext.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Global registry of per-host technology profiles with cross-module feedback.
 *
 * Thread-safety model:
 *   - Lock-free reads: get(), getOrCreate(), snapshot() use ConcurrentHashMap
 *   - Synchronized writes: addEvidence() and confirm() go through TechContext's
 *     synchronized mutation which linearizes score updates
 *   - Listener dispatch: CopyOnWriteArrayList for safe concurrent iteration
 *
 * Cross-module feedback loop: when ANY module discovers tech evidence
 * (SmartSqliDetector finds MySQL, TechFingerprinter sees Spring header),
 * it calls addEvidence() or confirm(). The registry dispatches a TechUpdatedEvent
 * to ALL registered listeners, instantly pivoting every other module's routing.
 *
 * The TechProfiler subscribes as a listener to trigger tie-breaker probes
 * when a category gains TENTATIVE evidence but hasn't reached CONFIRMED.
 */
public final class TechRegistry {

    private static final int MAX_HOSTS = 10_000;

    private final ConcurrentHashMap<String, TechContext> contexts = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<TechUpdateListener> listeners = new CopyOnWriteArrayList<>();
    private volatile Consumer<String> logger;
    private volatile boolean warnedCapacity = false;

    // ════════════════════════════════════════════════════════════════════════
    //  Event system — cross-module feedback
    // ════════════════════════════════════════════════════════════════════════

    @FunctionalInterface
    public interface TechUpdateListener {
        /**
         * Fired when a host's tech profile changes. Must be fast and non-blocking —
         * dispatched on the caller's thread (often a scanner thread).
         *
         * @param host     the affected hostname
         * @param tech     the technology that gained evidence
         * @param newScore the new accumulated score for this tech
         * @param level    the new confidence level
         */
        void onTechUpdated(String host, TechStack tech, int newScore, ConfidenceLevel level);
    }

    public void addListener(TechUpdateListener listener) { listeners.add(listener); }
    public void removeListener(TechUpdateListener listener) { listeners.remove(listener); }
    public void setLogger(Consumer<String> logger) { this.logger = logger; }

    // ════════════════════════════════════════════════════════════════════════
    //  Core operations
    // ════════════════════════════════════════════════════════════════════════

    /** Returns the TechContext for a host, creating one if it doesn't exist. */
    public TechContext getOrCreate(String host) {
        String key = normalizeHost(host);
        TechContext ctx = contexts.get(key);
        if (ctx != null) return ctx;

        if (contexts.size() >= MAX_HOSTS) {
            if (!warnedCapacity) {
                warnedCapacity = true;
                log("[TechRegistry] WARNING: Capacity limit (" + MAX_HOSTS + "). New hosts won't be profiled.");
            }
            return new TechContext(key); // Transient — updates won't persist
        }
        return contexts.computeIfAbsent(key, TechContext::new);
    }

    /** Returns existing TechContext or null. */
    public TechContext get(String host) {
        return contexts.get(normalizeHost(host));
    }

    /**
     * Add weighted evidence for a tech on a host. Dispatches TechUpdatedEvent if
     * the score actually changed.
     *
     * This is the PRIMARY entry point for cross-module feedback. Any module that
     * discovers a technology signal calls this.
     *
     * @param host        target hostname
     * @param tech        technology this evidence supports
     * @param weight      score weight (use TechContext.W_* constants)
     * @param evidenceKey dedup key (e.g., "header:Server:Apache") — prevents double-counting
     * @return true if the score changed
     */
    public boolean addEvidence(String host, TechStack tech, int weight, String evidenceKey) {
        TechContext ctx = getOrCreate(host);
        boolean changed = ctx.addEvidence(tech, weight, evidenceKey);
        if (changed) {
            int newScore = ctx.getScore(tech);
            ConfidenceLevel level = ctx.getConfidence(tech);
            dispatchEvent(host, tech, newScore, level);
        }
        return changed;
    }

    /**
     * Confirm a tech with maximum confidence. Used when evidence is structurally
     * unambiguous (e.g., DBMS-specific exception class name in error response).
     */
    public boolean confirm(String host, TechStack tech, String evidenceKey) {
        TechContext ctx = getOrCreate(host);
        boolean changed = ctx.confirm(tech, evidenceKey);
        if (changed) {
            int newScore = ctx.getScore(tech);
            ConfidenceLevel level = ctx.getConfidence(tech);
            dispatchEvent(host, tech, newScore, level);
        }
        return changed;
    }

    /** Convenience: confirm with auto-generated evidence key. */
    public boolean confirm(String host, TechStack tech) {
        return confirm(host, tech, "confirmed:" + tech.name() + ":" + System.nanoTime());
    }

    /** Mark proxy/WAF detected for a host. */
    public void markProxyDetected(String host) {
        getOrCreate(host).setProxyDetected(true);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Liar-proxy detection: resolve contradictions
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Called when evidence contradicts the Server header (e.g., Server: nginx but
     * X-AspNet-Version present). Marks the host as proxy-masked and trusts the
     * stronger evidence over the Server header.
     *
     * @param host        target hostname
     * @param serverTech  what the Server header says (e.g., NGINX)
     * @param realTech    what the stronger evidence says (e.g., DOTNET)
     * @param evidenceKey dedup key for the stronger evidence
     */
    public void resolveContradiction(String host, TechStack serverTech, TechStack realTech,
                                      int realWeight, String evidenceKey) {
        markProxyDetected(host);
        addEvidence(host, realTech, realWeight, evidenceKey);
        log("[TechRegistry] Proxy detected on " + host + ": Server says " + serverTech
                + " but evidence points to " + realTech);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Queries
    // ════════════════════════════════════════════════════════════════════════

    public int size() { return contexts.size(); }
    public Set<String> hosts() { return Collections.unmodifiableSet(contexts.keySet()); }

    public Map<TechStack, Integer> snapshot(String host) {
        TechContext ctx = contexts.get(normalizeHost(host));
        return ctx != null ? ctx.snapshot() : Collections.emptyMap();
    }

    public void clear() {
        contexts.clear();
        warnedCapacity = false;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Internal
    // ════════════════════════════════════════════════════════════════════════

    private void dispatchEvent(String host, TechStack tech, int newScore, ConfidenceLevel level) {
        String normalized = normalizeHost(host);
        log("[TechProfile] " + normalized + " → " + tech + " score=" + newScore + " (" + level + ")");
        for (TechUpdateListener listener : listeners) {
            try {
                listener.onTechUpdated(normalized, tech, newScore, level);
            } catch (Exception e) {
                log("[TechRegistry] Listener error: " + e.getMessage());
            }
        }
    }

    private static String normalizeHost(String host) {
        if (host == null) return "";
        String h = host.toLowerCase(Locale.ROOT).trim();
        int colon = h.lastIndexOf(':');
        if (colon > 0 && colon > h.lastIndexOf(']')) {
            h = h.substring(0, colon);
        }
        return h;
    }

    private void log(String msg) {
        Consumer<String> l = logger;
        if (l != null) {
            try { l.accept(msg); } catch (Exception ignored) {}
        }
    }
}
