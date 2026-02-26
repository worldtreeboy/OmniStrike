package com.omnistrike.framework;

import com.omnistrike.model.Finding;
import com.omnistrike.model.Severity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * Central findings storage. All modules report findings here.
 * Thread-safe via CopyOnWriteArrayList. Supports multiple listeners.
 */
public class FindingsStore {

    private static final int MAX_FINDINGS = 10000;

    private final CopyOnWriteArrayList<Finding> findings = new CopyOnWriteArrayList<>();
    private final ConcurrentHashMap<String, Boolean> seenKeys = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<FindingsListener> listeners = new CopyOnWriteArrayList<>();
    private volatile java.util.function.Consumer<String> errorLogger;

    public interface FindingsListener {
        void onFindingAdded(Finding finding);
    }

    /** @deprecated Use addListener/removeListener instead */
    @Deprecated
    public void setListener(FindingsListener listener) {
        listeners.clear();
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void setErrorLogger(java.util.function.Consumer<String> logger) {
        this.errorLogger = logger;
    }

    public void addListener(FindingsListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(FindingsListener listener) {
        listeners.remove(listener);
    }

    /**
     * Adds a finding with deduplication. Synchronized to prevent races with clearModule().
     * Listener notifications fire outside the critical section to avoid deadlocks.
     */
    public void addFinding(Finding finding) {
        boolean added;
        synchronized (this) {
            if (findings.size() >= MAX_FINDINGS) return; // cap check FIRST
            String param = finding.getParameter() != null ? finding.getParameter() : "";
            String normalizedUrl = normalizeUrlForDedup(finding.getUrl());
            // Primary key: module + title + normalized URL (no query params) + parameter
            String key = finding.getModuleId() + "|" + finding.getTitle() + "|" + normalizedUrl + "|" + param;
            if (seenKeys.putIfAbsent(key, Boolean.TRUE) != null) return; // duplicate

            // Cross-module dedup
            String crossModuleKey = normalizeFindingCategory(finding.getTitle()) + "|" + normalizedUrl + "|" + param;
            if (!crossModuleKey.startsWith("|") && seenKeys.putIfAbsent("xmod:" + crossModuleKey, Boolean.TRUE) != null) {
                return;
            }

            findings.add(finding);
            added = true;
        }

        // Notify listeners outside synchronized block to avoid deadlocks
        if (added) {
            for (FindingsListener l : listeners) {
                try {
                    l.onFindingAdded(finding);
                } catch (Throwable t) {
                    String msg = "[FindingsStore] Listener error: " + t.getClass().getName() + ": " + t.getMessage();
                    java.util.function.Consumer<String> logger = errorLogger;
                    if (logger != null) {
                        logger.accept(msg);
                    }
                }
            }
        }
    }

    public void addFindings(List<Finding> newFindings) {
        for (Finding f : newFindings) {
            addFinding(f);
        }
    }

    public List<Finding> getAllFindings() {
        return Collections.unmodifiableList(new ArrayList<>(findings));
    }

    public List<Finding> getFindingsByModule(String moduleId) {
        return findings.stream()
                .filter(f -> f.getModuleId().equals(moduleId))
                .collect(Collectors.toList());
    }

    public List<Finding> getFindingsBySeverity(Severity severity) {
        return findings.stream()
                .filter(f -> f.getSeverity() == severity)
                .collect(Collectors.toList());
    }

    public int getCount() {
        return findings.size();
    }

    public int getCountByModule(String moduleId) {
        return (int) findings.stream().filter(f -> f.getModuleId().equals(moduleId)).count();
    }

    public int getCountBySeverity(Severity severity) {
        return (int) findings.stream().filter(f -> f.getSeverity() == severity).count();
    }

    /**
     * Clears all findings and dedup keys. Synchronized to prevent races with addFinding().
     */
    public synchronized void clear() {
        findings.clear();
        seenKeys.clear();
    }

    /**
     * Clears all findings for a specific module and rebuilds cross-module dedup keys.
     * Synchronized to prevent race window between wipe and rebuild where concurrent
     * addFinding() calls could bypass cross-module dedup.
     */
    public synchronized void clearModule(String moduleId) {
        findings.removeIf(f -> f.getModuleId().equals(moduleId));
        seenKeys.entrySet().removeIf(e -> e.getKey().startsWith(moduleId + "|"));

        // Rebuild cross-module dedup keys from surviving findings.
        seenKeys.entrySet().removeIf(e -> e.getKey().startsWith("xmod:"));
        for (Finding f : findings) {
            String param = f.getParameter() != null ? f.getParameter() : "";
            String normalizedUrl = normalizeUrlForDedup(f.getUrl());
            String crossModuleKey = normalizeFindingCategory(f.getTitle()) + "|" + normalizedUrl + "|" + param;
            if (!crossModuleKey.startsWith("|")) {
                seenKeys.putIfAbsent("xmod:" + crossModuleKey, Boolean.TRUE);
            }
        }
    }

    /**
     * Normalize URL for deduplication — strips query parameters and fragments
     * so the same endpoint with different query values deduplicates correctly.
     */
    private static String normalizeUrlForDedup(String url) {
        if (url == null || url.isEmpty()) return "";
        int qIdx = url.indexOf('?');
        if (qIdx > 0) url = url.substring(0, qIdx);
        int fIdx = url.indexOf('#');
        if (fIdx > 0) url = url.substring(0, fIdx);
        return url.toLowerCase();
    }

    /**
     * Normalize finding title to a category for cross-module deduplication.
     * Maps different module-specific titles to a common category when they
     * describe the same underlying vulnerability.
     */
    private static String normalizeFindingCategory(String title) {
        if (title == null || title.isEmpty()) return "";
        String lower = title.toLowerCase();

        // CORS issues from header-analyzer vs cors-scanner
        if (lower.contains("cors")) return "cors-issue";
        // Security header issues
        if (lower.contains("missing security header") || lower.contains("missing hsts")
                || lower.contains("missing x-frame") || lower.contains("missing csp")) return "";
        // XSS from client-side-analyzer vs xss-scanner
        if (lower.contains("dom xss")) return "dom-xss";
        if (lower.contains("reflected xss") || lower.contains("xss:")) return "xss";
        // Prototype pollution from client-side-analyzer vs prototype-pollution-scanner
        if (lower.contains("prototype pollution")) return "prototype-pollution";

        // Default: return empty to skip cross-module dedup (let module-specific dedup handle it)
        return "";
    }
}
